//! FIL-03 rows of the flow: capture, seal, cancel, output and cleanup, each with
//! real files in private folders.

use super::*;
use crate::fsio::watch::Fault;
use crate::{OutputFolder, ScratchRoot, SourceFile, clean_label, encrypt_file};
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, symlink};
use std::process::Command;

const LARGE: usize = 300_000;

fn name(text: &str) -> &OsStr {
    text.as_ref()
}

struct Case {
    t: Temp,
    scratch: PathBuf,
    out: PathBuf,
    input: PathBuf,
    plain: Vec<u8>,
    keys: Identities,
}

impl Case {
    fn new() -> Self {
        let t = Temp::new();
        let scratch = t.sub("scratch");
        let out = t.sub("out");
        let plain = demo_bytes(LARGE);
        let input = t.file("demo.age", &seal_to(&plain, &[rec(ID_A)]));
        Self {
            t,
            scratch,
            out,
            input,
            plain,
            keys: ids(ID_A),
        }
    }

    fn root(&self) -> ScratchRoot {
        ScratchRoot::open(&self.scratch).unwrap()
    }

    fn folder(&self) -> OutputFolder {
        OutputFolder::open(&self.out).unwrap()
    }

    fn validated(&self) -> crate::Validated {
        let snapshot = self
            .root()
            .capture_file(SourceFile::open(&self.input).unwrap(), &mut keep)
            .unwrap();
        let unwrapped = snapshot.unlock(&Unlock::Identities(&self.keys)).unwrap();
        match unwrapped.validate(&mut keep).unwrap() {
            Validation::Ready(v) => v,
            Validation::Weak(_) => panic!("X25519 files have no work factor"),
        }
    }

    /// Captures the input, with `change` run once after its first chunk.
    fn capture_while(&self, change: impl FnOnce(&Path)) -> Result<crate::Snapshot, Error> {
        let mut change = Some(change);
        let source = SourceFile::open(&self.input).unwrap();
        self.root().capture_file(source, &mut |_, _| {
            if let Some(change) = change.take() {
                change(&self.input);
            }
            true
        })
    }
}

#[test]
fn fil03_t05_source_changed_during_capture_is_refused_with_no_output() {
    type Edit = Box<dyn FnOnce(&Path)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "edited in place",
            Box::new(|p| {
                let mut f = fs::OpenOptions::new().write(true).open(p).unwrap();
                f.seek(SeekFrom::Start(200_000)).unwrap();
                f.write_all(&[0xFF]).unwrap();
            }),
        ),
        (
            "truncated",
            Box::new(|p| {
                let f = fs::OpenOptions::new().write(true).open(p).unwrap();
                f.set_len(70_000).unwrap();
            }),
        ),
        (
            "grown",
            Box::new(|p| {
                let mut f = fs::OpenOptions::new().append(true).open(p).unwrap();
                f.write_all(b"more").unwrap();
            }),
        ),
        (
            "replaced",
            Box::new(|p| {
                let other = p.with_extension("new");
                fs::write(&other, b"other demo").unwrap();
                fs::rename(other, p).unwrap();
            }),
        ),
        ("removed", Box::new(|p| fs::remove_file(p).unwrap())),
    ];
    for (what, edit) in edits {
        let case = Case::new();
        watch::take();
        let error = case.capture_while(edit).map(|_| ()).unwrap_err();
        assert_eq!(error, Error::Changed, "{what}");
        assert!(no_output(&watch::take()), "{what}");
        assert!(names_in(&case.scratch).is_empty(), "{what}: scratch stays");
        assert!(names_in(&case.out).is_empty(), "{what}");
    }
}

#[test]
fn fil03_t05_encrypting_a_source_that_changes_leaves_no_output() {
    let case = Case::new();
    let input = case.t.file("plain.bin", &case.plain);
    let recipients = [rec(ID_A)];
    let mut change = Some(());
    let result = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &case.folder(),
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut |_, _| {
            if change.take().is_some() {
                let mut f = fs::OpenOptions::new().append(true).open(&input).unwrap();
                f.write_all(b"more").unwrap();
            }
            true
        },
    );
    assert_eq!(result, Err(Error::Changed));
    assert!(names_in(&case.out).is_empty());
}

#[test]
fn fil03_t05_full_scratch_disk_cleans_up_and_leaves_the_source() {
    let case = Case::new();
    let before = fs::read(&case.input).unwrap();
    watch::inject(Fault::ScratchFull);
    let result = case
        .root()
        .capture_file(SourceFile::open(&case.input).unwrap(), &mut keep);
    watch::clear_faults();
    assert_eq!(result.map(|_| ()), Err(Error::Space));
    assert!(names_in(&case.scratch).is_empty());
    assert_eq!(fs::read(&case.input).unwrap(), before);
}

#[test]
fn fil03_t05_links_and_other_kinds_are_not_inputs() {
    let t = Temp::new();
    let real = t.file("real.age", b"demo");
    let link = t.0.join("link.age");
    symlink(&real, &link).unwrap();
    assert_eq!(SourceFile::open(&link).map(|_| ()), Err(Error::Input));
    let dangling = t.0.join("dangling.age");
    symlink(t.0.join("gone"), &dangling).unwrap();
    assert_eq!(SourceFile::open(&dangling).map(|_| ()), Err(Error::Input));
    assert_eq!(SourceFile::open(&t.0).map(|_| ()), Err(Error::Input));
    assert_eq!(
        SourceFile::open(&t.0.join("gone")).map(|_| ()),
        Err(Error::Input)
    );
    assert_eq!(SourceFile::open(&real).map(|_| ()), Ok(()));
    assert_eq!(fs::read(&real).unwrap(), b"demo");
}

#[test]
fn fil03_t05_the_descriptor_defines_the_captured_source() {
    let case = Case::new();
    let good = fs::read(&case.input).unwrap();
    let mut held = fs::File::open(&case.input).unwrap();
    // Replace the name, then capture from the handle chosen before.
    let other = case.t.file("other", b"other demo bytes");
    fs::rename(other, &case.input).unwrap();
    let mut snapshot = case.root().capture_stream(&mut held, &mut keep).unwrap();
    let mut bytes = Vec::new();
    snapshot.src.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, good);
    // Through a chosen file, a replaced name is a changed source, never its bytes.
    let source = SourceFile::open(&case.input).unwrap();
    let again = case.t.file("again", b"a third demo");
    fs::rename(again, &case.input).unwrap();
    assert_eq!(
        case.root().capture_file(source, &mut keep).map(|_| ()),
        Err(Error::Changed)
    );
}

#[test]
fn fil03_t06_sealed_snapshot_has_no_name_its_handle_only_reads_and_it_reads_the_same_twice() {
    let case = Case::new();
    let mut snapshot = case
        .root()
        .capture_file(SourceFile::open(&case.input).unwrap(), &mut keep)
        .unwrap();
    let meta = snapshot.src.metadata().unwrap();
    assert_eq!(meta.nlink(), 0, "no name reaches the inode");
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert!(
        names_in(&case.scratch).is_empty(),
        "no operation folder stays"
    );
    assert!(
        snapshot.src.write_all(b"x").is_err(),
        "the handle only reads"
    );

    // Replace the original: the passes read what was captured.
    let other = case.t.file("other", b"other demo bytes");
    fs::rename(other, &case.input).unwrap();
    let unwrapped = snapshot.unlock(&Unlock::Identities(&case.keys)).unwrap();
    let Validation::Ready(validated) = unwrapped.validate(&mut keep).unwrap() else {
        panic!("X25519 files have no work factor");
    };
    let mut out = Vec::new();
    validated.write_to(&mut out, &mut keep).unwrap();
    assert_eq!(out, case.plain);
    assert!(names_in(&case.scratch).is_empty());
}

/// Ciphertext that changes, or starts to fail, when pass number `at_pass` starts.
struct Shifting {
    data: Vec<u8>,
    pos: usize,
    seeks: usize,
    at_pass: usize,
    change: fn(&mut Vec<u8>),
    fail_after: Option<usize>,
}

impl Read for Shifting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.seeks >= self.at_pass && self.fail_after.is_some_and(|n| self.pos >= n) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let rest = self.data.get(self.pos..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pos += n;
        Ok(n)
    }
}

impl Seek for Shifting {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        assert_eq!(from, SeekFrom::Start(0));
        self.seeks += 1;
        if self.seeks == self.at_pass {
            (self.change)(&mut self.data);
        }
        self.pos = 0;
        Ok(0)
    }
}

/// Pass 1 unwraps, pass 2 checks, pass 3 writes.
fn shifting(data: Vec<u8>, at_pass: usize, change: fn(&mut Vec<u8>)) -> Shifting {
    Shifting {
        data,
        pos: 0,
        seeks: 0,
        at_pass,
        change,
        fail_after: None,
    }
}

fn run_shifting(src: Shifting, keys: &Identities) -> Result<crate::Validated<Shifting>, Error> {
    let unwrapped = crate::Snapshot { src }.unlock(&Unlock::Identities(keys))?;
    match unwrapped.validate(&mut keep)? {
        Validation::Ready(v) => Ok(v),
        Validation::Weak(_) => panic!("X25519 files have no work factor"),
    }
}

#[test]
fn fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass() {
    let keys = ids(ID_A);
    let plain = demo_bytes(3 * crate::limits::CHUNK);
    let good = seal_to(&plain, &[rec(ID_A)]);
    let changes: [fn(&mut Vec<u8>); 5] = [
        |d| d[25] ^= 1, // the header
        |d| {
            let at = header_end(d);
            d[at] ^= 1;
        }, // the nonce
        |d| {
            let end = d.len() - 1;
            d[end] ^= 1; // the last tag
        },
        |d| d.truncate(d.len() - 1),      // cut
        |d| d.extend_from_slice(b"more"), // grown
    ];
    for change in changes {
        // Whatever changes after pass 2, pass 3 refuses it.
        let checked = run_shifting(shifting(good.clone(), 3, change), &keys).unwrap();
        let mut out = Vec::new();
        assert_eq!(checked.write_to(&mut out, &mut keep), Err(Error::Decrypt));
        // Before pass 2, the check refuses it.
        let failed = run_shifting(shifting(good.clone(), 2, change), &keys);
        assert_eq!(failed.map(|_| ()), Err(Error::Decrypt));
    }

    // Through a new file: the output that was started does not stay.
    let t = Temp::new();
    let out_dir = t.sub("out");
    let folder = OutputFolder::open(&out_dir).unwrap();
    let last: fn(&mut Vec<u8>) = |d| {
        let end = d.len() - 1;
        d[end] ^= 1;
    };
    let checked = run_shifting(shifting(good.clone(), 3, last), &keys).unwrap();
    assert_eq!(
        checked.save_new(&folder, name("demo.out"), &mut keep),
        Err(Error::Decrypt)
    );
    assert!(names_in(&out_dir).is_empty());
}

#[test]
fn fil03_t07_cancel_in_each_phase_leaves_nothing_owned() {
    // Capture.
    let case = Case::new();
    let result = case
        .root()
        .capture_file(SourceFile::open(&case.input).unwrap(), &mut |_, _| false);
    assert_eq!(result.map(|_| ()), Err(Error::Cancelled));
    assert!(names_in(&case.scratch).is_empty());

    // Validate.
    let snapshot = case
        .root()
        .capture_file(SourceFile::open(&case.input).unwrap(), &mut keep)
        .unwrap();
    let unwrapped = snapshot.unlock(&Unlock::Identities(&case.keys)).unwrap();
    assert_eq!(
        unwrapped.validate(&mut |_, _| false).map(|_| ()),
        Err(Error::Cancelled)
    );
    assert!(names_in(&case.out).is_empty());

    // Write: stop after the first chunk, then again after the last.
    for stop_at in [65_536u64, LARGE as u64] {
        let result = case
            .validated()
            .save_new(&case.folder(), name("demo.out"), &mut |_, n| n < stop_at);
        assert_eq!(result, Err(Error::Cancelled), "stopped at {stop_at}");
        assert!(names_in(&case.out).is_empty(), "stopped at {stop_at}");
    }

    // Encrypt.
    let recipients = [rec(ID_A)];
    let plain_input = case.t.file("plain.bin", &case.plain);
    let result = encrypt_file(
        SourceFile::open(&plain_input).unwrap(),
        &case.folder(),
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut |_, n| n < 65_536,
    );
    assert_eq!(result, Err(Error::Cancelled));
    assert!(names_in(&case.out).is_empty());
    assert_eq!(fs::read(plain_input).unwrap(), case.plain);
}

#[test]
fn fil03_t07_a_later_read_fault_is_reported_as_itself_not_as_corruption() {
    let keys = ids(ID_A);
    let good = seal_to(&demo_bytes(LARGE), &[rec(ID_A)]);
    let t = Temp::new();
    let out_dir = t.sub("out");
    let folder = OutputFolder::open(&out_dir).unwrap();
    let mut src = shifting(good, 3, |_| {});
    src.fail_after = Some(100_000);
    let checked = run_shifting(src, &keys).unwrap();
    assert_eq!(
        checked.save_new(&folder, name("demo.out"), &mut keep),
        Err(Error::Io)
    );
    assert!(names_in(&out_dir).is_empty(), "no incomplete output stays");
}

#[test]
fn fil03_t08_no_output_ever_replaces_anything() {
    let case = Case::new();
    let target = case.t.file("linked-target", b"target demo");
    let sentinel = case.out.join("taken");
    fs::write(&sentinel, b"sentinel demo").unwrap();
    symlink(&target, case.out.join("sym")).unwrap();
    symlink(case.t.0.join("nothing-here"), case.out.join("dangling")).unwrap();
    fs::hard_link(&target, case.out.join("hard")).unwrap();
    for taken in ["taken", "sym", "dangling", "hard"] {
        let result = case
            .validated()
            .save_new(&case.folder(), name(taken), &mut keep);
        assert_eq!(result, Err(Error::Exists), "{taken}");
    }
    assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel demo");
    assert_eq!(fs::read(&target).unwrap(), b"target demo");
    assert!(
        !case.t.0.join("nothing-here").exists(),
        "no write through a dangling link"
    );

    // Same source and destination.
    let plain_input = case.out.join("same.bin");
    fs::write(&plain_input, b"demo source").unwrap();
    let recipients = [rec(ID_A)];
    let result = encrypt_file(
        SourceFile::open(&plain_input).unwrap(),
        &case.folder(),
        name("same.bin"),
        &Lock::Recipients(&recipients),
        &mut keep,
    );
    assert_eq!(result, Err(Error::Exists));
    assert_eq!(fs::read(&plain_input).unwrap(), b"demo source");

    // A name taken after the check, the last moment before the create.
    let validated = case.validated();
    fs::write(case.out.join("late"), b"late demo").unwrap();
    assert_eq!(
        validated.save_new(&case.folder(), name("late"), &mut keep),
        Err(Error::Exists)
    );
    assert_eq!(fs::read(case.out.join("late")).unwrap(), b"late demo");

    // Names that are no plain name, with no file made anywhere.
    let before = names_in(&case.out);
    let long = "x".repeat(256);
    for bad in ["", ".", "..", "../up", "a/b", "/abs", "dir/", long.as_str()] {
        let result = case
            .validated()
            .save_new(&case.folder(), name(bad), &mut keep);
        assert_eq!(result, Err(Error::Destination), "{bad:?}");
    }
    assert_eq!(
        case.validated()
            .save_new(&case.folder(), OsStr::from_bytes(b"a\0b"), &mut keep),
        Err(Error::Destination)
    );
    assert_eq!(names_in(&case.out), before);
    assert_eq!(
        names_in(&case.t.0).len(),
        4,
        "nothing made next to the folder"
    );
}

#[test]
fn fil03_t08_only_a_folder_can_be_an_output_folder() {
    let t = Temp::new();
    let file = t.file("a-file", b"demo");
    assert_eq!(
        OutputFolder::open(&file).map(|_| ()),
        Err(Error::Destination)
    );
    assert_eq!(
        OutputFolder::open(&t.0.join("gone")).map(|_| ()),
        Err(Error::Destination)
    );
    // A folder moved after the choice still takes the file: the handle is bound.
    let first = t.sub("first");
    let folder = OutputFolder::open(&first).unwrap();
    let moved = t.0.join("moved");
    fs::rename(&first, &moved).unwrap();
    fs::create_dir(&first).unwrap();
    let keys = ids(ID_A);
    let good = seal_to(PLAIN, &[rec(ID_A)]);
    let checked = checked(&good, &Unlock::Identities(&keys)).unwrap();
    checked
        .save_new(&folder, name("demo.out"), &mut keep)
        .unwrap();
    assert!(moved.join("demo.out").exists());
    assert!(!first.join("demo.out").exists());
}

#[test]
fn fil03_t09_a_renamed_output_is_emptied_and_a_planted_sentinel_stays() {
    let case = Case::new();
    let moved = case.t.0.join("moved-away");
    let target = case.out.join("demo.out");
    let mut planted = false;
    let result = case
        .validated()
        .save_new(&case.folder(), name("demo.out"), &mut |_, _| {
            if !planted {
                planted = true;
                fs::rename(&target, &moved).unwrap();
                fs::write(&target, b"sentinel demo").unwrap();
            }
            false
        });
    assert_eq!(
        result,
        Err(Error::CleanupEmpty),
        "the cleanup failure is said plainly"
    );
    assert_eq!(fs::read(&target).unwrap(), b"sentinel demo");
    assert_eq!(
        fs::read(&moved).unwrap().len(),
        0,
        "our inode holds no plaintext"
    );
}

#[test]
fn fil03_t09_a_replaced_output_on_success_is_not_called_saved() {
    let case = Case::new();
    let moved = case.t.0.join("moved-away");
    let target = case.out.join("demo.out");
    let mut planted = false;
    let result = case
        .validated()
        .save_new(&case.folder(), name("demo.out"), &mut |_, n| {
            if n >= LARGE as u64 && !planted {
                planted = true;
                fs::rename(&target, &moved).unwrap();
                fs::write(&target, b"sentinel demo").unwrap();
            }
            true
        });
    assert_eq!(result, Err(Error::Uncertain));
    assert_eq!(fs::read(&target).unwrap(), b"sentinel demo");
    assert_eq!(fs::read(&moved).unwrap(), case.plain, "complete, and kept");
}

#[test]
fn fil03_t10_write_faults_give_no_success_and_old_files_stay() {
    for (fault, expected) in [
        (Fault::OutputFull, Error::Space),
        (Fault::OutputShort, Error::Io),
    ] {
        let case = Case::new();
        let sentinel = case.out.join("old");
        fs::write(&sentinel, b"old demo").unwrap();
        let validated = case.validated();
        watch::inject(fault);
        let result = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
        watch::clear_faults();
        assert_eq!(result, Err(expected), "{fault:?}");
        assert_eq!(
            names_in(&case.out),
            ["old"],
            "{fault:?}: incomplete output removed"
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"old demo");
    }
}

#[test]
fn fil03_t10_a_failed_sync_keeps_the_whole_file_and_says_uncertain() {
    let case = Case::new();
    let validated = case.validated();
    watch::inject(Fault::OutputSync);
    let result = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
    watch::clear_faults();
    assert_eq!(result, Err(Error::Uncertain));
    assert_eq!(fs::read(case.out.join("demo.out")).unwrap(), case.plain);
}

#[test]
fn fil03_t10_permission_loss_is_a_cleanup_error_and_never_silent() {
    let case = Case::new();
    let validated = case.validated();
    let out = case.out.clone();
    let mut denied = false;
    let result = validated.save_new(&case.folder(), name("demo.out"), &mut |_, _| {
        if !denied {
            denied = true;
            fs::set_permissions(&out, fs::Permissions::from_mode(0o500)).unwrap();
        }
        false
    });
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result, Err(Error::CleanupEmpty));
    assert_eq!(
        fs::read(out.join("demo.out")).unwrap().len(),
        0,
        "emptied through its handle"
    );
}

fn op_name(n: u8) -> String {
    format!("op-{}", format!("{n:02x}").repeat(16))
}

fn leftover(root: &Path, n: u8) -> PathBuf {
    let dir = root.join(op_name(n));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join("ciphertext");
    fs::write(&file, b"demo ciphertext").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    dir
}

#[test]
fn fil03_t11_sweep_removes_only_proven_leftovers() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let outside = t.file("outside", b"outside demo");

    // Crash before the seal, and crash before the first byte.
    let crash = leftover(&scratch, 1);
    let empty = scratch.join(op_name(2));
    fs::create_dir(&empty).unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();

    // Not ours, by mode as well as by name; the name alone has its own test.
    let foreign = t.0.join("scratch/demo-folder");
    fs::create_dir(&foreign).unwrap();
    let short = scratch.join("op-00");
    fs::create_dir(&short).unwrap();
    let upper = scratch.join(format!("op-{}", "AB".repeat(16)));
    fs::create_dir(&upper).unwrap();
    // Not ours, by form: a link in place of the folder, a wider folder, one with
    // another file, one with a link, one with a wider or hard linked snapshot.
    let link = scratch.join(op_name(3));
    symlink(&outside, &link).unwrap();
    let wide = leftover(&scratch, 4);
    fs::set_permissions(&wide, fs::Permissions::from_mode(0o755)).unwrap();
    let extra = leftover(&scratch, 5);
    fs::write(extra.join("other"), b"demo").unwrap();
    let inner_link = scratch.join(op_name(6));
    fs::create_dir(&inner_link).unwrap();
    fs::set_permissions(&inner_link, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&outside, inner_link.join("ciphertext")).unwrap();
    let wide_file = leftover(&scratch, 7);
    fs::set_permissions(
        wide_file.join("ciphertext"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let linked = leftover(&scratch, 8);
    let other_name = t.0.join("hard-link");
    fs::hard_link(linked.join("ciphertext"), &other_name).unwrap();
    // One nobody can open: not this crate's mode, so it is no failure either.
    let closed = leftover(&scratch, 9);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();

    let root = ScratchRoot::open(&scratch).unwrap();
    assert_eq!(root.sweep().unwrap(), 2);
    assert!(!crash.exists());
    assert!(!empty.exists());
    for kept in [
        &foreign,
        &short,
        &upper,
        &wide,
        &extra,
        &inner_link,
        &wide_file,
        &linked,
    ] {
        assert!(kept.exists(), "{}", kept.display());
    }
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(fs::read(&outside).unwrap(), b"outside demo");
    assert_eq!(fs::read(other_name).unwrap(), b"demo ciphertext");
    assert_eq!(fs::read(extra.join("other")).unwrap(), b"demo");
    // A second sweep finds nothing new.
    assert_eq!(root.sweep().unwrap(), 0);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(closed.join("ciphertext").exists());
}

#[test]
fn fil03_t11_sweep_leaves_a_live_operation_alone() {
    let case = Case::new();
    let root = case.root();
    let sweeper = case.root();
    let mut swept = None;
    let snapshot = root
        .capture_file(SourceFile::open(&case.input).unwrap(), &mut |_, _| {
            if swept.is_none() {
                swept = Some((sweeper.sweep().unwrap(), names_in(&case.scratch).len()));
            }
            true
        })
        .unwrap();
    assert_eq!(
        swept,
        Some((0, 1)),
        "the capture's folder stays while it runs"
    );
    // After a seal there is nothing left to sweep, by name or by handle.
    assert!(names_in(&case.scratch).is_empty());
    assert_eq!(sweeper.sweep().unwrap(), 0);
    assert_eq!(
        snapshot.unlock(&Unlock::Identities(&case.keys)).map(|_| ()),
        Ok(())
    );
}

#[test]
fn fil03_t11_only_a_private_folder_can_be_a_scratch_root() {
    let t = Temp::new();
    let wide = t.sub("wide");
    fs::set_permissions(&wide, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        ScratchRoot::open(&wide).map(|_| ()),
        Err(Error::Destination)
    );
    let file = t.file("a-file", b"demo");
    assert_eq!(
        ScratchRoot::open(&file).map(|_| ()),
        Err(Error::Destination)
    );
    assert_eq!(
        ScratchRoot::open(&t.0.join("gone")).map(|_| ()),
        Err(Error::Destination)
    );
    // The root's name replaced after the choice: no capture runs through it.
    let chosen = t.sub("chosen");
    let root = ScratchRoot::open(&chosen).unwrap();
    fs::rename(&chosen, t.0.join("moved")).unwrap();
    fs::create_dir(&chosen).unwrap();
    let result = root.capture_stream(&mut &b"demo"[..], &mut keep);
    assert_eq!(result.map(|_| ()), Err(Error::Destination));
    assert!(names_in(&chosen).is_empty());
}

#[test]
fn fil03_t13_every_cause_gives_the_same_typed_result_and_message() {
    let message =
        "This file could not be decrypted. Check the passphrase or file key and try again.";
    let (phrase, wrong) = (secret(PASS), secret("wrong demo"));
    let (keys, other) = (ids(ID_A), ids(ID_B));
    let x = seal_to(PLAIN, &[rec(ID_A)]);
    let p = seal_pass(PLAIN, PASS);
    let mut mac = x.clone();
    let at = x.windows(4).position(|w| w == b"--- ").unwrap() + 4;
    mac[at] = if mac[at] == b'A' { b'B' } else { b'A' };
    let mut body = x.clone();
    *body.last_mut().unwrap() ^= 1;
    let cases: Vec<(Vec<u8>, Unlock<'_>, Failure)> = vec![
        (p.clone(), Unlock::Passphrase(&wrong), Failure::NoMatch),
        (x.clone(), Unlock::Identities(&other), Failure::NoMatch),
        (x.clone(), Unlock::Passphrase(&phrase), Failure::NoMatch),
        (p.clone(), Unlock::Identities(&keys), Failure::NoMatch),
        (
            b"not a file".to_vec(),
            Unlock::Identities(&keys),
            Failure::Header,
        ),
        (mac, Unlock::Identities(&keys), Failure::Mac),
        (body, Unlock::Identities(&keys), Failure::Payload),
        (
            x[..x.len() - 1].to_vec(),
            Unlock::Identities(&keys),
            Failure::Payload,
        ),
        (b" \n".to_vec(), Unlock::Identities(&keys), Failure::Armor),
    ];
    for (file, unlock, cause) in cases {
        assert_eq!(
            refused(&file, &unlock),
            cause,
            "the internal cause is known"
        );
        let public = snapshot(&file)
            .unlock(&unlock)
            .and_then(|u| u.validate(&mut keep))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(public, Error::Decrypt);
        assert_eq!(public.to_string(), message);
        assert_eq!(format!("{public:?}"), "Decrypt", "its Debug says no more");
    }
    // Every error type holds nothing: a tag the size of a small integer.
    assert!(std::mem::size_of::<Error>() <= 1);
}

#[test]
fn fil03_t13_the_exact_message_of_every_error() {
    for (error, text) in [
        (
            Error::Input,
            "Choose one local file. Folders and links are not supported here.",
        ),
        (
            Error::Passphrase,
            "Enter a passphrase within the allowed size.",
        ),
        (Error::Recipient, "Add a valid native X25519 recipient key."),
        (
            Error::Exists,
            "A file already exists with this name. Choose a different name.",
        ),
        (
            Error::Destination,
            "This location cannot be used. Choose another folder and a new file name.",
        ),
        (
            Error::Changed,
            "The source file changed. Choose it again and try once more.",
        ),
        (
            Error::Space,
            "There is not enough free space. Free some space or choose another disk.",
        ),
        (
            Error::Io,
            "The file could not be read or saved. Check access to the files and try again.",
        ),
        (
            Error::Cleanup,
            "Larsal could not remove an incomplete file. It may contain readable data. Check the destination before you leave.",
        ),
        (
            Error::CleanupEmpty,
            "Larsal could not remove a file it made. The file is empty. Check the destination before you leave.",
        ),
        (
            Error::Unprotected,
            "This disk cannot keep a decrypted file private. Choose another folder and a new file name.",
        ),
        (
            Error::Uncertain,
            "A file was written, but Larsal could not confirm it was saved safely. Keep the source and check the destination.",
        ),
        (Error::Cancelled, "The file operation was cancelled."),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

#[test]
fn fil03_t14_labels_are_clean_plain_text_and_errors_hold_no_name() {
    assert_eq!(clean_label(name("plain report.pdf")), "plain report.pdf");
    assert_eq!(
        clean_label(name("line\nbreak\t.txt")),
        "line\\nbreak\\t.txt"
    );
    assert_eq!(clean_label(name("bell\u{7}.txt")), "bell\\u{7}.txt");
    assert_eq!(
        clean_label(name("a\u{202E}gnp.exe\u{2066}\u{200F}")),
        "agnp.exe",
        "direction controls go"
    );
    // Markup stays as the characters it is: nothing renders it here.
    assert_eq!(clean_label(name("[a](http://demo)")), "[a](http://demo)");
    let bad = OsStr::from_bytes(b"caf\xFF.txt");
    assert_eq!(clean_label(bad), "caf\u{FFFD}.txt");

    let t = Temp::new();
    let hostile = "secret-name $(touch x) \u{202E}";
    let error = SourceFile::open(&t.0.join(hostile))
        .map(|_| ())
        .unwrap_err();
    assert!(!error.to_string().contains("secret-name"));
    assert!(!format!("{error:?}").contains("secret-name"));
    assert_eq!(error, Error::Input);
    let os = io::Error::other("disk reason with a /private/path");
    let mapped = crate::error::io_error(&os);
    assert!(!mapped.to_string().contains("private"));
    assert_eq!(mapped, Error::Io);
}

#[test]
fn fil03_t20_payload_round_trips_as_bytes_and_no_metadata_travels() {
    let t = Temp::new();
    let mut payload = b"#!/bin/sh\necho demo\n\x7fELF\xFF\xD8\xFF\xE1Exif\0\0".to_vec();
    payload.extend(demo_bytes(1000));
    let input = t.file("secret-name-of-person.jpg", &payload);
    fs::set_permissions(&input, fs::Permissions::from_mode(0o755)).unwrap();
    let out = t.sub("out");
    let folder = OutputFolder::open(&out).unwrap();
    let recipients = [rec(ID_A)];
    encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    )
    .unwrap();
    let sealed = fs::read(out.join("demo.age")).unwrap();
    let meta = fs::metadata(out.join("demo.age")).unwrap();
    assert_eq!(
        meta.mode() & 0o7777,
        0o600,
        "the source's mode is not copied"
    );
    assert!(
        !sealed.windows(6).any(|w| w == b"secret"),
        "its name is not carried"
    );

    let keys = ids(ID_A);
    let Validation::Ready(checked) = snapshot(&sealed)
        .unlock(&Unlock::Identities(&keys))
        .unwrap()
        .validate(&mut keep)
        .unwrap()
    else {
        panic!("X25519 files have no work factor");
    };
    checked
        .save_new(&folder, name("demo.jpg"), &mut keep)
        .unwrap();
    assert_eq!(fs::read(out.join("demo.jpg")).unwrap(), payload);
    let meta = fs::metadata(out.join("demo.jpg")).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600, "never executable");
}

/// The names `xattr` shows, less the one the system puts on what a guarded program
/// makes.
fn shown_xattrs(path: &Path) -> Vec<String> {
    let out = Command::new("/usr/bin/xattr").arg(path).output().unwrap();
    assert!(out.status.success(), "xattr {}", path.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| *line != "com.apple.provenance")
        .map(str::to_owned)
        .collect()
}

/// A tag, a user attribute, a quarantine mark, a list and an old date.
fn mark_as_a_finder_would(path: &Path) {
    for (key, value) in [
        ("com.apple.metadata:_kMDItemUserTags", "demo tag"),
        ("demo.user.mark", "demo value"),
        ("com.apple.quarantine", "0081;00000000;demo;"),
    ] {
        let done = Command::new("/usr/bin/xattr")
            .args(["-w", key, value])
            .arg(path)
            .status()
            .unwrap();
        assert!(done.success(), "xattr -w {key}");
    }
    chmod_acl("everyone allow read", path);
    let done = Command::new("/usr/bin/touch")
        .args(["-t", "200001020304"])
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success());
}

/// C1-R2-01: what a source carries beside its bytes stays with it, on both roads.
#[test]
fn fil03_t20_no_tag_attribute_list_or_date_of_a_source_reaches_an_output() {
    let t = Temp::new();
    let (scratch, out) = (t.sub("scratch"), t.sub("out"));
    let folder = OutputFolder::open(&out).unwrap();
    let keys = ids(ID_A);
    let recipients = [rec(ID_A)];

    let input = t.file("plain.bin", PLAIN);
    mark_as_a_finder_would(&input);
    assert_eq!(shown_xattrs(&input).len(), 3, "the control: it has them");
    assert!(shown_acl(&input).contains("everyone"), "and the list");
    let old = fs::metadata(&input).unwrap().mtime();
    encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    )
    .unwrap();

    let sealed = t.file("marked.age", &fs::read(out.join("demo.age")).unwrap());
    mark_as_a_finder_would(&sealed);
    let snapshot = ScratchRoot::open(&scratch)
        .unwrap()
        .capture_file(SourceFile::open(&sealed).unwrap(), &mut keep)
        .unwrap();
    let Validation::Ready(checked) = snapshot
        .unlock(&Unlock::Identities(&keys))
        .unwrap()
        .validate(&mut keep)
        .unwrap()
    else {
        panic!("X25519 files have no work factor");
    };
    checked
        .save_new(&folder, name("back.bin"), &mut keep)
        .unwrap();
    assert_eq!(fs::read(out.join("back.bin")).unwrap(), PLAIN);

    for output in ["demo.age", "back.bin"] {
        let path = out.join(output);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(shown_xattrs(&path), Vec::<String>::new(), "{output}");
        assert!(!shown_acl(&path).contains("everyone"), "{output}");
        assert!(meta.mtime() > old, "{output}: the source's date");
        assert!(meta.created().unwrap() > fs::metadata(&input).unwrap().modified().unwrap());
    }
}

#[test]
fn fil03_t21_the_original_is_never_deleted_or_changed() {
    let t = Temp::new();
    let plain = demo_bytes(2000);
    let input = t.file("person.jpg", &plain);
    let before = fs::metadata(&input).unwrap();
    let out = t.sub("out");
    let scratch = t.sub("scratch");
    let folder = OutputFolder::open(&out).unwrap();
    let recipients = [rec(ID_A)];
    encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    )
    .unwrap();
    assert_eq!(fs::read(&input).unwrap(), plain);
    let after = fs::metadata(&input).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );

    // Decrypting keeps the encrypted file, too.
    let sealed_path = out.join("demo.age");
    let sealed = fs::read(&sealed_path).unwrap();
    let keys = ids(ID_A);
    let root = ScratchRoot::open(&scratch).unwrap();
    let snapshot = root
        .capture_file(SourceFile::open(&sealed_path).unwrap(), &mut keep)
        .unwrap();
    let Validation::Ready(checked) = snapshot
        .unlock(&Unlock::Identities(&keys))
        .unwrap()
        .validate(&mut keep)
        .unwrap()
    else {
        panic!("X25519 files have no work factor");
    };
    checked
        .save_new(&folder, name("back.jpg"), &mut keep)
        .unwrap();
    assert_eq!(fs::read(&sealed_path).unwrap(), sealed);
    assert_eq!(fs::read(out.join("back.jpg")).unwrap(), plain);
}

#[test]
fn fil03_t12_a_sparse_source_is_read_by_its_length_only() {
    let t = Temp::new();
    let input = t.0.join("sparse.bin");
    let file = fs::File::create(&input).unwrap();
    let size = 3 * crate::limits::CHUNK as u64 + 5;
    file.set_len(size).unwrap();
    drop(file);
    let out = t.sub("out");
    let folder = OutputFolder::open(&out).unwrap();
    let recipients = [rec(ID_A)];
    let written = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &folder,
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    )
    .unwrap();
    assert_eq!(written, size);
    let keys = ids(ID_A);
    let sealed = fs::read(out.join("demo.age")).unwrap();
    assert_eq!(
        open(&sealed, &Unlock::Identities(&keys)).unwrap().len() as u64,
        size
    );
    assert_eq!(
        fs::metadata(&input).unwrap().len(),
        size,
        "the source is unharmed"
    );
}

/// A real access list on a real path, by the system's own tool.
fn chmod_acl(entry: &str, path: &Path) {
    let done = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success(), "chmod +a {entry}");
}

fn chmod_no_acl(path: &Path) {
    let done = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .unwrap();
    assert!(done.success(), "chmod -N");
}

/// What `ls -lde` says of one path.
fn shown_acl(path: &Path) -> String {
    let out = Command::new("/bin/ls")
        .args(["-lde"])
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn no_write(events: &[Event]) -> bool {
    !events.iter().any(|e| matches!(e, Event::OutputWrite(_)))
}

const PASSES_ON: &str = "everyone allow read,file_inherit";

#[test]
fn fil03_t08_fil03_t20_a_folder_that_passes_on_an_access_list_gets_not_one_byte() {
    let case = Case::new();
    chmod_acl(PASSES_ON, &case.out);

    // Control: what the folder does to any new file. Mode 0600, and everyone can read.
    let control = case.out.join("control");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&control)
        .unwrap();
    assert_eq!(
        fs::metadata(&control).unwrap().mode() & 0o7777,
        0o600,
        "the mode does not show it"
    );
    assert!(
        shown_acl(&control).contains("everyone"),
        "the system passed the list on"
    );
    fs::remove_file(&control).unwrap();

    // A decrypted output.
    let validated = case.validated();
    watch::take();
    assert_eq!(
        validated.save_new(&case.folder(), name("demo.out"), &mut keep),
        Err(Error::Destination)
    );
    let events = watch::take();
    assert!(
        events.iter().any(|e| matches!(e, Event::OutputCreate)),
        "the file was made"
    );
    assert!(no_write(&events), "and not one byte went into it");
    assert!(names_in(&case.out).is_empty(), "and it does not stay");

    // An encrypted output takes the same road.
    let input = case.t.file("plain.bin", &case.plain);
    let recipients = [rec(ID_A)];
    watch::take();
    let result = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &case.folder(),
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    );
    assert_eq!(result, Err(Error::Destination));
    assert!(no_write(&watch::take()));
    assert!(names_in(&case.out).is_empty());
}

#[test]
fn fil03_t08_a_list_the_folder_keeps_to_itself_changes_nothing() {
    let case = Case::new();
    // Ones like this one are on a Mac user's own folders. It is not passed on.
    chmod_acl("everyone deny delete", &case.out);
    let result = case
        .validated()
        .save_new(&case.folder(), name("demo.out"), &mut keep);
    let written = fs::read(case.out.join("demo.out"));
    let shown = shown_acl(&case.out.join("demo.out"));
    chmod_no_acl(&case.out);
    assert_eq!(result, Ok(LARGE as u64));
    assert_eq!(written.unwrap(), case.plain);
    assert!(!shown.contains("everyone"), "{shown}");
}

/// C1-R2-06: not only a list that names everyone.
#[test]
fn fil03_t08_a_list_naming_one_user_counts_the_same() {
    let case = Case::new();
    chmod_acl("user:nobody allow read,file_inherit", &case.out);
    let validated = case.validated();
    watch::take();
    assert_eq!(
        validated.save_new(&case.folder(), name("demo.out"), &mut keep),
        Err(Error::Destination)
    );
    assert!(no_write(&watch::take()));
    assert!(names_in(&case.out).is_empty());
}

/// Each name in `dir`, and `dir`, without their lists: so a test can read or end.
fn clear_lists(dir: &Path) {
    for entry in fs::read_dir(dir).unwrap() {
        chmod_no_acl(&entry.unwrap().path());
    }
    chmod_no_acl(dir);
}

/// C1-R2-04: a list the system will not show counts as a list, on both checks.
#[test]
fn fil03_t08_a_list_that_cannot_be_read_counts_as_one() {
    let case = Case::new();
    chmod_acl(
        "everyone deny readsecurity,file_inherit,only_inherit",
        &case.out,
    );
    let validated = case.validated();
    watch::take();
    let result = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
    assert!(no_write(&watch::take()), "not one byte");
    clear_lists(&case.out);
    assert_eq!(result, Err(Error::CleanupEmpty));
    assert_eq!(fs::read(case.out.join("demo.out")).unwrap().len(), 0);

    let t = Temp::new();
    let shut = t.sub("shut");
    chmod_acl("user:nobody allow list,search,read", &shut);
    chmod_acl("everyone deny readsecurity", &shut);
    let result = ScratchRoot::open(&shut).map(|_| ());
    chmod_no_acl(&shut);
    assert_eq!(result, Err(Error::Destination));
}

/// C1-R2-05, C2R2-08: a refusal whose cleanup also failed says the second thing, and
/// the empty file is named as empty.
#[test]
fn fil03_t08_a_folder_that_blocks_deletion_gets_the_empty_file_named() {
    let case = Case::new();
    chmod_acl("everyone deny delete,file_inherit", &case.out);
    let validated = case.validated();
    watch::take();
    let decrypted = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
    assert!(no_write(&watch::take()), "not one byte");
    let input = case.t.file("plain.bin", &case.plain);
    let recipients = [rec(ID_A)];
    let encrypted = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &case.folder(),
        name("demo.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    );
    assert!(no_write(&watch::take()), "not one byte");
    clear_lists(&case.out);
    assert_eq!(decrypted, Err(Error::CleanupEmpty));
    assert_eq!(encrypted, Err(Error::CleanupEmpty));
    for left in ["demo.out", "demo.age"] {
        assert_eq!(fs::read(case.out.join(left)).unwrap().len(), 0, "{left}");
    }
}

/// C1-R2-05: scratch that cannot be taken back is said, not hidden by the refusal.
#[test]
fn fil03_t11_a_capture_that_cannot_remove_its_new_folder_says_so() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let root = ScratchRoot::open(&scratch).unwrap();
    chmod_acl("everyone deny delete,directory_inherit", &scratch);
    let result = root.capture_stream(&mut &b"demo"[..], &mut keep);
    assert_eq!(result.map(|_| ()), Err(Error::Io));
    let left = names_in(&scratch);
    assert_eq!(left.len(), 1, "the empty folder stays");
    assert!(names_in(&scratch.join(&left[0])).is_empty());
    assert_eq!(root.sweep(), Ok(0), "its list keeps the sweep off it too");
    clear_lists(&scratch);
}

/// Part 3 of the round's rulings. A real volume's proof is `tests/volumes.rs`; these
/// run in every test run, through the same checks.
#[test]
fn fil03_t08_a_disk_that_cannot_keep_a_file_private_takes_only_ciphertext() {
    for fault in [Fault::VolumeOtherMode, Fault::VolumeNoOwners] {
        let case = Case::new();
        let input = case.t.file("plain.bin", &case.plain);
        let recipients = [rec(ID_A)];
        let encrypt = |file: &str| {
            encrypt_file(
                SourceFile::open(&input).unwrap(),
                &case.folder(),
                name(file),
                &Lock::Recipients(&recipients),
                &mut keep,
            )
        };

        // A decrypted output: made, refused before a byte, gone.
        let validated = case.validated();
        watch::take();
        watch::inject(fault);
        let result = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
        watch::clear_faults();
        assert_eq!(result, Err(Error::Unprotected), "{fault:?}");
        let events = watch::take();
        assert!(
            events.iter().any(|e| matches!(e, Event::OutputCreate)),
            "{fault:?}: the check is on the new file"
        );
        assert!(no_write(&events), "{fault:?}");
        assert!(names_in(&case.out).is_empty(), "{fault:?}");

        // An encrypted one goes there, and opens.
        watch::inject(fault);
        let result = encrypt("demo.age");
        watch::clear_faults();
        assert_eq!(result, Ok(LARGE as u64), "{fault:?}");
        let sealed = fs::read(case.out.join("demo.age")).unwrap();
        assert_eq!(
            open(&sealed, &Unlock::Identities(&case.keys)).unwrap(),
            case.plain
        );
        fs::remove_file(case.out.join("demo.age")).unwrap();

        // A list is refused on any volume, whatever the output holds.
        chmod_acl(PASSES_ON, &case.out);
        let validated = case.validated();
        watch::inject(fault);
        let decrypted = validated.save_new(&case.folder(), name("demo.out"), &mut keep);
        let encrypted = encrypt("demo.age");
        watch::clear_faults();
        chmod_no_acl(&case.out);
        assert_eq!(decrypted, Err(Error::Destination), "{fault:?}");
        assert_eq!(encrypted, Err(Error::Destination), "{fault:?}");
        assert!(names_in(&case.out).is_empty(), "{fault:?}");
    }

    // Scratch never goes on a volume that ignores ownership.
    let t = Temp::new();
    let scratch = t.sub("scratch");
    watch::inject(Fault::VolumeNoOwners);
    let result = ScratchRoot::open(&scratch).map(|_| ());
    watch::clear_faults();
    assert_eq!(result, Err(Error::Destination));
    assert_eq!(
        ScratchRoot::open(&scratch).map(|_| ()),
        Ok(()),
        "the control"
    );
}

/// FAT32 and exFAT go on saying one link after the unlink. Here a hard link makes a
/// normal volume say the same, in every run: the name gone and nothing left is a
/// clean end, whatever the count.
#[test]
fn fil03_t09_cleanup_goes_by_what_is_left_and_not_by_the_link_count() {
    let case = Case::new();
    let target = case.out.join("demo.out");
    let link = case.t.0.join("held-by-a-link");
    let mut once = true;
    let result = case
        .validated()
        .save_new(&case.folder(), name("demo.out"), &mut |_, _| {
            if once {
                once = false;
                fs::hard_link(&target, &link).unwrap();
            }
            false
        });
    assert_eq!(result, Err(Error::Cancelled));
    assert!(names_in(&case.out).is_empty());
    assert_eq!(fs::read(&link).unwrap().len(), 0, "no readable data stays");
}

/// `Error::Cleanup` is kept for what it says: there may be readable data.
#[test]
fn fil03_t09_an_output_that_cannot_be_emptied_says_it_may_hold_data() {
    let case = Case::new();
    let validated = case.validated();
    watch::inject(Fault::OutputStuck);
    let result = validated.save_new(&case.folder(), name("demo.out"), &mut |_, _| false);
    watch::clear_faults();
    assert_eq!(result, Err(Error::Cleanup));
    assert!(names_in(&case.out).is_empty(), "the name still goes");

    // And with the name that cannot go.
    let validated = case.validated();
    let out = case.out.clone();
    watch::inject(Fault::OutputStuck);
    let result = validated.save_new(&case.folder(), name("demo.out"), &mut |_, _| {
        fs::set_permissions(&out, fs::Permissions::from_mode(0o500)).unwrap();
        false
    });
    watch::clear_faults();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result, Err(Error::Cleanup));
    assert_eq!(names_in(&case.out), ["demo.out"]);
}

const DIRECTORIES_TOO: &str = "everyone allow list,search,read,file_inherit,directory_inherit";

#[test]
fn fil03_t05_fil03_t11_a_scratch_root_with_an_access_list_is_not_private() {
    let t = Temp::new();
    let listed = t.sub("listed");
    chmod_acl(DIRECTORIES_TOO, &listed);
    assert_eq!(
        ScratchRoot::open(&listed).map(|_| ()),
        Err(Error::Destination)
    );

    // A list that came after the choice: the operation's folder would take it.
    let late = t.sub("late");
    let root = ScratchRoot::open(&late).unwrap();
    chmod_acl(DIRECTORIES_TOO, &late);
    watch::take();
    let result = root.capture_stream(&mut &b"demo"[..], &mut keep);
    assert_eq!(result.map(|_| ()), Err(Error::Destination));
    assert!(
        !watch::take()
            .iter()
            .any(|e| matches!(e, Event::ScratchWrite(_))),
        "no ciphertext went in"
    );
    assert!(names_in(&late).is_empty(), "nothing stays");
}

#[test]
fn fil03_t05_a_link_put_in_place_during_the_open_is_never_followed() {
    let t = Temp::new();
    let input = t.file("demo.age", b"demo");
    // The link points at the very file: its inode says nothing is wrong, so only
    // the open itself can refuse it.
    let moved = t.0.join("moved");
    watch::at_source_open(Box::new(move |p: &Path| {
        fs::rename(p, &moved).unwrap();
        symlink(&moved, p).unwrap();
    }));
    assert_eq!(SourceFile::open(&input).map(|_| ()), Err(Error::Input));
}

#[test]
fn fil03_t05_a_file_put_in_place_during_the_open_is_a_changed_source() {
    let t = Temp::new();
    let input = t.file("demo.age", b"demo");
    let other = t.file("other", b"other demo");
    watch::at_source_open(Box::new(move |p: &Path| fs::rename(&other, p).unwrap()));
    assert_eq!(SourceFile::open(&input).map(|_| ()), Err(Error::Changed));
}

#[test]
fn fil03_t05_a_parent_folder_swap_is_a_changed_source() {
    // The file itself is not touched, so its inode, size and times all hold. Only
    // the name no longer being that file can show the swap.
    let t = Temp::new();
    let parent = t.sub("parent");
    let moved = t.0.join("parent-moved");
    let input = parent.join("demo.age");
    fs::write(&input, seal_to(&demo_bytes(LARGE), &[rec(ID_A)])).unwrap();
    let scratch = t.sub("scratch");
    let root = ScratchRoot::open(&scratch).unwrap();
    let source = SourceFile::open(&input).unwrap();
    let mut once = true;
    let result = root.capture_file(source, &mut |_, _| {
        if once {
            once = false;
            fs::rename(&parent, &moved).unwrap();
            fs::create_dir(&parent).unwrap();
            fs::write(parent.join("demo.age"), b"another file, same path").unwrap();
        }
        true
    });
    assert_eq!(result.map(|_| ()), Err(Error::Changed));
    assert!(names_in(&scratch).is_empty());
}

#[test]
fn fil03_t11_a_capture_whose_cleanup_fails_says_so_whatever_stopped_it() {
    // Each: what stopped the capture, and whether the source was edited to do it.
    for (stop, edit) in [(true, false), (false, true)] {
        let case = Case::new();
        let source = SourceFile::open(&case.input).unwrap();
        let mut once = true;
        let result = case.root().capture_file(source, &mut |_, _| {
            if once {
                once = false;
                for entry in fs::read_dir(&case.scratch).unwrap() {
                    let op = entry.unwrap().path();
                    fs::set_permissions(op, fs::Permissions::from_mode(0o500)).unwrap();
                }
                if edit {
                    let mut f = fs::OpenOptions::new()
                        .append(true)
                        .open(&case.input)
                        .unwrap();
                    f.write_all(b"more").unwrap();
                }
            }
            !stop
        });
        let left = names_in(&case.scratch);
        for op in &left {
            let path = case.scratch.join(op);
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(left.len(), 1, "the ciphertext is still there");
        assert_eq!(
            result.map(|_| ()),
            Err(Error::Io),
            "stop {stop}, edit {edit}"
        );
    }
}

#[test]
fn fil03_t10_encrypting_says_a_failed_cleanup_and_a_failed_sync() {
    let case = Case::new();
    let input = case.t.file("plain.bin", &case.plain);
    let recipients = [rec(ID_A)];
    let out = case.out.clone();
    let mut denied = false;
    let result = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &case.folder(),
        name("denied.age"),
        &Lock::Recipients(&recipients),
        &mut |_, _| {
            if !denied {
                denied = true;
                fs::set_permissions(&out, fs::Permissions::from_mode(0o500)).unwrap();
            }
            false
        },
    );
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result, Err(Error::CleanupEmpty));
    assert_eq!(fs::read(out.join("denied.age")).unwrap().len(), 0);

    watch::inject(Fault::OutputSync);
    let result = encrypt_file(
        SourceFile::open(&input).unwrap(),
        &case.folder(),
        name("unsure.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    );
    watch::clear_faults();
    assert_eq!(result, Err(Error::Uncertain));
    assert!(out.join("unsure.age").exists(), "the whole file is kept");
}

/// A folder of the crate's form, private, with one private snapshot: only `name`
/// can tell it from a real leftover.
fn shaped(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join("ciphertext");
    fs::write(&file, b"demo").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    dir
}

#[test]
fn fil03_t11_sweep_goes_by_the_name_alone_where_all_else_fits() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let kept = [
        shaped(&scratch, "demo-folder"),
        shaped(&scratch, "op-00"),
        shaped(&scratch, &format!("op-{}", "AB".repeat(16))),
        shaped(&scratch, &format!("op-{}0", "ab".repeat(16))),
        shaped(&scratch, &format!("xp-{}", "ab".repeat(16))),
    ];
    let root = ScratchRoot::open(&scratch).unwrap();
    assert_eq!(root.sweep(), Ok(0));
    for dir in &kept {
        assert!(dir.join("ciphertext").exists(), "{}", dir.display());
    }
}

#[test]
fn fil03_t11_sweep_leaves_a_private_folder_with_a_second_private_file() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let dir = shaped(&scratch, &format!("op-{}", "cd".repeat(16)));
    let other = dir.join("other");
    fs::write(&other, b"demo").unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(ScratchRoot::open(&scratch).unwrap().sweep(), Ok(0));
    assert!(dir.join("ciphertext").exists() && other.exists());
}

#[test]
fn fil03_t11_sweep_leaves_a_folder_with_an_access_list() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let dir = shaped(&scratch, &format!("op-{}", "ef".repeat(16)));
    chmod_acl("everyone allow read", &dir);
    assert_eq!(ScratchRoot::open(&scratch).unwrap().sweep(), Ok(0));
    assert!(dir.join("ciphertext").exists());
}

#[test]
fn fil03_t11_a_sweep_that_cannot_remove_says_so() {
    let t = Temp::new();
    let scratch = t.sub("scratch");
    let dir = shaped(&scratch, &format!("op-{}", "12".repeat(16)));
    let root = ScratchRoot::open(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o500)).unwrap();
    let result = root.sweep();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result, Err(Error::Io));
    assert!(dir.exists());
}

#[test]
fn fil03_t11_sweep_stays_in_the_root_it_was_given() {
    let t = Temp::new();
    let chosen = t.sub("chosen");
    let root = ScratchRoot::open(&chosen).unwrap();
    fs::rename(&chosen, t.0.join("moved")).unwrap();
    fs::create_dir(&chosen).unwrap();
    let other = shaped(&chosen, &format!("op-{}", "ab".repeat(16)));
    assert_eq!(root.sweep(), Err(Error::Destination));
    assert!(other.join("ciphertext").exists(), "another folder's file");
}

#[test]
fn fil03_t05_each_capture_has_a_new_operation_folder() {
    let case = Case::new();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let source = SourceFile::open(&case.input).unwrap();
        case.root()
            .capture_file(source, &mut |_, _| {
                seen.extend(names_in(&case.scratch));
                true
            })
            .unwrap();
    }
    assert_eq!(seen.len(), 3, "{seen:?}");
}

#[test]
fn fil03_t14_every_line_break_and_direction_control_is_handled_alone() {
    for c in [
        '\u{A}', '\u{B}', '\u{C}', '\u{D}', '\u{85}', '\u{2028}', '\u{2029}',
    ] {
        let shown = clean_label(name(&format!("a{c}b.txt")));
        assert!(!shown.contains(c), "{:x} reaches the screen", c as u32);
        assert!(
            shown.starts_with("a\\") && shown.ends_with("b.txt"),
            "{shown}"
        );
    }
    assert_eq!(clean_label(name("a\u{2028}b")), "a\\u{2028}b");
    assert_eq!(clean_label(name("a\u{2029}b")), "a\\u{2029}b");
    for c in [
        '\u{61C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ] {
        assert_eq!(clean_label(name(&format!("a{c}b"))), "ab", "{:x}", c as u32);
    }
}
