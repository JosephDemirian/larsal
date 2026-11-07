//! FIL-03.6, FIL-03-T06: no open writer survives the seal. One test alone in its
//! program, so no other test moves the count of this process's descriptors.

use larsal_files::{ScratchRoot, SourceFile};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn open_descriptors() -> usize {
    fs::read_dir("/dev/fd").unwrap().count()
}

#[test]
fn fil03_t06_no_writer_survives_the_seal() {
    let base = std::env::temp_dir().join(format!("larsal-files-seal-{}", std::process::id()));
    let scratch = base.join("scratch");
    fs::create_dir_all(&scratch).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let input = base.join("demo.bin");
    fs::write(&input, vec![5u8; 70_000]).unwrap();
    let root = ScratchRoot::open(&scratch).unwrap();
    let source = SourceFile::open(&input).unwrap();
    let before = open_descriptors();
    // The source's handle goes and the snapshot's read handle comes: no change.
    let snapshot = root.capture_file(source, &mut |_, _| true).unwrap();
    assert_eq!(open_descriptors(), before, "a descriptor stayed open");
    drop(snapshot);
    assert_eq!(
        open_descriptors(),
        before - 1,
        "the read handle was the one"
    );
    fs::remove_dir_all(&base).unwrap();
}
