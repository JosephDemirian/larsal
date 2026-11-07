//! FIL-03-T03, FIL-03.3: working memory does not grow with the file. Measured from
//! outside, by the process's resident size, on real files, through every state.
//! The 4 GB run and the allocation fault are in `tests/measure.rs` and the open list.

use larsal_crypto::secret::SecretString;
use larsal_files::{
    Identities, Lock, Recipient, ScratchRoot, SourceFile, Unlock, Validation, encrypt_stream,
};
use larsal_platform::macos::resident_bytes;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

const ID: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const RECIPIENT: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";
/// FIL-03.3's non-KDF budget.
const BUDGET: u64 = 8 << 20;

struct Zeros(u64);

impl Read for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = u64::min(self.0, buf.len() as u64);
        buf[..n as usize].fill(0x5A);
        self.0 -= n;
        Ok(n as usize)
    }
}

struct Counting(u64);

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

static STOP: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicU64 = AtomicU64::new(0);

/// The most the process's resident size rose while `work` ran.
fn rise_while(work: impl FnOnce()) -> u64 {
    STOP.store(false, Relaxed);
    let base = resident_bytes().unwrap();
    PEAK.store(base, Relaxed);
    let sampler = std::thread::spawn(|| {
        while !STOP.load(Relaxed) {
            PEAK.fetch_max(resident_bytes().unwrap(), Relaxed);
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    work();
    STOP.store(true, Relaxed);
    sampler.join().unwrap();
    PEAK.load(Relaxed).saturating_sub(base)
}

/// One whole round trip through every state, with its rise.
fn round_trip_rise(size: u64, dir: &Path) -> u64 {
    let to = [Recipient::parse(RECIPIENT).unwrap()];
    let keys = Identities::single(&SecretString::from(ID)).unwrap();
    let scratch = dir.join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let sealed = dir.join("demo.age");
    let rise = rise_while(|| round_trip(size, &to, &keys, &scratch, &sealed));
    fs::remove_file(&sealed).unwrap();
    fs::remove_dir(&scratch).unwrap();
    rise
}

fn round_trip(size: u64, to: &[Recipient], keys: &Identities, scratch: &Path, sealed: &Path) {
    let mut out = File::create(sealed).unwrap();
    let written = encrypt_stream(
        &mut Zeros(size),
        &mut out,
        &Lock::Recipients(to),
        &mut |_, _| true,
    )
    .unwrap();
    assert_eq!(written, size);
    out.sync_all().unwrap();
    drop(out);

    let root = ScratchRoot::open(scratch).unwrap();
    let snapshot = root
        .capture_file(SourceFile::open(sealed).unwrap(), &mut |_, _| true)
        .unwrap();
    let unwrapped = snapshot.unlock(&Unlock::Identities(keys)).unwrap();
    let Validation::Ready(validated) = unwrapped.validate(&mut |_, _| true).unwrap() else {
        panic!("X25519 files have no work factor");
    };
    let mut sink = Counting(0);
    validated.write_to(&mut sink, &mut |_, _| true).unwrap();
    assert_eq!(sink.0, size);
}

#[test]
fn fil03_t03_memory_does_not_grow_with_the_file() {
    let dir = std::env::temp_dir().join(format!("larsal-files-mem-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    // The control: a whole-file buffer shows, so the bound below measures something.
    let shown = rise_while(|| {
        let whole = vec![1u8; 64 << 20];
        std::thread::sleep(Duration::from_millis(50));
        std::hint::black_box(whole);
    });
    assert!(shown > 32 << 20, "the control rose only {shown} bytes");

    // The first run sizes the thread and the page caches of this process.
    let _ = round_trip_rise(1 << 20, &dir);
    let small = round_trip_rise(1 << 20, &dir);
    let large = round_trip_rise(512 << 20, &dir);
    println!("resident rise: 1 MiB file {small} bytes, 512 MiB file {large} bytes");
    assert!(large < BUDGET, "512 MiB file rose {large} bytes");
    // What a whole-file buffer would show: hundreds of MiB against this.
    assert!(
        large < small + (4 << 20),
        "1 MiB: {small} bytes, 512 MiB: {large} bytes"
    );
    fs::remove_dir(&dir).unwrap();
}
