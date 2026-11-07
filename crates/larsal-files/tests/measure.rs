//! FIL-03-T03, FIL-03-T22: what a real run costs, stage by stage, disk to disk,
//! at the sizes of the research card's section 6. Ignored: it writes gigabytes of
//! demo data. Run it from a release build with
//! `cargo test --release -p larsal-files --test measure -- --ignored --nocapture`.
//! Its numbers are the only runtime evidence; the research card's figures stay a
//! documentation study.

use larsal_crypto::secret::SecretString;
use larsal_files::limits::{READ_MAX_LOG_N, WRITE_LOG_N};
mod common;

use common::open_all;
use larsal_files::{
    Error, Identities, Lock, OutputFolder, Recipient, ScratchRoot, SourceFile, Unlock, Validation,
    encrypt_file,
};
use larsal_platform::macos::resident_bytes;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

const ID: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const RECIPIENT: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";
const SIZES: [u64; 8] = [0, 1, 65_535, 65_536, 65_537, 16 << 20, 1 << 30, 4 << 30];

static STOP: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicU64 = AtomicU64::new(0);

fn stage<T>(name: &str, size: u64, work: impl FnOnce() -> T) -> T {
    STOP.store(false, Relaxed);
    let base = resident_bytes().unwrap();
    PEAK.store(base, Relaxed);
    let sampler = std::thread::spawn(|| {
        while !STOP.load(Relaxed) {
            PEAK.fetch_max(resident_bytes().unwrap(), Relaxed);
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let start = Instant::now();
    let value = work();
    let took = start.elapsed().as_secs_f64();
    STOP.store(true, Relaxed);
    sampler.join().unwrap();
    let rise = PEAK.load(Relaxed).saturating_sub(base);
    let mib = size as f64 / 1_048_576.0;
    println!(
        "  {name:<22} {took:>9.3} s  {:>8.1} MiB/s  peak resident {:>8.2} MiB  rise {:>8.2} MiB",
        mib / took.max(0.000_001),
        PEAK.load(Relaxed) as f64 / 1_048_576.0,
        rise as f64 / 1_048_576.0
    );
    value
}

fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_demo(path: &Path, size: u64) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    let block = [0x5A; 1 << 16];
    let mut left = size;
    while left > 0 {
        let n = u64::min(left, block.len() as u64);
        out.write_all(&block[..n as usize])?;
        left -= n;
    }
    out.flush()?;
    out.get_ref().sync_all()
}

fn one_round(size: u64, lock: &Lock<'_>, unlock: &Unlock<'_>, label: &str, dir: &Path) {
    println!("{label}, {size} bytes");
    let (scratch, outs) = (dir.join("scratch"), dir.join("out"));
    private_dir(&scratch);
    private_dir(&outs);
    let plain = dir.join("plain.bin");
    write_demo(&plain, size).unwrap();
    let folder = OutputFolder::open(&outs).unwrap();
    let (sealed_name, opened_name) = (OsStr::new("demo.age"), OsStr::new("opened.bin"));

    stage("encrypt, disk to disk", size, || {
        let source = SourceFile::open(&plain).unwrap();
        encrypt_file(source, &folder, sealed_name, lock, &mut |_, _| true).unwrap();
    });
    let root = ScratchRoot::open(&scratch).unwrap();
    let snapshot = stage("capture and seal", size, || {
        let source = SourceFile::open(&outs.join(sealed_name)).unwrap();
        root.capture_file(source, &mut |_, _| true).unwrap()
    });
    let unwrapped = stage("unlock, KDF if any", size, || {
        snapshot.unlock(unlock).unwrap()
    });
    let validated = stage("validate, discarding", size, || {
        match unwrapped.validate(&mut |_, _| true).unwrap() {
            Validation::Ready(v) => v,
            Validation::Weak(w) => w.accept(),
        }
    });
    let written = stage("save a new file", size, || {
        validated
            .save_new(&folder, opened_name, &mut |_, _| true)
            .unwrap()
    });
    assert_eq!(written, size);
    assert_eq!(fs::metadata(outs.join(opened_name)).unwrap().len(), size);
    fs::remove_file(&plain).unwrap();
    fs::remove_file(outs.join(sealed_name)).unwrap();
    fs::remove_file(outs.join(opened_name)).unwrap();
    fs::remove_dir(&scratch).unwrap();
    fs::remove_dir(&outs).unwrap();
}

#[test]
#[ignore = "writes gigabytes of demo data; run by hand"]
fn fil03_t22_measured_costs_for_the_report() {
    let dir = std::env::temp_dir().join(format!("larsal-files-measure-{}", std::process::id()));
    private_dir(&dir);
    println!(
        "write cost {WRITE_LOG_N}, read ceiling {READ_MAX_LOG_N}; {}; debug assertions {}",
        std::env::consts::ARCH,
        cfg!(debug_assertions)
    );
    let to = [Recipient::parse(RECIPIENT).unwrap()];
    let keys = Identities::single(&SecretString::from(ID)).unwrap();
    let phrase = SecretString::from("demo passphrase");
    for size in SIZES {
        one_round(
            size,
            &Lock::Recipients(&to),
            &Unlock::Identities(&keys),
            "X25519",
            &dir,
        );
        one_round(
            size,
            &Lock::Passphrase(&phrase),
            &Unlock::Passphrase(&phrase),
            "passphrase",
            &dir,
        );
    }
    fs::remove_dir(&dir).unwrap();

    // FIL-03-T03's ceiling: the one derivation a file can ask of a reader. The key
    // it gives opens nothing here, so the file needs no derivation to make.
    let filler = "A".repeat(43);
    let ceiling = format!(
        "age-encryption.org/v1\n-> scrypt {} {READ_MAX_LOG_N}\n{filler}\n--- {filler}\n",
        "A".repeat(22),
    );
    println!("key derivation at the read ceiling");
    let result = stage("unlock, KDF", 0, || {
        open_all(ceiling.as_bytes(), &Unlock::Passphrase(&phrase)).map(|_| ())
    });
    assert_eq!(result, Err(Error::Decrypt));
}
