//! E23-S3 check 4: what a real run costs, stage by stage, disk to disk, with the method of
//! LD-378: fresh baseline rates on this Mac, five runs of each, median and p95, bytes and
//! hash equality, peak RAM, every stage, and 1 against up to 4 workers with the same checks.
//! Ignored: it writes gigabytes of demo data. Run from a release build:
//! `cargo test --release -p larsal-folders --test measure -- --ignored --nocapture`
//! A target not met is a finding, not a changed target.

mod common;

use common::{ENC, MAC, PASSWORD, dir_path, fresh, make_folder, raw_name, secret};
use larsal_crypto::hash::{Algorithm, Hasher};
use larsal_folders::{Error, Phase, Stores, Vault};
use larsal_platform::macos::resident_bytes;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

const MIB: u64 = 1 << 20;
/// The whole measurement stops itself here, and says what it did not run.
/// Eight minutes, so the whole run with its setup stays under the ten of the story.
const CAP: Duration = Duration::from_secs(8 * 60);
const RUNS: usize = 5;

static STOP: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicU64 = AtomicU64::new(0);

/// Runs `work` and the resident-memory sampler; gives its time and its peak above the
/// resident size at its start, so what earlier work left (the key work's) is not counted.
fn timed<T>(work: impl FnOnce() -> T) -> (T, f64, u64) {
    STOP.store(false, Relaxed);
    let resident = resident_bytes().unwrap();
    PEAK.store(resident, Relaxed);
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
    (value, took, PEAK.load(Relaxed).saturating_sub(resident))
}

fn median_p95(values: &[f64]) -> (f64, f64) {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let at = |q: f64| sorted[((sorted.len() - 1) as f64 * q).ceil() as usize];
    (at(0.5), at(0.95))
}

fn mib_s(bytes: u64, seconds: f64) -> f64 {
    bytes as f64 / MIB as f64 / seconds.max(1e-9)
}

/// Demo bytes that do not repeat by block: a 1 MiB pattern with a counter in it.
fn write_source(path: &Path, size: u64) -> String {
    let mut block: Vec<u8> = (0..MIB as usize).map(|i| (i % 251) as u8).collect();
    let mut out = BufWriter::with_capacity(MIB as usize, File::create(path).unwrap());
    let mut hasher = Hasher::new(Algorithm::Sha256);
    let mut at = 0u64;
    while at < size {
        block[..8].copy_from_slice(&at.to_be_bytes());
        out.write_all(&block).unwrap();
        hasher.update(&block);
        at += MIB;
    }
    out.flush().unwrap();
    out.get_ref().sync_all().unwrap();
    common::hex(hasher.finalize().expose())
}

fn hash_file(path: &Path) -> (u64, String) {
    let mut file = File::open(path).unwrap();
    let mut hasher = Hasher::new(Algorithm::Sha256);
    let mut block = vec![0u8; MIB as usize];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut block).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
        total += n as u64;
    }
    (total, common::hex(hasher.finalize().expose()))
}

/// Fresh same-Mac rates: write and fsync, then read back. Reads come from the cache, as in
/// the card's baseline: an upper bound on storage, not a speed of the medium.
fn baseline(dir: &Path) -> (f64, f64) {
    let path = dir.join("baseline.bin");
    let block = vec![0xA5u8; MIB as usize];
    let (mut writes, mut reads) = (Vec::new(), Vec::new());
    for _ in 0..3 {
        let ((), took, _) = timed(|| {
            let mut f = File::create(&path).unwrap();
            for _ in 0..256 {
                f.write_all(&block).unwrap();
            }
            f.sync_all().unwrap();
        });
        writes.push(mib_s(256 * MIB, took));
        let ((), took, _) = timed(|| {
            let mut f = File::open(&path).unwrap();
            let mut got = vec![0u8; MIB as usize];
            while f.read(&mut got).unwrap() > 0 {}
        });
        reads.push(mib_s(256 * MIB, took));
    }
    fs::remove_file(path).unwrap();
    (median_p95(&reads).0, median_p95(&writes).0)
}

struct Fix {
    top: PathBuf,
    path: PathBuf,
    stores: Stores,
    vault: Vault,
}

/// A folder made for real, with a new folder's key cost.
fn real_folder(tag: &str) -> Fix {
    let top = fresh(tag);
    let path = top.join("folder");
    let stores = Stores::open(&top.join("stores")).unwrap();
    let (vault, took, _) =
        timed(|| Vault::create(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap());
    println!("  create folder, N=2^18 (key work and first objects): {took:.3} s");
    Fix {
        top,
        path,
        stores,
        vault,
    }
}

/// Removes what a run stored and its recovery copies, by the test's own hand: this demo
/// folder is the test's, and the copies would otherwise pass the ceiling on purpose.
fn tidy(fix: &Fix) {
    for item in fix.vault.recovery_items().unwrap() {
        fix.vault
            .recovery_discard(&item.id, item.base, item.new)
            .unwrap();
    }
    let d = fix.path.join("d");
    for first in fs::read_dir(&d).unwrap() {
        for second in fs::read_dir(first.unwrap().path()).unwrap() {
            for entry in fs::read_dir(second.unwrap().path()).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() != "dirid.c9r" {
                    fs::remove_file(entry.path()).unwrap();
                }
            }
        }
    }
}

struct Sizes {
    create: Vec<f64>,
    pipeline: Vec<f64>,
    capture: Vec<f64>,
    validate: Vec<f64>,
    write: Vec<f64>,
    peak: u64,
}

fn one_size(fix: &Fix, size: u64, workers: usize, runs: usize, started: Instant) -> Option<Sizes> {
    let source = fix.top.join("source.bin");
    let want = write_source(&source, size);
    let output = fix.top.join("output.bin");
    fix.vault.set_workers(workers);
    let mut got = Sizes {
        create: Vec::new(),
        pipeline: Vec::new(),
        capture: Vec::new(),
        validate: Vec::new(),
        write: Vec::new(),
        peak: 0,
    };
    let root = fix.vault.root_dir().unwrap();
    let mut last = Duration::ZERO;
    for run in 0..runs {
        // A run that would end past the cap is not started.
        if started.elapsed() + last > CAP {
            println!("  stopped by the time cap at run {run} of {runs}");
            break;
        }
        let run_started = Instant::now();
        let name = format!("data-{run}.bin");
        let (node, took, peak) = timed(|| {
            let mut input = File::open(&source).unwrap();
            fix.vault
                .create_file(&root, &name, &mut input, size, &mut |_, _| true)
                .unwrap()
        });
        got.create.push(took);
        got.peak = got.peak.max(peak);

        let (snapshot, capture, p1) = timed(|| fix.vault.capture(&node, &mut |_, _| true).unwrap());
        let (proven, validate, p2) = timed(|| snapshot.validate(&mut |_, _| true).unwrap());
        let (_, write, p3) = timed(|| {
            let mut out = BufWriter::with_capacity(MIB as usize, File::create(&output).unwrap());
            let n = proven.write_to(&mut out, &mut |_, _| true).unwrap();
            out.flush().unwrap();
            out.get_ref().sync_all().unwrap();
            n
        });
        got.capture.push(capture);
        got.validate.push(validate);
        got.write.push(write);
        got.pipeline.push(capture + validate + write);
        got.peak = got.peak.max(p1).max(p2).max(p3);
        let (len, hash) = hash_file(&output);
        assert_eq!(
            (len, hash.as_str()),
            (size, want.as_str()),
            "bytes and hash, run {run}"
        );
        fs::remove_file(&output).unwrap();
        tidy(fix);
        last = run_started.elapsed();
    }
    fs::remove_file(&source).unwrap();
    Some(got)
}

fn report(label: &str, size: u64, got: &Sizes) -> (f64, f64) {
    let line = |what: &str, values: &[f64]| -> (f64, f64) {
        let rates: Vec<f64> = values.iter().map(|t| mib_s(size, *t)).collect();
        let (m, _) = median_p95(&rates);
        let worst = rates.iter().copied().fold(f64::MAX, f64::min);
        let (tm, tp) = median_p95(values);
        println!(
            "  {label:<14} {what:<18} median {m:>9.1} MiB/s ({tm:>8.3} s)  p95 time {tp:>8.3} s  slowest {worst:>9.1} MiB/s  runs {}",
            values.len()
        );
        (m, tp)
    };
    let c = line("create", &got.create);
    line("capture", &got.capture);
    line("validate", &got.validate);
    line("write", &got.write);
    let p = line("read to new output", &got.pipeline);
    println!(
        "  {label:<14} peak resident above the start {:.1} MiB; bytes and hash equal on every run",
        got.peak as f64 / MIB as f64
    );
    (c.0, p.0)
}

/// A folder with `count` plain files by hand: the demo keys, ordinary names, little content.
fn hand_folder(tag: &str, count: usize) -> (PathBuf, Stores, Vault) {
    let top = fresh(tag);
    let path = top.join("folder");
    make_folder(&path, PASSWORD);
    let dir = path.join(dir_path(&ENC, &MAC, b""));
    let body = common::seal_plain(&ENC, b"listed");
    for i in 0..count {
        fs::write(
            dir.join(raw_name(&ENC, &MAC, b"", &format!("ordinary name {i}.txt"))),
            &body,
        )
        .unwrap();
    }
    let stores = Stores::open(&top.join("stores")).unwrap();
    let vault = Vault::unlock(&path, &secret(PASSWORD), &stores, &mut |_, _| true).unwrap();
    (path, stores, vault)
}

fn listing_times() -> (f64, f64, f64, f64) {
    let (_p, _s, vault) = hand_folder("list128", 128);
    let root = vault.root_dir().unwrap();
    let mut small = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        let mut listing = vault.open_listing(&root).unwrap();
        let mut rows = 0;
        loop {
            let page = listing.next_page(256).unwrap();
            if page.is_empty() {
                break;
            }
            rows += page.len();
        }
        small.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(rows, 128);
    }
    let (_p, _s, vault) = hand_folder("list10k", 10_000);
    let root = vault.root_dir().unwrap();
    let mut first = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        let mut listing = vault.open_listing(&root).unwrap();
        let page = listing.next_page(256).unwrap();
        first.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(page.len(), 256);
        assert_eq!(listing.total(), 10_000);
    }
    let (a, b) = median_p95(&small);
    let (c, d) = median_p95(&first);
    (a, b, c, d)
}

/// The gaps between progress calls, the first call's delay, and how long a cancel takes to
/// come back, for a read and for a write, over a large file.
fn responsiveness(fix: &Fix, size: u64) {
    let source = fix.top.join("resp.bin");
    write_source(&source, size);
    let root = fix.vault.root_dir().unwrap();
    fix.vault.set_workers(4);
    let (mut firsts, mut gaps, mut acks) = (Vec::new(), Vec::new(), Vec::new());
    let mut cancels = Vec::new();

    for run in 0..RUNS {
        // A write: first progress, the boundary gaps, then a cancel half way.
        let start = Instant::now();
        let mut last = start;
        let mut input = File::open(&source).unwrap();
        let mut at_cancel = None;
        let name = format!("resp-{run}");
        let got = fix
            .vault
            .create_file(&root, &name, &mut input, size, &mut |_, done| {
                let now = Instant::now();
                if firsts.len() == run {
                    firsts.push(now.duration_since(start).as_secs_f64() * 1000.0);
                } else {
                    gaps.push(now.duration_since(last).as_secs_f64() * 1000.0);
                }
                last = now;
                if done >= size / 2 {
                    at_cancel = Some(Instant::now());
                    return false;
                }
                true
            });
        acks.push(at_cancel.unwrap().elapsed().as_secs_f64() * 1000.0);
        assert_eq!(got.err(), Some(Error::Cancelled));
    }
    // A read: stored once, cancelled half way through each pass.
    let mut input = File::open(&source).unwrap();
    let node = fix
        .vault
        .create_file(&root, "resp-read", &mut input, size, &mut |_, _| true)
        .unwrap();
    for run in 0..RUNS {
        let phase = [Phase::Capture, Phase::Validate, Phase::Write][run % 3];
        let mut at_cancel = None;
        let mut sink = io::sink();
        let got = fix.vault.read_to(&node, &mut sink, &mut |p, done| {
            if p == phase && done >= size / 2 {
                at_cancel = Some(Instant::now());
                return false;
            }
            true
        });
        cancels.push(at_cancel.unwrap().elapsed().as_secs_f64() * 1000.0);
        assert_eq!(got.err(), Some(Error::Cancelled));
    }
    tidy(fix);
    fs::remove_file(&source).unwrap();
    let say = |what: &str, target: &str, values: &[f64]| {
        let (m, p) = median_p95(values);
        let max = values.iter().copied().fold(0.0, f64::max);
        println!(
            "  {what:<44} median {m:>8.2} ms  p95 {p:>8.2} ms  max {max:>8.2} ms  target {target}  samples {}",
            values.len()
        );
    };
    say("first progress of a write", "<= 100 ms", &firsts);
    say(
        "cooperative chunk boundary (between calls)",
        "<= 250 ms",
        &gaps,
    );
    say("cancel acknowledged, write", "<= 100 ms", &acks);
    say("cancel acknowledged, read", "<= 100 ms", &cancels);
}

/// After the key work: until the first page is in hand.
fn idle_unlock(fix: &Fix, runs: usize) -> (f64, f64) {
    let root = fix.vault.root_dir().unwrap();
    for i in 0..256 {
        fix.vault
            .create_file(
                &root,
                &format!("idle {i}.txt"),
                &mut &b"x"[..],
                1,
                &mut |_, _| true,
            )
            .unwrap();
    }
    let mut after = Vec::new();
    let mut kdf = Vec::new();
    for _ in 0..runs {
        let mut before_kdf = None;
        let mut after_kdf = None;
        let vault = Vault::unlock(&fix.path, &secret(PASSWORD), &fix.stores, &mut |_, n| {
            let now = Instant::now();
            if n == 0 {
                before_kdf = Some(now);
            } else {
                after_kdf = Some(now);
            }
            true
        })
        .unwrap();
        let root = vault.root_dir().unwrap();
        let page = vault.open_listing(&root).unwrap().next_page(256).unwrap();
        assert_eq!(page.len(), 256);
        let done = after_kdf.unwrap();
        after.push(done.elapsed().as_secs_f64() * 1000.0);
        kdf.push(done.duration_since(before_kdf.unwrap()).as_secs_f64() * 1000.0);
    }
    let (m, _) = median_p95(&kdf);
    println!("  key work itself, N=2^18, r=8: median {m:.1} ms (not counted, and not lowered)");
    median_p95(&after)
}

#[test]
#[ignore = "writes gigabytes of demo data; run on purpose, in release"]
fn measure_speed_targets() {
    let started = Instant::now();
    if cfg!(debug_assertions) {
        panic!("run this from a release build");
    }
    let fix = real_folder("measure");
    let (r, w) = baseline(&fix.top);
    let target = 100f64.min(0.25 / (3.0 / r + 2.0 / w));
    println!("baseline, 256 MiB: read {r:.1} MiB/s (from the cache), write+fsync {w:.1} MiB/s");
    println!(
        "target: min(100, 0.25/(3/R+2/W)) = {target:.1} MiB/s for read to output; create: the same 100 MiB/s"
    );
    println!(
        "workers on this Mac: {}",
        std::thread::available_parallelism().unwrap()
    );

    // The short targets first, so the cap can only cut the large sizes.
    println!("-- listing");
    let (a, b, c, d) = listing_times();
    println!(
        "  list 128 names            median {a:.2} ms  p95 {b:.2} ms  target <= 250 ms: {}",
        if a <= 250.0 { "MET" } else { "NOT MET" }
    );
    println!(
        "  10,000 names, first 256   median {c:.2} ms  p95 {d:.2} ms  target <= 500 ms: {}",
        if c <= 500.0 { "MET" } else { "NOT MET" }
    );

    println!("-- idle unlock after the key work, 256 files, then the first page, {RUNS} runs");
    let (m, p) = idle_unlock(&fix, RUNS);
    println!(
        "  median {m:.2} ms  p95 {p:.2} ms  target <= 500 ms: {}",
        if m <= 500.0 { "MET" } else { "NOT MET" }
    );

    println!("-- responsiveness, 1 GiB, 4 workers");
    responsiveness(&fix, 1024 * MIB);

    println!("-- sizes, 4 workers, {RUNS} runs");
    for (label, size) in [
        ("256 MiB", 256 * MIB),
        ("1 GiB", 1024 * MIB),
        ("4 GiB", 4096 * MIB),
    ] {
        match one_size(&fix, size, 4, RUNS, started) {
            Some(got) if !got.create.is_empty() => {
                let (c, p) = report(label, size, &got);
                println!(
                    "  {label:<14} against target: create {} ({c:.1} >= 100), read to output {} ({p:.1} >= {target:.1})",
                    if c >= 100.0 { "MET" } else { "NOT MET" },
                    if p >= target { "MET" } else { "NOT MET" },
                );
            }
            _ => println!("  {label:<14} not run: the time cap"),
        }
    }

    println!("-- 1, 2 and 4 workers with identical checks, 1 GiB, {RUNS} runs");
    for workers in [1, 2, 4] {
        match one_size(&fix, 1024 * MIB, workers, RUNS, started) {
            Some(got) if !got.create.is_empty() => {
                report(&format!("{workers} workers"), 1024 * MIB, &got);
            }
            _ => println!("  {workers} workers not run: the time cap"),
        }
    }
    println!(
        "total {:.1} s (cap {} s)",
        started.elapsed().as_secs_f64(),
        CAP.as_secs()
    );
}
