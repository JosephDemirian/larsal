//! E6-S6 benchmark body, shared by `bench_zeroing.rs` (the zeroing
//! allocator, as the `larsal` tool and the Mac app run) and `bench_system.rs`
//! (the system allocator alone). Opens and saves the 10,000-entry demo vault
//! and prints the median of 5 runs of each; the key derivation is the same
//! in both, so the difference is the allocator's cost.
//!
//! cargo test --release -p larsal-cli --test bench_zeroing --test bench_system -- --ignored --nocapture

use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved, open, save};
use std::time::{Duration, Instant};

pub fn run(allocator: &str) {
    let file = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/big-10000.larsalvault"
    ))
    .unwrap();
    let pw = SecretString::new("demo-pass-6".to_owned());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut host = Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1000,
        }),
    };
    let (mut opens, mut saves) = (Vec::new(), Vec::new());
    for _ in 0..5 {
        let t = Instant::now();
        let Ok(Opened::Vault(v)) = open(&file, &creds, &mut host, &Limits::DEFAULT, None) else {
            panic!("big-10000 opens")
        };
        opens.push(t.elapsed());
        let t = Instant::now();
        let Ok(Saved::File(f)) = save(
            &v.vault,
            &creds,
            Some(&v.key),
            &mut host,
            &Limits::DEFAULT,
            None,
        ) else {
            panic!("big-10000 saves")
        };
        drop((v, f));
        saves.push(t.elapsed());
    }
    let median = |mut d: Vec<Duration>| {
        d.sort();
        d[d.len() / 2].as_secs_f64() * 1000.0
    };
    println!(
        "{allocator}: open {:.1} ms, save {:.1} ms (median of 5, big-10000)",
        median(opens),
        median(saves)
    );
}
