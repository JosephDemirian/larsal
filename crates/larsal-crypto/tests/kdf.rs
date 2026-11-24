//! Key derivation through the public API (story E2-S5, spec CRY-02).
//! Vectors: CRY-02 test cases (named per test). The RFC 9106 vectors with a
//! secret and associated data are unit tests in src/kdf.rs, because the
//! public API never takes either (CRY-02.17).

use larsal_crypto::Error;
use larsal_crypto::kdf::{
    AES_KDF_ID, AES_KDF_NEW_ID, ARGON2D_ID, ARGON2ID_ID, Argon2Type, Ceilings, CostReport, Host,
    KdfParams, SpeedRecord, Verdict, assess, benchmark, derive,
};
use larsal_crypto::secret::SecretBytes;
use proptest::prelude::*;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A wall clock for tests; Larsal passes the thread's CPU time (LD-72).
fn wall_clock() -> Duration {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The ceilings proposed in CRY-02.14 and accepted in LD-22.
const CEILINGS: Ceilings = Ceilings {
    refuse_iterations: 1_000_000_000,
    ask_memory_kib: 1_048_576,
    ask_lanes: 128,
    ask_ms: 10_000,
};

/// The CRY-02 T25 test hooks: 16 GiB, 8 logical processors, both speed records.
fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 4,
            ms: 1_000,
        }),
        aes_record: Some(SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 150,
        }),
    }
}

fn aes(rounds: u64, seed: &[u8]) -> KdfParams {
    KdfParams::AesKdf {
        rounds,
        seed: seed.to_vec(),
    }
}

fn argon(kind: Argon2Type, iterations: u64, memory_kib: u64, lanes: u64) -> KdfParams {
    KdfParams::Argon2 {
        kind,
        version: 0x13,
        iterations,
        memory_kib,
        lanes,
        salt: (0..32).collect(),
    }
}

/// Assess (must say Run), then derive. Returns the transformed key as hex.
fn derive_hex(composite: &str, params: &KdfParams) -> String {
    let key = SecretBytes::new(hex(composite));
    let Verdict::Run(cleared) = assess(params, &mut host(), &CEILINGS, None).unwrap() else {
        panic!("expected Run");
    };
    let out = derive(&key, &cleared).unwrap();
    assert_eq!(out.len(), 32);
    out.expose().iter().map(|b| format!("{b:02x}")).collect()
}

fn verdict(params: &KdfParams) -> Result<Verdict<'_>, Error> {
    assess(params, &mut host(), &CEILINGS, None)
}

fn ask(params: &KdfParams) -> CostReport {
    ask_with(params, &mut host())
}

fn ask_with(params: &KdfParams, host: &mut Host) -> CostReport {
    match assess(params, host, &CEILINGS, None) {
        Ok(Verdict::Ask(report)) => report,
        other => panic!("expected Ask, got {other:?}"),
    }
}

// composite("demo-pw") and S = 00 01 .. 1f (CRY-02 T4, T7 to T11).
const DEMO: &str = "f2973021930881894a6de0f6d67fcc736f1f670ffd2c0b23d59ace17e6f31d8e";
// NIST SP 800-38A F.1.5 key and plaintext (CRY-02 T1 to T3).
const NIST_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const NIST_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

#[test]
fn aes_kdf_card_vectors() {
    let seed = hex(NIST_KEY);
    let cases = [
        // CRY-02 T1 (blocks from NIST SP 800-38A F.1.5).
        (
            1,
            "ff823b5bda041640278b85e2dcafe390dfe91fea65147cdfc949c4d94a27b125",
        ),
        // CRY-02 T2.
        (
            2,
            "0a895b48f536bac86351455753aefdc450f7fa43f2091d687112854c2b35c8f8",
        ),
        // CRY-02 T3.
        (
            1_000,
            "2899eefeed851099fd0f0aeca382d7dbcee9708ddf3cacaa49ed7a880698776c",
        ),
        (
            6_000,
            "b124a3df8c6b0c3cbb8b02a4bab60a5170ff609c9d9e7cc8b03401096eddd401",
        ),
        (
            1_000_000,
            "4ba764a81b1538578a821e9d29ddaad5befb6ddb294ae6a6cefebac6a18da262",
        ),
    ];
    for (rounds, want) in cases {
        assert_eq!(
            derive_hex(NIST_PLAIN, &aes(rounds, &seed)),
            want,
            "R = {rounds}"
        );
    }
}

#[test]
fn aes_kdf_full_chain_demo_password() {
    // CRY-02 T4: composite("demo-pw"), S = 00 01 .. 1f, R = 1,000.
    let seed: Vec<u8> = (0..32).collect();
    assert_eq!(
        derive_hex(DEMO, &aes(1_000, &seed)),
        "a47cdee61f8445f25a7913e502d33bbc48f20459b42e8a396a0f6021497c3a84"
    );
}

#[test]
fn argon2_no_secret_card_vectors() {
    use Argon2Type::{D, Id};
    // CRY-02 T7, T8, T9.
    let cases = [
        (
            argon(D, 2, 1_024, 2),
            "6e8abd847c712da999584804acfb39c1f7eac4057078043298ca8a28910a9175",
        ),
        (
            argon(Id, 2, 1_024, 2),
            "343306087c7cc35646f7c6fab53a56251a4e47bfbeb07c550f95e19a3bfd9074",
        ),
        (
            argon(D, 1, 1_024, 1),
            "42d120fb02f576e4a3e5eacc908257ab048fe4d0df8775baa3da65e1e1a2cece",
        ),
    ];
    for (params, want) in &cases {
        assert_eq!(derive_hex(DEMO, params), *want, "{params:?}");
    }
}

#[test]
fn argon2_version_1_0() {
    // CRY-02 T11: as T7 but V = 0x10.
    let KdfParams::Argon2 { salt, .. } = argon(Argon2Type::D, 2, 1_024, 2) else {
        unreachable!()
    };
    let params = KdfParams::Argon2 {
        kind: Argon2Type::D,
        version: 0x10,
        iterations: 2,
        memory_kib: 1_024,
        lanes: 2,
        salt,
    };
    assert_eq!(
        derive_hex(DEMO, &params),
        "c4a3be5a9a0026e0089c114158572ad4ac1b9d2e727b8edb193fa4e1ff7c71da"
    );
}

#[test]
fn argon2_reference_test_vault_numbers() {
    // CRY-02 T10: the composite and map values the card lists.
    let params = KdfParams::Argon2 {
        kind: Argon2Type::D,
        version: 19,
        iterations: 2,
        memory_kib: 1_048_576 / 1024,
        lanes: 2,
        salt: hex("56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5"),
    };
    assert_eq!(
        derive_hex(
            "7415e100520c4fc2de9429958c0b64500a076b48ef2ad0648c7243c52046c671",
            &params
        ),
        "5ef06327c2aa395e04aa9a94fb837b58030cf202eddc61f408046070c256a2e8"
    );
}

#[test]
fn ids_are_the_card_bytes() {
    // CRY-02 KDF ids table; AES-KDF is always written with the old id (CRY-02.19).
    assert_eq!(aes(1, &[0; 32]).id(), AES_KDF_ID);
    assert_eq!(argon(Argon2Type::D, 1, 8, 1).id(), ARGON2D_ID);
    assert_eq!(argon(Argon2Type::Id, 1, 8, 1).id(), ARGON2ID_ID);
    assert_eq!(AES_KDF_ID.to_vec(), hex("c9d9f39a628a4460bf740d08c18a4fea"));
    assert_eq!(
        AES_KDF_NEW_ID.to_vec(),
        hex("7c02bb8279a74ac0927d114a00648238")
    );
    assert_eq!(ARGON2D_ID.to_vec(), hex("ef636ddf8c29444b91f7a9a403e30a0c"));
    assert_eq!(
        ARGON2ID_ID.to_vec(),
        hex("9e298b1956db4773b23dfc3ec6f0a1e6")
    );
}

#[test]
fn composite_must_be_32_bytes() {
    let params = aes(1, &[0; 32]);
    let Verdict::Run(cleared) = verdict(&params).unwrap() else {
        panic!("expected Run");
    };
    for len in [0, 31, 33] {
        let key = SecretBytes::new(vec![0; len]);
        assert_eq!(derive(&key, &cleared).unwrap_err(), Error::KeyLength);
    }
}

fn settings_error(params: &KdfParams) {
    let clock = Instant::now();
    assert_eq!(
        verdict(params).unwrap_err(),
        Error::KdfSettings,
        "{params:?}"
    );
    assert!(
        clock.elapsed() < Duration::from_millis(50),
        "must return at once"
    );
}

fn passes_ranges(params: &KdfParams) {
    assert!(
        !matches!(verdict(params), Err(Error::KdfSettings)),
        "{params:?}"
    );
}

#[test]
fn argon2_salt_lengths() {
    // CRY-02 T15: 7 and 33 refused; 8, 16, 32 accepted.
    for (len, ok) in [(7, false), (8, true), (16, true), (32, true), (33, false)] {
        let params = KdfParams::Argon2 {
            kind: Argon2Type::Id,
            version: 0x13,
            iterations: 1,
            memory_kib: 1_024,
            lanes: 1,
            salt: vec![2; len],
        };
        if ok {
            passes_ranges(&params);
        } else {
            settings_error(&params);
        }
    }
}

#[test]
fn argon2_versions() {
    // CRY-02 T16: only 0x10 and 0x13; the full-width 2^32 + 0x13 is refused.
    for (version, ok) in [
        (0x0F, false),
        (0x10, true),
        (0x11, false),
        (0x12, false),
        (0x13, true),
        (0x14, false),
        ((1 << 32) + 0x13, false),
    ] {
        let params = KdfParams::Argon2 {
            kind: Argon2Type::D,
            version,
            iterations: 1,
            memory_kib: 1_024,
            lanes: 1,
            salt: vec![0; 32],
        };
        if ok {
            passes_ranges(&params);
        } else {
            settings_error(&params);
        }
    }
}

#[test]
fn argon2_lanes() {
    // CRY-02 T17, with m = max(1,024, 8P) KiB, 16 GiB and 8 processors.
    let p = |lanes: u64| argon(Argon2Type::Id, 1, (8 * lanes).max(1_024), lanes);
    settings_error(&p(0));
    settings_error(&p(16_777_216));
    settings_error(&argon(Argon2Type::Id, 1, 1_024, (1 << 32) + 4));
    assert!(matches!(verdict(&p(1)), Ok(Verdict::Run(_))));
    assert!(matches!(verdict(&p(128)), Ok(Verdict::Run(_))));
    assert!(ask(&p(129)).over_lanes());
    // 16,777,215 lanes need 128 GiB, more than the fixed 16 GiB.
    assert_eq!(verdict(&p(16_777_215)).unwrap_err(), Error::KdfCost);
}

#[test]
fn argon2_memory_floor_and_lanes() {
    // CRY-02 T19: 7 KiB. T20: 8 KiB with P = 2 refused; 16 KiB with P = 2
    // and 8 KiB with P = 1 accepted.
    settings_error(&argon(Argon2Type::D, 1, 7, 1));
    settings_error(&argon(Argon2Type::D, 1, 8, 2));
    passes_ranges(&argon(Argon2Type::D, 1, 16, 2));
    passes_ranges(&argon(Argon2Type::D, 1, 8, 1));
}

#[test]
fn argon2_iterations() {
    // CRY-02 T21: only 1 and 2,147,483,646 pass the range check.
    for (i, ok) in [
        (0, false),
        (1, true),
        (2_147_483_646, true),
        (2_147_483_647, false),
        (1 << 31, false),
        ((1 << 32) + 1, false),
    ] {
        let params = argon(Argon2Type::Id, i, 8, 1);
        if ok {
            passes_ranges(&params);
        } else {
            settings_error(&params);
        }
    }
}

#[test]
fn aes_kdf_seed_and_rounds() {
    // CRY-02 T22 (LD-14): seeds other than 32 bytes refused.
    for len in [8, 16, 31, 33] {
        settings_error(&aes(1, &vec![0; len]));
    }
    // CRY-02 T23: rounds.
    for r in [0, 1 << 31, (1 << 32) + 5] {
        settings_error(&aes(r, &[0; 32]));
    }
    passes_ranges(&aes(1, &[0; 32]));
    passes_ranges(&aes(2_147_483_646, &[0; 32]));
}

#[test]
fn cost_bomb_values_are_refused_at_once() {
    // CRY-02 T26 / AT-A05: 4 TiB (m = 2^32 KiB), I = 2^63, P = 2^24.
    settings_error(&argon(Argon2Type::Id, 1, 1 << 32, 4));
    settings_error(&argon(Argon2Type::Id, 1 << 63, 8, 1));
    settings_error(&argon(Argon2Type::Id, 1, 1 << 27, 1 << 24));
}

#[test]
fn over_the_ceiling_is_refused_before_any_work() {
    // CRY-02 T25 first two cases: no approval can lift them.
    for params in [
        argon(Argon2Type::Id, 1, (1 << 32) - 1, 4),
        argon(Argon2Type::Id, 1_000_000_001, 8, 1),
    ] {
        let clock = Instant::now();
        assert_eq!(verdict(&params).unwrap_err(), Error::KdfCost);
        assert!(
            clock.elapsed() < Duration::from_millis(50),
            "must return at once"
        );
        // Also with no speed record: refused before any calibration.
        let mut h = Host {
            argon2_record: None,
            ..host()
        };
        let clock = Instant::now();
        assert_eq!(
            assess(&params, &mut h, &CEILINGS, None).unwrap_err(),
            Error::KdfCost
        );
        assert!(clock.elapsed() < Duration::from_millis(50));
        assert_eq!(h.argon2_record, None, "no calibration ran");
    }
}

#[test]
fn memory_equal_to_the_mac_is_not_refused() {
    // CRY-02.14: refused only above physical memory.
    let mut h = Host {
        physical_memory: 1 << 30,
        ..host()
    };
    let params = argon(Argon2Type::Id, 1, 1 << 20, 4);
    assert!(matches!(
        assess(&params, &mut h, &CEILINGS, None),
        Ok(Verdict::Run(_))
    ));
    h.physical_memory -= 1;
    assert_eq!(
        assess(&params, &mut h, &CEILINGS, None).unwrap_err(),
        Error::KdfCost
    );
}

#[test]
fn f_134_damaged_speed_record_is_measured_again() {
    // A zero field in a stored record would turn off the time question;
    // it counts as no record (CRY-02.14 calibration).
    // The new record is this Mac's real speed, so the time limit is 1 s,
    // not 10 s: a billion rounds took 7 to 17 s on this Mac (F-134).
    let ceilings = Ceilings {
        ask_ms: 1_000,
        ..CEILINGS
    };
    let damaged = SpeedRecord {
        count: 10_000_000,
        memory_kib: 0,
        lanes: 1,
        ms: 0,
    };
    let mut h = Host {
        aes_record: Some(damaged),
        ..host()
    };
    let params = aes(1_000_000_000, &[0; 32]);
    let rounds = match assess(&params, &mut h, &ceilings, None) {
        Ok(Verdict::Ask(report)) => report,
        other => panic!("expected Ask, got {other:?}"),
    };
    assert!(rounds.over_time(), "a billion rounds still asks");
    let fresh = h.aes_record.expect("a new record is stored");
    assert!(fresh.ms > 0 && fresh.count >= 100_000);
}

#[test]
fn time_estimate_counts_one_thread() {
    // LD-38: Argon2 runs on one thread, so P = 16 on 8 processors takes as
    // long as P = 1. T25 record: 10 iterations of 64 MiB in 1,000 ms.
    let r = ask(&argon(Argon2Type::Id, 101, 65_536, 16));
    assert_eq!(r.estimated_ms(), 10_100);
    assert!(r.over_time() && !r.over_lanes());
}

#[test]
fn ask_band_gives_a_cost_report() {
    // CRY-02 T25 last two cases.
    let clock = Instant::now();
    let big = ask(&argon(Argon2Type::Id, 1, 2_097_152, 4));
    let wide = ask(&argon(Argon2Type::Id, 1, 1_032, 129));
    assert!(
        clock.elapsed() < Duration::from_millis(50),
        "must return at once"
    );
    assert_eq!(big.kdf_id(), ARGON2ID_ID);
    assert_eq!(
        (big.memory_bytes(), big.work(), big.lanes()),
        (2_147_483_648, 1, 4)
    );
    assert!(big.over_memory() && !big.over_lanes() && !big.over_time());
    assert_eq!(
        (wide.memory_bytes(), wide.work(), wide.lanes()),
        (1_056_768, 1, 129)
    );
    assert!(wide.over_lanes() && !wide.over_memory() && !wide.over_time());
    // Estimates (CRY-02 T25b): 2 GiB at I = 1, P = 4 is 1 × 32 × 1,000 / 10.
    assert_eq!(big.estimated_ms(), 3_200);
}

#[test]
fn time_estimate_asks_above_ten_seconds() {
    // CRY-02 T25b on one thread (LD-38): 10,100 ms and 15,000 ms ask;
    // 10,000 ms and 7,500 ms run.
    let slow = ask(&argon(Argon2Type::Id, 101, 65_536, 1));
    assert_eq!(slow.estimated_ms(), 10_100);
    assert!(slow.over_time() && !slow.over_memory() && !slow.over_lanes());
    assert!(matches!(
        verdict(&argon(Argon2Type::Id, 100, 65_536, 1)),
        Ok(Verdict::Run(_))
    ));
    let rounds = ask(&aes(1_000_000_000, &[0; 32]));
    assert_eq!(
        (rounds.kdf_id(), rounds.memory_bytes(), rounds.lanes()),
        (AES_KDF_ID, 0, 1)
    );
    assert_eq!(rounds.estimated_ms(), 15_000);
    assert!(matches!(
        verdict(&aes(500_000_000, &[0; 32])),
        Ok(Verdict::Run(_))
    ));
}

#[test]
fn approval_runs_once_and_binds_to_the_settings() {
    // CRY-02 T25: declining keeps the ask; approving runs the KDF.
    let params = argon(Argon2Type::Id, 1, 1_032, 129);
    let report = ask(&params);
    assert!(matches!(verdict(&params), Ok(Verdict::Ask(_))), "declined");
    let Verdict::Run(cleared) = assess(&params, &mut host(), &CEILINGS, Some(&report)).unwrap()
    else {
        panic!("approved settings must run");
    };
    let key = derive(&SecretBytes::new(vec![7; 32]), &cleared).unwrap();
    assert_eq!(key.len(), 32);
    // CRY-02 T25c: an approval for P = 129, m = 1,032 does not cover P = 130, m = 1,040.
    let other = argon(Argon2Type::Id, 1, 1_040, 130);
    assert!(matches!(
        assess(&other, &mut host(), &CEILINGS, Some(&report)),
        Ok(Verdict::Ask(_))
    ));
}

#[test]
fn approval_binds_each_setting_on_its_own() {
    // CRY-02.14: the approval holds the KDF id, m, I and P. Changing any one
    // of them alone asks again.
    let params = argon(Argon2Type::Id, 2, 1_032, 129);
    let report = ask(&params);
    for changed in [
        argon(Argon2Type::D, 2, 1_032, 129),
        argon(Argon2Type::Id, 2, 1_040, 129),
        argon(Argon2Type::Id, 3, 1_032, 129),
    ] {
        assert!(matches!(
            assess(&changed, &mut host(), &CEILINGS, Some(&report)),
            Ok(Verdict::Ask(_))
        ));
    }
    // Lanes alone, memory unchanged.
    let big = argon(Argon2Type::Id, 1, 2_097_152, 129);
    let report = ask(&big);
    let fewer = argon(Argon2Type::Id, 1, 2_097_152, 130);
    assert!(matches!(
        assess(&fewer, &mut host(), &CEILINGS, Some(&report)),
        Ok(Verdict::Ask(_))
    ));
    // AES-KDF rounds alone.
    let report = ask(&aes(1_000_000_000, &[0; 32]));
    assert!(matches!(
        assess(
            &aes(999_999_999, &[0; 32]),
            &mut host(),
            &CEILINGS,
            Some(&report)
        ),
        Ok(Verdict::Ask(_))
    ));
    // A made-up approval cannot lift a refusal.
    let refused = argon(Argon2Type::Id, 1_000_000_001, 8, 1);
    assert_eq!(
        assess(&refused, &mut host(), &CEILINGS, Some(&report)).unwrap_err(),
        Error::KdfCost
    );
}

#[test]
fn ceilings_come_from_the_caller() {
    // CRY-02.14: the thresholds live in larsal-format's limits; larsal-crypto uses
    // whatever it is given.
    let tight = Ceilings {
        refuse_iterations: 5,
        ask_memory_kib: 64,
        ask_lanes: 2,
        ask_ms: 0,
    };
    assert_eq!(
        assess(&argon(Argon2Type::Id, 6, 8, 1), &mut host(), &tight, None).unwrap_err(),
        Error::KdfCost
    );
    let big = argon(Argon2Type::Id, 5, 128, 3);
    let Ok(Verdict::Ask(r)) = assess(&big, &mut host(), &tight, None) else {
        panic!("expected Ask");
    };
    assert!(r.over_memory() && r.over_lanes() && r.over_time());
}

#[test]
fn missing_aes_record_is_calibrated_once() {
    // CRY-02.14 calibration: dummy inputs from 100,000 rounds, stored in the host.
    let mut h = Host {
        aes_record: None,
        ..host()
    };
    let params = aes(1_000, &[9; 32]);
    assert!(matches!(
        assess(&params, &mut h, &CEILINGS, None),
        Ok(Verdict::Run(_))
    ));
    let record = h.aes_record.expect("calibration stores a record");
    assert!(record.count >= 100_000);
    assert_eq!((record.memory_kib, record.lanes), (0, 1));
    // The record keeps the fastest of three runs at the count where one run
    // first took 50 ms, so its time can be a little under 50 ms.
    assert!(record.ms > 0, "a real run has a time");
    assess(&params, &mut h, &CEILINGS, None).unwrap();
    assert_eq!(h.aes_record, Some(record), "no second calibration");
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn missing_argon2_record_is_calibrated_with_64_mib() {
    // CRY-02.14: Argon2 calibration with the file's type, 64 MiB, p = min(4, n).
    let mut h = Host {
        argon2_record: None,
        logical_processors: 2,
        ..host()
    };
    assess(&argon(Argon2Type::D, 3, 1_024, 1), &mut h, &CEILINGS, None).unwrap();
    let record = h.argon2_record.expect("calibration stores a record");
    assert_eq!((record.memory_kib, record.lanes), (65_536, 2));
    assert!(
        record.count >= 1 && record.ms > 0,
        "fastest of three (LD-40)"
    );
    // An Argon2 record with memory 0 is damaged: it is measured again.
    h.argon2_record = Some(SpeedRecord {
        memory_kib: 0,
        ..record
    });
    assess(&argon(Argon2Type::D, 3, 1_024, 1), &mut h, &CEILINGS, None).unwrap();
    assert_eq!(h.argon2_record.map(|r| r.memory_kib), Some(65_536));
}

#[test]
fn benchmark_refuses_bad_input_before_work() {
    // CRY-02.28: target 100 to 5,000 ms; the template must be in range.
    let template = argon(Argon2Type::Id, 1, 65_536, 4);
    for target in [0, 99, 5_001] {
        assert_eq!(
            benchmark(&template, target, &host(), wall_clock).unwrap_err(),
            Error::KdfSettings
        );
    }
    let clock = Instant::now();
    let bad = argon(Argon2Type::Id, 1, 8, 2);
    assert_eq!(
        benchmark(&bad, 1_000, &host(), wall_clock).unwrap_err(),
        Error::KdfSettings
    );
    assert!(clock.elapsed() < Duration::from_millis(50));
    // RT-5: memory above this Mac's is refused before any work.
    let small = Host {
        physical_memory: 32 << 20,
        ..host()
    };
    let clock = Instant::now();
    assert_eq!(
        benchmark(&template, 1_000, &small, wall_clock).unwrap_err(),
        Error::KdfCost
    );
    assert!(clock.elapsed() < Duration::from_millis(50));
}

/// Times one derive with `params` (dummy key), as an unlock would run it.
fn unlock_ms(params: &KdfParams) -> u128 {
    let mut h = host();
    h.physical_memory = u64::MAX;
    let approved;
    let cleared = match assess(params, &mut h, &CEILINGS, None).unwrap() {
        Verdict::Run(c) => c,
        Verdict::Ask(report) => {
            approved = report;
            let Verdict::Run(c) = assess(params, &mut h, &CEILINGS, Some(&approved)).unwrap()
            else {
                unreachable!()
            };
            c
        }
    };
    let key = SecretBytes::new(vec![0x5A; 32]);
    let clock = Instant::now();
    derive(&key, &cleared).unwrap();
    clock.elapsed().as_millis()
}

fn median_unlock_ms(params: &KdfParams) -> u128 {
    let mut times: Vec<u128> = (0..5).map(|_| unlock_ms(params)).collect();
    times.sort_unstable();
    times[2]
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn benchmark_argon2id_default_lands_in_band() {
    // CRY-02 T41 (LD-19): Argon2id, 64 MiB, p = 4, target 1,000 ms; the
    // median of 5 unlocks is within 1,000 to 1,200 ms.
    let template = argon(Argon2Type::Id, 1, 65_536, 4);
    let result = benchmark(&template, 1_000, &host(), wall_clock).unwrap();
    let KdfParams::Argon2 {
        iterations,
        memory_kib,
        lanes,
        ..
    } = result.params
    else {
        panic!("type changed")
    };
    assert!(iterations >= 1);
    assert_eq!((memory_kib, lanes), (65_536, 4), "memory and p unchanged");
    assert_eq!(result.record.memory_kib, 65_536);
    let median = median_unlock_ms(&result.params);
    eprintln!("Argon2id: {iterations} iterations, median unlock {median} ms");
    assert!((1_000..=1_200).contains(&median), "median {median} ms");
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn benchmark_aes_kdf_lands_in_band() {
    // CRY-02.28 (LD-19) for AES-KDF, target 1,000 ms.
    let result = benchmark(&aes(1, &[0; 32]), 1_000, &host(), wall_clock).unwrap();
    let KdfParams::AesKdf { rounds, .. } = result.params else {
        panic!("type changed")
    };
    let median = median_unlock_ms(&result.params);
    eprintln!("AES-KDF: {rounds} rounds, median unlock {median} ms");
    assert!((1_000..=1_200).contains(&median), "median {median} ms");
}

/// Ranges of FMT-03.12 and CRY-02.10, written out again as the test's model.
fn in_range(i: u64, m: u64, p: u64, v: u64, salt: usize) -> bool {
    (1..=2_147_483_646).contains(&i)
        && (8..(1 << 32)).contains(&m)
        && (1..=16_777_215).contains(&p)
        && m >= 8 * p
        && (v == 0x10 || v == 0x13)
        && (8..=32).contains(&salt)
}

proptest! {
    #[test]
    fn assess_follows_the_rules_for_any_numbers(
        i in prop_oneof![0u64..=4, 999_999_990u64..=1_000_000_010, any::<u64>()],
        m in prop_oneof![0u64..=64, 1_048_570u64..=1_048_590, (1u64 << 24)..=(1u64 << 25), any::<u64>()],
        p in prop_oneof![0u64..=4, 120u64..=140, any::<u64>()],
        v in prop_oneof![Just(0x10u64), Just(0x13), any::<u64>()],
        salt in 0usize..40,
    ) {
        let params = KdfParams::Argon2 { kind: Argon2Type::Id, version: v, iterations: i, memory_kib: m, lanes: p, salt: vec![0; salt] };
        let h = host();
        let got = assess(&params, &mut host(), &CEILINGS, None);
        if !in_range(i, m, p, v, salt) {
            prop_assert_eq!(got.unwrap_err(), Error::KdfSettings);
        } else if m * 1024 > h.physical_memory || i > 1_000_000_000 {
            prop_assert_eq!(got.unwrap_err(), Error::KdfCost);
        } else {
            // T25 record on one thread (LD-38): I × m × 1,000 / (10 × 65,536).
            let est = (u128::from(i) * u128::from(m) * 1_000).div_ceil(655_360);
            let flags = (m > 1_048_576, p > 128, est > 10_000);
            match got.unwrap() {
                Verdict::Ask(r) => {
                    prop_assert_eq!((r.over_memory(), r.over_lanes(), r.over_time()), flags);
                    prop_assert_eq!(u128::from(r.estimated_ms()), est);
                }
                Verdict::Run(_) => prop_assert_eq!(flags, (false, false, false)),
            }
        }
    }

    #[test]
    fn approval_round_trip(p in 129u64..2_000, extra in 0u64..4_096, i in 1u64..100) {
        // Ask, approve with the same report: Run. A different P: Ask again.
        let params = argon(Argon2Type::D, i, 8 * p + extra, p);
        let report = ask(&params);
        prop_assert!(matches!(assess(&params, &mut host(), &CEILINGS, Some(&report)), Ok(Verdict::Run(_))));
        let changed = argon(Argon2Type::D, i, 8 * p + extra + 8, p + 1);
        prop_assert!(matches!(assess(&changed, &mut host(), &CEILINGS, Some(&report)), Ok(Verdict::Ask(_))));
    }
}

// -- Story E4-S13: the import derivations (FEA-08.35, FEA-08.49, FEA-08.50,
// FEA-08.68; LD-142). Every expected value below was also computed with
// `python3 -I` hashlib.pbkdf2_hmac and hmac on this Mac.

mod import {
    use super::hex;
    use larsal_crypto::Error;
    use larsal_crypto::kdf::{Prf, hkdf_expand_sha256, import_argon2id, pbkdf2};
    use larsal_crypto::secret::SecretBytes;

    fn secret(b: &[u8]) -> SecretBytes {
        SecretBytes::new(b.to_vec())
    }

    fn pb(prf: Prf, pw: &[u8], salt: &[u8], c: u64, len: usize) -> Vec<u8> {
        pbkdf2(prf, &secret(pw), salt, c, len)
            .unwrap()
            .expose()
            .to_vec()
    }

    // RFC 7914 section 11: the two PBKDF2-HMAC-SHA256 vectors.
    #[test]
    fn pbkdf2_sha256_rfc_7914_section_11() {
        let one = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                   49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
        assert_eq!(pb(Prf::Sha256, b"passwd", b"salt", 1, 64), hex(one));
        let two = "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
                   a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d";
        assert_eq!(pb(Prf::Sha256, b"Password", b"NaCl", 80_000, 64), hex(two));
    }

    // The RFC 6070 inputs with HMAC-SHA-256 (the widely published values).
    #[test]
    fn pbkdf2_sha256_rfc_6070_style() {
        for (c, want) in [
            (
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ] {
            assert_eq!(pb(Prf::Sha256, b"password", b"salt", c, 32), hex(want));
        }
        let long =
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9";
        let pw = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        assert_eq!(pb(Prf::Sha256, pw, salt, 4096, 40), hex(long));
        let nul = "89b69d0516f829893c696226650a8687";
        assert_eq!(
            pb(Prf::Sha256, b"pass\0word", b"sa\0lt", 4096, 16),
            hex(nul)
        );
    }

    // The RFC 6070 inputs with HMAC-SHA-512, 64-byte keys (OPVault uses
    // SHA-512 with a 64-byte output, FEA-08.35).
    #[test]
    fn pbkdf2_sha512_vectors() {
        for (c, want) in [
            (
                1,
                "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252\
                 c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
            ),
            (
                2,
                "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c\
                 f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
            ),
            (
                4096,
                "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5\
                 143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
            ),
        ] {
            let want: String = want.split_whitespace().collect();
            assert_eq!(pb(Prf::Sha512, b"password", b"salt", c, 64), hex(&want));
        }
        let long = "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71\
                    115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8";
        let pw = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        assert_eq!(pb(Prf::Sha512, pw, salt, 4096, 64), hex(long));
    }

    // FEA-08.68: 1 to 10,000,000 iterations; refused before any work, so
    // the ceiling plus one returns at once.
    #[test]
    fn pbkdf2_cost_range() {
        let pw = secret(b"demo");
        for c in [0, 10_000_001, u64::MAX] {
            let started = std::time::Instant::now();
            assert_eq!(
                pbkdf2(Prf::Sha256, &pw, b"s", c, 32).unwrap_err(),
                Error::KdfCost
            );
            assert!(started.elapsed().as_millis() < 50);
        }
        assert!(pbkdf2(Prf::Sha512, &pw, b"s", 1, 64).is_ok());
        for len in [0, 1_025] {
            assert_eq!(
                pbkdf2(Prf::Sha256, &pw, b"s", 1, len).unwrap_err(),
                Error::KeyLength
            );
        }
    }

    // RFC 5869 appendix A.1 to A.3, the expand step from the listed PRK.
    #[test]
    fn hkdf_expand_rfc_5869_a1_to_a3() {
        let a1_info: Vec<u8> = (0xf0..=0xf9).collect();
        let a2_info: Vec<u8> = (0xb0..=0xff).collect();
        for (prk, info, len, okm) in [
            (
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                a1_info.as_slice(),
                42,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                a2_info.as_slice(),
                82,
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                &[][..],
                42,
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ] {
            let okm: String = okm.split_whitespace().collect();
            let got = hkdf_expand_sha256(&secret(&hex(prk)), info, len).unwrap();
            assert_eq!(got.expose(), hex(&okm).as_slice());
        }
    }

    #[test]
    fn hkdf_expand_refuses_bad_lengths() {
        let prk = secret(&[7; 32]);
        for len in [0, 8_161] {
            assert_eq!(
                hkdf_expand_sha256(&prk, b"enc", len).unwrap_err(),
                Error::KeyLength
            );
        }
        assert_eq!(
            hkdf_expand_sha256(&prk, b"enc", 8_160).unwrap().len(),
            8_160
        );
        let short = secret(&[7; 31]);
        assert_eq!(
            hkdf_expand_sha256(&short, b"enc", 32).unwrap_err(),
            Error::KeyLength
        );
    }

    // The published Argon2id vector of the Argon2 authors' reference tool:
    // "password", salt "somesalt", t = 2, 64 MiB, p = 1, 32-byte tag.
    #[test]
    fn import_argon2id_published_vector() {
        let tag = import_argon2id(&secret(b"password"), b"somesalt", 2, 64, 1, 32).unwrap();
        assert_eq!(
            tag.expose(),
            hex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7").as_slice()
        );
    }

    // FEA-08.49 kdfType 1 is RFC 9106 Argon2id 0x13; the primitive is the
    // one of `derive` (RFC 9106 vectors in src/kdf.rs). Here: the
    // FEA-08.68 ranges, refused before any memory is allocated, and a fixed
    // answer so a change in the call shows.
    #[test]
    fn import_argon2id_ranges() {
        let pw = secret(b"demo-pass");
        let salt = [2u8; 32];
        for (t, m, p) in [
            (0, 1, 1),
            (101, 1, 1),
            (1, 0, 1),
            (1, 1_025, 1),
            (1, 2_048, 1),
            (1, 1, 0),
            (1, 1, 17),
            (1, u64::MAX, 1),
        ] {
            let started = std::time::Instant::now();
            assert_eq!(
                import_argon2id(&pw, &salt, t, m, p, 32).unwrap_err(),
                Error::KdfCost,
                "{t} {m} {p}"
            );
            assert!(started.elapsed().as_millis() < 50);
        }
        let a = import_argon2id(&pw, &salt, 1, 1, 1, 32).unwrap();
        let b = import_argon2id(&pw, &salt, 1, 1, 1, 32).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, import_argon2id(&pw, &salt, 2, 1, 1, 32).unwrap());
        assert_eq!(
            import_argon2id(&pw, &[1; 4], 1, 1, 1, 32).unwrap_err(),
            Error::KdfSettings
        );
    }
}
