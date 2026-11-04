//! Key derivation (story E2-S5, spec CRY-02): Argon2d, Argon2id and AES-KDF,
//! the setting ranges and cost ceilings checked before any work, and the
//! benchmark that turns a target unlock time into settings. Story E4-S13
//! adds the derivations of encrypted import files (FEA-08, LD-142):
//! [`pbkdf2`], [`hkdf_expand_sha256`] and [`import_argon2id`], each with the
//! cost ranges of FEA-08.68 checked before any work.
//!
//! The flow for every caller:
//! 1. [`assess`] checks the settings (ranges of CRY-02.7 to CRY-02.13 and
//!    FMT-03.11 to FMT-03.17, m ≥ 8 × p) and their cost (CRY-02.14). It runs
//!    no KDF on the key and allocates no Argon2 memory for it.
//! 2. If it returns [`Verdict::Ask`], the user sees the [`CostReport`]. When
//!    the user approves, call [`assess`] again with that report as the
//!    approval; it clears the settings only if they still match it.
//! 3. [`derive`] needs the [`Cleared`] value that only [`assess`] makes, so no
//!    KDF can run without step 1, and it runs with exactly the settings checked.
//!
//! Guarantees: the composite key, the transformed key, the Argon2 memory and
//! the AES-KDF blocks live only in wiped memory ([`SecretBytes`], `Zeroizing`,
//! the crates' `zeroize` features). No secret reaches an error value.
//! Limit: a few stack temporaries inside the argon2 crate (the 1 KiB
//! first-block hash, and one copy of the 32-byte transformed key) cannot be
//! wiped by our types, and blake2's own `zeroize` feature stays off (blake2
//! is not a dependency of ours, LD-69). After [`derive`] returns, 256 KiB of
//! stack below it is zeroed (best effort), which covers all of them in
//! release and debug builds (E2-S7 stack probe).
//! Computation is single-threaded; the result does not depend on it (CRY-02.2),
//! and the time estimate counts one thread (spec/decisions.md LD-38).

use crate::Error;
use crate::secret::{SecretBytes, scrubbed, scrubbed_deep};
use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use core::time::Duration;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Instant;
use zeroize::Zeroizing;

/// AES-KDF id Larsal writes (the old id), as stored (CRY-02, KDF ids table).
pub const AES_KDF_ID: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
/// AES-KDF id other writers use: read as the same algorithm, never written.
pub const AES_KDF_NEW_ID: [u8; 16] = [
    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38,
];
/// Argon2d id, as stored.
pub const ARGON2D_ID: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
/// Argon2id id, as stored.
pub const ARGON2ID_ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

/// Highest I and R (FMT-03.12, FMT-03.16) and highest benchmark result (CRY-02.28).
const MAX_COUNT: u64 = 2_147_483_646;
/// Highest P (FMT-03.12).
const MAX_LANES: u64 = 16_777_215;
/// Lowest and highest m in KiB (FMT-03.12, FMT-03.13).
const MIN_MEMORY_KIB: u64 = 8;
const MAX_MEMORY_KIB: u64 = 4_294_967_295;
/// Argon2 salt length (FMT-03.12) and AES-KDF seed length (FMT-03.16, LD-14).
const MIN_SALT: usize = 8;
const MAX_SALT: usize = 32;
const SEED_LEN: usize = 32;
/// Benchmark (CRY-02.28): target range, and the shortest run it trusts.
const TARGET_MS: core::ops::RangeInclusive<u64> = 100..=5_000;
const MIN_RUN: Duration = Duration::from_millis(50);
/// First AES-KDF count of the measuring loop (CRY-02.14, CRY-02.28).
const AES_START: u64 = 100_000;
/// Composite key and transformed key length (CRY-02.4).
const KEY_LEN: usize = 32;
/// Fastest believable speed records, about 16 times what this Mac measured
/// (Argon2id 64 MiB: about 2,700 KiB-iterations per ms; AES-KDF: about
/// 130,000 rounds per ms). A faster record is damaged settings (RT-4).
// ponytail: fixed ceilings; on a Mac 16 times faster every record is just
// measured again, so raise them then.
const MAX_ARGON2_KIB_PER_MS: u128 = 45_000;
const MAX_AES_ROUNDS_PER_MS: u128 = 2_000_000;

/// A monotonic time source for [`benchmark`]: elapsed time since some fixed
/// start. Pass the thread's CPU time (from larsal-platform) so other work on
/// the Mac cannot make the tuned KDF weaker (LD-72). A wall clock works but
/// picks about half the iterations on a busy Mac.
pub type Clock = fn() -> Duration;

/// Wall-clock time since the first call, from the monotonic `Instant`. Only
/// for the calibration: [`benchmark`] needs the caller's CPU-time clock.
fn wall_clock() -> Duration {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed()
}

/// The Argon2 type (RFC 9106 section 3.1): data-dependent (`D`) or hybrid (`Id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    /// Argon2d.
    D,
    /// Argon2id.
    Id,
}

/// KDF settings as stored in the file, every number at its full stored width
/// (FMT-03.18), so nothing is cut down before the range check. Salt and seed
/// are public header values, not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    /// AES-KDF (CRY-02.1), for both AES-KDF ids.
    AesKdf {
        /// Rounds R: 1 to 2,147,483,646.
        rounds: u64,
        /// Seed S, the AES-256 key: exactly 32 bytes.
        seed: Vec<u8>,
    },
    /// Argon2d or Argon2id (CRY-02.2).
    Argon2 {
        /// Which Argon2 type.
        kind: Argon2Type,
        /// Version V: 0x10 or 0x13 (CRY-02.3).
        version: u64,
        /// Iterations I: 1 to 2,147,483,646.
        iterations: u64,
        /// Memory m = floor(M / 1024) KiB: 8 to 2^32 - 1, and at least 8 × lanes.
        memory_kib: u64,
        /// Lanes P: 1 to 16,777,215.
        lanes: u64,
        /// Salt S: 8 to 32 bytes, used at its stored length.
        salt: Vec<u8>,
    },
}

impl KdfParams {
    /// The id Larsal writes for these settings: the old id for AES-KDF (CRY-02.19).
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        match self {
            Self::AesKdf { .. } => AES_KDF_ID,
            Self::Argon2 {
                kind: Argon2Type::D,
                ..
            } => ARGON2D_ID,
            Self::Argon2 {
                kind: Argon2Type::Id,
                ..
            } => ARGON2ID_ID,
        }
    }

    /// Same settings with iterations (Argon2) or rounds (AES-KDF) set to `count`.
    fn with_count(&self, count: u64) -> Self {
        let mut p = self.clone();
        match &mut p {
            Self::AesKdf { rounds, .. } => *rounds = count,
            Self::Argon2 { iterations, .. } => *iterations = count,
        }
        p
    }
}

/// What [`assess`] needs to know about this Mac (CRY-02.14). The caller fills
/// it in; tests fix every field so each Mac gives the same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// Physical memory in bytes.
    pub physical_memory: u64,
    /// Number of logical processors (0 counts as 1).
    pub logical_processors: u64,
    /// Last measured Argon2 run, from Larsal's settings on this Mac.
    pub argon2_record: Option<SpeedRecord>,
    /// Last measured AES-KDF run, from Larsal's settings on this Mac.
    pub aes_record: Option<SpeedRecord>,
}

/// The cost ceilings of CRY-02.14. The values live in larsal-format's limits
/// (proposed in CRY-02.14, accepted in LD-22: 1,000,000,000 iterations,
/// 1,048,576 KiB, 128 lanes, 10,000 ms); the caller passes them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceilings {
    /// Argon2 iterations above this are refused.
    pub refuse_iterations: u64,
    /// Argon2 memory in KiB above this asks the user.
    pub ask_memory_kib: u64,
    /// Argon2 lanes above this ask the user.
    pub ask_lanes: u64,
    /// An estimated time in milliseconds above this asks the user.
    pub ask_ms: u64,
}

/// One measured KDF run: the speed record of CRY-02.14. Holds no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedRecord {
    /// Iterations (Argon2) or rounds (AES-KDF) of the run.
    pub count: u64,
    /// Argon2 memory in KiB; 0 for AES-KDF.
    pub memory_kib: u64,
    /// Argon2 lanes; 1 for AES-KDF.
    pub lanes: u64,
    /// How long the run took, in whole milliseconds, rounded up.
    pub ms: u64,
}

/// The cost of settings that need the user's approval (CRY-02.14). Holds no
/// secret. Every report is approvable: refusals are [`Error::KdfCost`].
/// Only [`assess`] makes one and its fields are read-only, so an approval is
/// always a report that was produced for these settings (RT-6, F-030); the
/// caller keeps it one-shot.
///
/// ```compile_fail,E0616
/// # use larsal_crypto::kdf::CostReport;
/// fn forge(mut r: CostReport) -> CostReport { r.work = 1; r }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostReport {
    kdf_id: [u8; 16],
    memory_bytes: u64,
    work: u64,
    lanes: u64,
    estimated_ms: u64,
    over_memory: bool,
    over_lanes: bool,
    over_time: bool,
}

impl CostReport {
    /// The KDF id ([`KdfParams::id`]).
    #[must_use]
    pub fn kdf_id(&self) -> [u8; 16] {
        self.kdf_id
    }
    /// Argon2 memory m × 1024 in bytes; 0 for AES-KDF.
    #[must_use]
    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }
    /// Iterations I (Argon2) or rounds R (AES-KDF).
    #[must_use]
    pub fn work(&self) -> u64 {
        self.work
    }
    /// Lanes P; 1 for AES-KDF.
    #[must_use]
    pub fn lanes(&self) -> u64 {
        self.lanes
    }
    /// Estimated time from the speed record, whole milliseconds rounded up
    /// (`u64::MAX` when it does not fit).
    #[must_use]
    pub fn estimated_ms(&self) -> u64 {
        self.estimated_ms
    }
    /// Memory above [`Ceilings::ask_memory_kib`].
    #[must_use]
    pub fn over_memory(&self) -> bool {
        self.over_memory
    }
    /// Lanes above [`Ceilings::ask_lanes`].
    #[must_use]
    pub fn over_lanes(&self) -> bool {
        self.over_lanes
    }
    /// Estimated time above [`Ceilings::ask_ms`].
    #[must_use]
    pub fn over_time(&self) -> bool {
        self.over_time
    }
}

impl SpeedRecord {
    /// A real run: every field in range, and no faster than a Mac can be
    /// (RT-4). Anything else is damaged settings and is measured again.
    fn is_sane(&self, argon2: bool) -> bool {
        let fields = (1..=MAX_COUNT).contains(&self.count)
            && (1..=MAX_LANES).contains(&self.lanes)
            && self.ms > 0;
        let (work, max_per_ms) = if argon2 {
            if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
                return false;
            }
            (
                u128::from(self.count).checked_mul(u128::from(self.memory_kib)),
                MAX_ARGON2_KIB_PER_MS,
            )
        } else {
            (Some(u128::from(self.count)), MAX_AES_ROUNDS_PER_MS)
        };
        let limit = u128::from(self.ms).checked_mul(max_per_ms);
        fields && matches!((work, limit), (Some(w), Some(l)) if w <= l)
    }
}

impl CostReport {
    /// An approval binds the KDF id, memory, I or R, and P (CRY-02.14).
    fn same_settings(&self, other: &Self) -> bool {
        (self.kdf_id, self.memory_bytes, self.work, self.lanes)
            == (other.kdf_id, other.memory_bytes, other.work, other.lanes)
    }
}

/// Settings that passed [`assess`]. Only [`assess`] makes one, and it keeps
/// the very settings it checked, so [`derive`] cannot run anything else.
#[derive(Debug)]
pub struct Cleared<'a>(&'a KdfParams);

/// The answer of [`assess`] when the settings are in range and not refused.
#[derive(Debug)]
pub enum Verdict<'a> {
    /// Below every ceiling, or approved: pass it to [`derive`].
    Run(Cleared<'a>),
    /// Over an ask threshold: show the report and ask the user first.
    Ask(CostReport),
}

/// Checks KDF settings and their cost before any key derivation.
///
/// Guarantees, in this order (CRY-02.5 to CRY-02.14):
/// - settings out of range, or m < 8 × p: [`Error::KdfSettings`];
/// - Argon2 memory above `host.physical_memory`, or I above
///   `ceilings.refuse_iterations`: [`Error::KdfCost`], which no approval
///   can lift;
/// - memory, lanes or estimated time above their ask ceiling:
///   [`Verdict::Ask`] with the cost, unless `approval` is an earlier report
///   with the same KDF id, memory, I or R, and P;
/// - otherwise [`Verdict::Run`].
///
/// It runs no KDF on any key and returns at once, with one exception: when
/// `host` has no usable speed record for this KDF family (none, or one with a
/// zero field), it first runs the short calibration of CRY-02.14 (dummy zero
/// inputs, at most 64 MiB, no secret) and stores the record in `host`, for the
/// caller to save. The time estimate counts one thread (LD-38).
///
/// # Errors
/// [`Error::KdfSettings`], [`Error::KdfCost`], as above.
pub fn assess<'a>(
    params: &'a KdfParams,
    host: &mut Host,
    ceilings: &Ceilings,
    approval: Option<&CostReport>,
) -> Result<Verdict<'a>, Error> {
    check_ranges(params)?;
    let n = host.logical_processors.max(1);
    let (memory_kib, work, lanes, slot) = match params {
        KdfParams::AesKdf { rounds, .. } => (0, *rounds, 1, &mut host.aes_record),
        KdfParams::Argon2 {
            iterations,
            memory_kib,
            lanes,
            ..
        } => {
            let over_ram = memory_kib
                .checked_mul(1024)
                .is_none_or(|bytes| bytes > host.physical_memory);
            if over_ram || *iterations > ceilings.refuse_iterations {
                return Err(Error::KdfCost);
            }
            (*memory_kib, *iterations, *lanes, &mut host.argon2_record)
        }
    };
    // A record with a zero field is damaged settings: measure again.
    let argon2 = matches!(params, KdfParams::Argon2 { .. });
    let record = match slot {
        Some(record) if record.is_sane(argon2) => *record,
        _ => *slot.insert(calibrate(params, n)?),
    };
    let estimated_ms = estimate_ms(params, &record);
    let report = CostReport {
        kdf_id: params.id(),
        memory_bytes: memory_kib.saturating_mul(1024),
        work,
        lanes,
        estimated_ms,
        over_memory: memory_kib > ceilings.ask_memory_kib,
        over_lanes: lanes > ceilings.ask_lanes,
        over_time: estimated_ms > ceilings.ask_ms,
    };
    let ask = report.over_memory || report.over_lanes || report.over_time;
    if !ask || approval.is_some_and(|a| a.same_settings(&report)) {
        Ok(Verdict::Run(Cleared(params)))
    } else {
        Ok(Verdict::Ask(report))
    }
}

/// Turns the 32-byte composite key into the 32-byte transformed key with the
/// cleared settings (CRY-02.1 to CRY-02.4). No secret key and no associated
/// data go into Argon2 (CRY-02.17).
///
/// Guarantees: the result is exactly 32 bytes in a [`SecretBytes`]; the Argon2
/// memory and the AES-KDF blocks are wiped before it returns, on success and
/// on failure; no partial key is returned.
///
/// # Errors
/// [`Error::KeyLength`] if `composite` is not 32 bytes; [`Error::KdfSettings`]
/// if the KDF crate refuses the settings or the memory cannot be allocated
/// (CRY-02.16).
pub fn derive(composite: &SecretBytes, cleared: &Cleared<'_>) -> Result<SecretBytes, Error> {
    scrubbed_deep(|| run_kdf(composite.expose(), cleared.0))
}

/// What [`benchmark`] found: settings to use and the run to save as the speed
/// record (CRY-02.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Benchmark {
    /// The template with iterations (Argon2) or rounds (AES-KDF) set.
    pub params: KdfParams,
    /// The measured run: the fastest of three at the final count (LD-40).
    pub record: SpeedRecord,
}

/// Finds the iterations (Argon2) or rounds (AES-KDF) that make the KDF take
/// about `target_ms` on this Mac (CRY-02.28, LD-19).
///
/// Guarantees: measures with `clock`, starting at 1 iteration or
/// 100,000 rounds and doubling until one run takes at least 50 ms, then sets
/// the count to ceiling(count × 1.1 × target / time), clamped to 1 to
/// 2,147,483,646; a zero time or an overflow gives the maximum, never a
/// smaller value. The time is the fastest of three runs at that count, so a
/// busy Mac does not make the result weaker. Memory, lanes, version, type,
/// salt and seed are kept as in `template`; its own count is ignored. Uses a
/// zero password and the template's salt or seed; no secret.
/// Argon2 memory above `host.physical_memory` is refused before any work.
///
/// # Errors
/// [`Error::KdfSettings`] if `target_ms` is outside 100 to 5,000, the
/// template is out of range, or the KDF crate refuses it;
/// [`Error::KdfCost`] if the template's memory is above this Mac's (RT-5).
pub fn benchmark(
    template: &KdfParams,
    target_ms: u64,
    host: &Host,
    clock: Clock,
) -> Result<Benchmark, Error> {
    if !TARGET_MS.contains(&target_ms) {
        return Err(Error::KdfSettings);
    }
    check_ranges(&template.with_count(1))?;
    if let KdfParams::Argon2 { memory_kib, .. } = template
        && memory_kib
            .checked_mul(1024)
            .is_none_or(|bytes| bytes > host.physical_memory)
    {
        return Err(Error::KdfCost);
    }
    let (record, elapsed) = measure(template, clock)?;
    Ok(Benchmark {
        params: template.with_count(fit(record.count, elapsed, target_ms)),
        record,
    })
}

/// The range checks of CRY-02.5 to CRY-02.13 (FMT-03.12, FMT-03.14, FMT-03.16).
fn check_ranges(params: &KdfParams) -> Result<(), Error> {
    let ok = match params {
        KdfParams::AesKdf { rounds, seed } => {
            (1..=MAX_COUNT).contains(rounds) && seed.len() == SEED_LEN
        }
        KdfParams::Argon2 {
            version,
            iterations,
            memory_kib,
            lanes,
            salt,
            ..
        } => {
            matches!(version, 0x10 | 0x13)
                && (1..=MAX_COUNT).contains(iterations)
                && (1..=MAX_LANES).contains(lanes)
                && (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(memory_kib)
                && lanes.checked_mul(8).is_some_and(|min| *memory_kib >= min)
                && (MIN_SALT..=MAX_SALT).contains(&salt.len())
        }
    };
    if ok { Ok(()) } else { Err(Error::KdfSettings) }
}

/// Estimated time of CRY-02.14 on one thread (LD-38), rounded up;
/// `u64::MAX` on overflow or a zero denominator.
fn estimate_ms(params: &KdfParams, record: &SpeedRecord) -> u64 {
    let wide = u128::from;
    let (num, den) = match params {
        // I × m × rec_ms / (rec_I × rec_m): lanes run one after another.
        KdfParams::Argon2 {
            iterations,
            memory_kib,
            ..
        } => (
            wide(*iterations)
                .checked_mul(wide(*memory_kib))
                .and_then(|v| v.checked_mul(wide(record.ms))),
            wide(record.count).checked_mul(wide(record.memory_kib)),
        ),
        // R × rec_ms / rec_R
        KdfParams::AesKdf { rounds, .. } => (
            wide(*rounds).checked_mul(wide(record.ms)),
            Some(wide(record.count)),
        ),
    };
    match (num, den.filter(|d| *d > 0)) {
        (Some(num), Some(den)) => u64::try_from(num.div_ceil(den)).unwrap_or(u64::MAX),
        _ => u64::MAX,
    }
}

/// The calibration of CRY-02.14: the measuring loop on dummy inputs.
fn calibrate(params: &KdfParams, n: u64) -> Result<SpeedRecord, Error> {
    // Wall time: a busy Mac only makes the estimate longer, so it asks more.
    measure(&calibration_params(params, n), wall_clock).map(|(record, _)| record)
}

/// The dummy settings the calibration measures (CRY-02.14).
fn calibration_params(params: &KdfParams, n: u64) -> KdfParams {
    match params {
        KdfParams::AesKdf { .. } => KdfParams::AesKdf {
            rounds: AES_START,
            seed: vec![0; SEED_LEN],
        },
        KdfParams::Argon2 { kind, .. } => KdfParams::Argon2 {
            kind: *kind,
            version: 0x13,
            iterations: 1,
            memory_kib: 65_536,
            lanes: n.clamp(1, 4),
            salt: vec![0; MAX_SALT],
        },
    }
}

/// The measuring loop of CRY-02.28 with the real KDF and `clock`.
fn measure(template: &KdfParams, clock: Clock) -> Result<(SpeedRecord, Duration), Error> {
    let start = match template {
        KdfParams::AesKdf { .. } => AES_START,
        KdfParams::Argon2 { .. } => 1,
    };
    check_ranges(&template.with_count(start))?;
    let run = |count: u64| -> Result<Duration, Error> {
        let params = template.with_count(count);
        let start = clock();
        run_kdf(&[0; KEY_LEN], &params)?;
        Ok(clock().saturating_sub(start))
    };
    // Warm-up: the first run in a process pays for cold memory and would end
    // the doubling too early (Verify S7-1).
    run(start)?;
    let (count, elapsed) = time_runs(start, run)?;
    let (memory_kib, lanes) = match template {
        KdfParams::AesKdf { .. } => (0, 1),
        KdfParams::Argon2 {
            memory_kib, lanes, ..
        } => (*memory_kib, *lanes),
    };
    let record = SpeedRecord {
        count,
        memory_kib,
        lanes,
        ms: whole_ms(elapsed),
    };
    Ok((record, elapsed))
}

/// Whole milliseconds, rounded up, so a speed record never looks faster.
fn whole_ms(d: Duration) -> u64 {
    u64::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

/// The fastest of `first` and two more runs at `count` (LD-40): a run slowed
/// by other work would give too few iterations, a weaker KDF.
fn fastest_of_three(
    count: u64,
    first: Duration,
    mut run: impl FnMut(u64) -> Result<Duration, Error>,
) -> Result<Duration, Error> {
    let mut best = first;
    for _ in 0..2 {
        best = best.min(run(count)?);
    }
    Ok(best)
}

/// The CRY-02.28 measuring loop, then the fastest of three at its count.
fn time_runs(
    start: u64,
    mut run: impl FnMut(u64) -> Result<Duration, Error>,
) -> Result<(u64, Duration), Error> {
    let (count, first) = double_until(start, &mut run)?;
    Ok((count, fastest_of_three(count, first, run)?))
}

/// Runs `run(count)` from `start`, doubling the count until one run takes at
/// least 50 ms or the count reaches the maximum. Returns the last run.
fn double_until(
    start: u64,
    mut run: impl FnMut(u64) -> Result<Duration, Error>,
) -> Result<(u64, Duration), Error> {
    let mut count = start;
    loop {
        let elapsed = run(count)?;
        if elapsed >= MIN_RUN || count >= MAX_COUNT {
            return Ok((count, elapsed));
        }
        count = count.saturating_mul(2).min(MAX_COUNT);
    }
}

/// ceiling(count × 1.1 × target / elapsed), exact in integers (× 11 / 10),
/// clamped to 1 to [`MAX_COUNT`]; zero time or overflow gives the maximum.
fn fit(count: u64, elapsed: Duration, target_ms: u64) -> u64 {
    let num = u128::from(count)
        .checked_mul(11)
        .and_then(|v| v.checked_mul(u128::from(target_ms)))
        .and_then(|v| v.checked_mul(1_000_000));
    let den = elapsed.as_nanos().checked_mul(10).filter(|d| *d > 0);
    match (num, den) {
        (Some(num), Some(den)) => u64::try_from(num.div_ceil(den))
            .unwrap_or(MAX_COUNT)
            .clamp(1, MAX_COUNT),
        _ => MAX_COUNT,
    }
}

/// The KDF itself, with no cost check: [`derive`] reaches it only through
/// [`Cleared`]; the benchmark and the calibration use dummy inputs.
fn run_kdf(composite: &[u8], params: &KdfParams) -> Result<SecretBytes, Error> {
    if composite.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    let mut out = SecretBytes::zeroed(KEY_LEN);
    match params {
        KdfParams::AesKdf { rounds, seed } => {
            let mut blocks = SecretBytes::new(composite.to_vec());
            aes_rounds(seed, *rounds, blocks.expose_mut())?;
            let out: &mut sha2::digest::Output<Sha256> =
                out.expose_mut().try_into().map_err(|_| Error::KeyLength)?;
            Sha256::new()
                .chain_update(blocks.expose())
                .finalize_into(out);
        }
        KdfParams::Argon2 {
            kind,
            version,
            iterations,
            memory_kib,
            lanes,
            salt,
        } => {
            let settings = Argon2Settings {
                kind: *kind,
                version: *version,
                iterations: *iterations,
                memory_kib: *memory_kib,
                lanes: *lanes,
            };
            argon2_into(&settings, composite, salt, &[], &[], out.expose_mut())?;
        }
    }
    Ok(out)
}

/// AES-256 ECB on each 16-byte block of `buf`, `rounds` times, key `seed` (CRY-02.1).
pub(crate) fn aes_rounds(seed: &[u8], rounds: u64, buf: &mut [u8]) -> Result<(), Error> {
    // The key schedule is wiped on drop (aes "zeroize" feature).
    let cipher = Aes256::new_from_slice(seed).map_err(|_| Error::KdfSettings)?;
    let (blocks, _) = aes::Block::slice_as_chunks_mut(buf);
    for _ in 0..rounds {
        cipher.encrypt_blocks(blocks);
    }
    Ok(())
}

/// Argon2 settings without the salt (kept apart so tests can add a secret).
pub(crate) struct Argon2Settings {
    pub(crate) kind: Argon2Type,
    pub(crate) version: u64,
    pub(crate) iterations: u64,
    pub(crate) memory_kib: u64,
    pub(crate) lanes: u64,
}

/// RFC 9106 Argon2 into `out`, in memory that is wiped before it returns.
/// `secret` and `ad` are empty except in the RFC 9106 known-answer tests
/// and the start self-test (APP-11.10).
pub(crate) fn argon2_into(
    s: &Argon2Settings,
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let small = |v: u64| u32::try_from(v).map_err(|_| Error::KdfSettings);
    let algorithm = match s.kind {
        Argon2Type::D => Algorithm::Argon2d,
        Argon2Type::Id => Algorithm::Argon2id,
    };
    let version = Version::try_from(small(s.version)?).map_err(|_| Error::KdfSettings)?;
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(small(s.memory_kib)?)
        .t_cost(small(s.iterations)?)
        .p_cost(small(s.lanes)?)
        .output_len(out.len());
    if !ad.is_empty() {
        builder.data(AssociatedData::new(ad).map_err(|_| Error::KdfSettings)?);
    }
    let params = builder.build().map_err(|_| Error::KdfSettings)?;
    let mut memory = work_memory(params.block_count())?;
    let ctx = if secret.is_empty() {
        Argon2::new(algorithm, version, params)
    } else {
        Argon2::new_with_secret(secret, algorithm, version, params)
            .map_err(|_| Error::KdfSettings)?
    };
    hash_into(&ctx, pwd, salt, out, &mut memory)
}

/// The only call into the argon2 crate. It takes the memory as `Zeroizing`
/// so a plain, unwiped buffer cannot be passed (LD-39).
fn hash_into(
    ctx: &Argon2<'_>,
    pwd: &[u8],
    salt: &[u8],
    out: &mut [u8],
    memory: &mut Zeroizing<Vec<Block>>,
) -> Result<(), Error> {
    ctx.hash_password_into_with_memory(pwd, salt, out, memory.as_mut_slice())
        .map_err(|_| Error::KdfSettings)
}

/// Argon2 working memory, wiped on drop (LD-39). Our own instead of the
/// crate's, which frees its blocks unwiped.
fn work_memory(blocks: usize) -> Result<Zeroizing<Vec<Block>>, Error> {
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| Error::KdfSettings)?;
    memory.resize(blocks, Block::new());
    Ok(memory)
}

// -- Import key derivation (story E4-S13; FEA-08.35, FEA-08.49, FEA-08.50,
// FEA-08.68; LD-142) ------------------------------------------------------

/// Highest PBKDF2 iteration count an import file may ask for (FEA-08.68).
pub const IMPORT_PBKDF2_MAX_ITERATIONS: u64 = 10_000_000;
/// Highest Argon2id iterations an import file may ask for (FEA-08.68).
pub const IMPORT_ARGON2_MAX_ITERATIONS: u64 = 100;
/// Highest Argon2id memory in MiB an import file may ask for (FEA-08.68).
pub const IMPORT_ARGON2_MAX_MEMORY_MIB: u64 = 1_024;
/// Highest Argon2id lane count an import file may ask for (FEA-08.68).
pub const IMPORT_ARGON2_MAX_LANES: u64 = 16;
/// Longest key the import derivations give, in bytes: far above the 64
/// any reader needs, so a caller's mistake cannot allocate much.
pub const IMPORT_MAX_KEY: usize = 1_024;
/// HKDF-Expand with SHA-256 gives at most 255 blocks of 32 bytes (RFC 5869
/// section 2.3).
const HKDF_SHA256_MAX: usize = 255 * 32;

/// The HMAC hash PBKDF2 runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    /// HMAC-SHA-256 (the password-protected JSON export, FEA-08.49).
    Sha256,
    /// HMAC-SHA-512 (OPVault, FEA-08.35).
    Sha512,
}

/// PBKDF2 (RFC 8018 section 5.2) with HMAC-`prf`, giving `len` bytes.
///
/// Guarantees: `iterations` outside 1 to 10,000,000 is refused before any
/// work (FEA-08.68); the result is exactly `len` bytes in a
/// [`SecretBytes`]; the HMAC states are wiped (the hmac crate's `zeroize`
/// feature) and 32 KiB of stack below the call is zeroed after it.
///
/// # Errors
/// [`Error::KdfCost`] for an iteration count out of range;
/// [`Error::KeyLength`] for `len` 0 or above [`IMPORT_MAX_KEY`].
pub fn pbkdf2(
    prf: Prf,
    password: &SecretBytes,
    salt: &[u8],
    iterations: u64,
    len: usize,
) -> Result<SecretBytes, Error> {
    if !(1..=IMPORT_PBKDF2_MAX_ITERATIONS).contains(&iterations) {
        return Err(Error::KdfCost);
    }
    if !(1..=IMPORT_MAX_KEY).contains(&len) {
        return Err(Error::KeyLength);
    }
    let rounds = u32::try_from(iterations).map_err(|_| Error::KdfCost)?;
    let mut out = SecretBytes::zeroed(len);
    let (pw, key) = (password.expose(), out.expose_mut());
    scrubbed(|| match prf {
        Prf::Sha256 => pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(pw, salt, rounds, key),
        Prf::Sha512 => pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(pw, salt, rounds, key),
    })
    .map_err(|_| Error::KeyLength)?;
    Ok(out)
}

/// HKDF-Expand (RFC 5869 section 2.3) with HMAC-SHA-256: `len` bytes from
/// the pseudorandom key `prk` and `info`. No extract step: FEA-08.50 uses
/// the derived key as the pseudorandom key.
///
/// Guarantees: the result is exactly `len` bytes in a [`SecretBytes`]; the
/// HMAC state is wiped and 32 KiB of stack below the call is zeroed after it.
///
/// # Errors
/// [`Error::KeyLength`] for `prk` shorter than 32 bytes (RFC 5869: at
/// least the hash length), or `len` 0 or above 8,160 bytes.
pub fn hkdf_expand_sha256(
    prk: &SecretBytes,
    info: &[u8],
    len: usize,
) -> Result<SecretBytes, Error> {
    if !(1..=HKDF_SHA256_MAX).contains(&len) {
        return Err(Error::KeyLength);
    }
    let mut out = SecretBytes::zeroed(len);
    let okm = out.expose_mut();
    scrubbed(|| {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(prk.expose()).map_err(|_| Error::KeyLength)?;
        hk.expand(info, okm).map_err(|_| Error::KeyLength)
    })?;
    Ok(out)
}

/// Argon2id version 0x13 (RFC 9106) for an import file (FEA-08.49):
/// `iterations`, `memory_mib` MiB and `lanes`, no secret key and no
/// associated data, `len` bytes out.
///
/// Guarantees: iterations outside 1 to 100, memory outside 1 to 1,024 MiB
/// or lanes outside 1 to 16 are refused before any memory is allocated
/// (FEA-08.68); the Argon2 memory is wiped before it returns, on success
/// and on failure; 256 KiB of stack below the call is zeroed after it.
///
/// # Errors
/// [`Error::KdfCost`] for settings out of range; [`Error::KeyLength`] for
/// `len` below 4 or above [`IMPORT_MAX_KEY`]; [`Error::KdfSettings`] when
/// the argon2 crate refuses the rest (a salt under 8 bytes) or the memory
/// cannot be allocated.
pub fn import_argon2id(
    password: &SecretBytes,
    salt: &[u8],
    iterations: u64,
    memory_mib: u64,
    lanes: u64,
    len: usize,
) -> Result<SecretBytes, Error> {
    let in_range = (1..=IMPORT_ARGON2_MAX_ITERATIONS).contains(&iterations)
        && (1..=IMPORT_ARGON2_MAX_MEMORY_MIB).contains(&memory_mib)
        && (1..=IMPORT_ARGON2_MAX_LANES).contains(&lanes);
    if !in_range {
        return Err(Error::KdfCost);
    }
    if !(4..=IMPORT_MAX_KEY).contains(&len) {
        return Err(Error::KeyLength);
    }
    let settings = Argon2Settings {
        kind: Argon2Type::Id,
        version: 0x13,
        iterations,
        memory_kib: memory_mib.checked_mul(1024).ok_or(Error::KdfCost)?,
        lanes,
    };
    let mut out = SecretBytes::zeroed(len);
    let tag = out.expose_mut();
    scrubbed_deep(|| argon2_into(&settings, password.expose(), salt, &[], &[], tag))?;
    Ok(out)
}

// Compile-time proof that the HMAC states PBKDF2 and HKDF clone and hold
// are wiped on drop: an HMAC state is two hash cores of these types (hmac
// 0.13 `HmacCore`), and turning off sha2's `zeroize` feature breaks the
// build here.
const _: () = {
    use hmac::digest::block_api::EagerHash;
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<<Sha256 as EagerHash>::Core>();
    wiped_on_drop::<<sha2::Sha512 as EagerHash>::Core>();
};

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9106 section 5 inputs: m = 32 KiB, t = 3, p = 4, password 32 × 01,
    /// salt 16 × 02, secret 8 × 03, associated data 12 × 04, tag 32 bytes.
    fn rfc9106(kind: Argon2Type, version: u64) -> Vec<u8> {
        let s = Argon2Settings {
            kind,
            version,
            iterations: 3,
            memory_kib: 32,
            lanes: 4,
        };
        let mut out = [0u8; 32];
        argon2_into(&s, &[1; 32], &[2; 16], &[3; 8], &[4; 12], &mut out).unwrap();
        out.to_vec()
    }

    #[test]
    fn rfc9106_5_1_argon2d() {
        // RFC 9106 section 5.1 (also CRY-02 T5).
        let tag = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";
        assert_eq!(rfc9106(Argon2Type::D, 0x13), hex(tag));
    }

    #[test]
    fn rfc9106_5_3_argon2id() {
        // RFC 9106 section 5.3 (also CRY-02 T6).
        let tag = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
        assert_eq!(rfc9106(Argon2Type::Id, 0x13), hex(tag));
    }

    #[test]
    fn version_0x10_with_secret_known_answers() {
        // Same inputs as RFC 9106 section 5, version 0x10: the Argon2 authors'
        // reference test vectors, as shipped in the argon2 0.6.0 crate's tests/kat.rs.
        let d = "96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b";
        let id = "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0";
        assert_eq!(rfc9106(Argon2Type::D, 0x10), hex(d));
        assert_eq!(rfc9106(Argon2Type::Id, 0x10), hex(id));
    }

    // CRY-02 T1, T2: S and the composite are the NIST SP 800-38A F.1.5 key
    // and first two plaintext blocks.
    const NIST_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const NIST_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

    #[test]
    fn aes_blocks_after_one_and_two_rounds() {
        let mut buf = hex(NIST_PLAIN);
        aes_rounds(&hex(NIST_KEY), 1, &mut buf).unwrap();
        // NIST SP 800-38A F.1.5 ECB-AES256 ciphertext blocks 1 and 2 (CRY-02 T1).
        let one = "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870";
        assert_eq!(buf, hex(one));
        aes_rounds(&hex(NIST_KEY), 1, &mut buf).unwrap();
        // CRY-02 T2.
        let two = "ef15ad5895e4025006d28fb13f2afe1b349325871646ba8185cf0c6ba226e699";
        assert_eq!(buf, hex(two));
    }

    #[test]
    fn estimate_matches_t25b() {
        // CRY-02 T25b: records rec_I 10, rec_m 65,536, rec_p 4, 1,000 ms and
        // rec_R 10,000,000, 150 ms; 8 logical processors.
        let argon = SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 4,
            ms: 1_000,
        };
        let aes = SpeedRecord {
            count: 10_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 150,
        };
        let a = |iterations, lanes| KdfParams::Argon2 {
            kind: Argon2Type::Id,
            version: 0x13,
            iterations,
            memory_kib: 65_536,
            lanes,
            salt: vec![0; 32],
        };
        let r = |rounds| KdfParams::AesKdf {
            rounds,
            seed: vec![0; 32],
        };
        // T25b on one thread (LD-38).
        assert_eq!(estimate_ms(&a(20, 1), &argon), 2_000);
        assert_eq!(estimate_ms(&a(30, 1), &argon), 3_000);
        assert_eq!(estimate_ms(&a(40, 4), &argon), 4_000);
        assert_eq!(estimate_ms(&r(500_000_000), &aes), 7_500);
        assert_eq!(estimate_ms(&r(1_000_000_000), &aes), 15_000);
        // Lanes change nothing, in the file or in the record.
        let wide = SpeedRecord { lanes: 16, ..argon };
        assert_eq!(estimate_ms(&a(20, 16), &wide), 2_000);
        // A zero record cannot divide by zero: it counts as too slow.
        let zero = SpeedRecord { count: 0, ..aes };
        assert_eq!(estimate_ms(&r(1), &zero), u64::MAX);
    }

    #[test]
    fn a_record_with_any_zero_field_is_not_used() {
        let good = SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 4,
            ms: 1_000,
        };
        assert!(good.is_sane(true) && good.is_sane(false));
        for bad in [
            SpeedRecord { count: 0, ..good },
            SpeedRecord { lanes: 0, ..good },
            SpeedRecord { ms: 0, ..good },
        ] {
            assert!(!bad.is_sane(true) && !bad.is_sane(false), "{bad:?}");
        }
        // Out of range, or faster than any Mac (RT-4): damaged.
        for bad in [
            SpeedRecord {
                count: MAX_COUNT + 1,
                ..good
            },
            SpeedRecord {
                lanes: MAX_LANES + 1,
                ..good
            },
            SpeedRecord {
                memory_kib: MAX_MEMORY_KIB + 1,
                ..good
            },
            SpeedRecord {
                memory_kib: 7,
                ..good
            },
            // 45,001 KiB-iterations in 1 ms.
            SpeedRecord {
                count: 45_001,
                memory_kib: 1,
                lanes: 1,
                ms: 1,
            },
        ] {
            assert!(!bad.is_sane(true), "{bad:?}");
        }
        let at_limit = SpeedRecord {
            count: 45_000,
            memory_kib: 8,
            lanes: 1,
            ms: 8,
        };
        assert!(at_limit.is_sane(true));
        let fast_aes = SpeedRecord {
            count: 2_000_001,
            memory_kib: 0,
            lanes: 1,
            ms: 1,
        };
        assert!(!fast_aes.is_sane(false));
        assert!(
            SpeedRecord {
                count: 2_000_000,
                ..fast_aes
            }
            .is_sane(false)
        );
        // Memory 0 is normal for AES-KDF, damaged for Argon2.
        let no_memory = SpeedRecord {
            memory_kib: 0,
            ..good
        };
        assert!(no_memory.is_sane(false) && !no_memory.is_sane(true));
    }

    #[test]
    fn benchmark_keeps_the_fastest_of_three_runs() {
        // LD-40, with a scripted clock: first run 80 ms, then 60 and 70 ms.
        let mut script = [60u64, 70].into_iter();
        let mut counts = Vec::new();
        let best = fastest_of_three(44, Duration::from_millis(80), |c| {
            counts.push(c);
            Ok(Duration::from_millis(script.next().unwrap()))
        })
        .unwrap();
        assert_eq!(best, Duration::from_millis(60));
        assert_eq!(counts, [44, 44], "two more runs at the same count");
        // The loop and the pick together: 7 ms per count from 1, so the
        // count is 8 (56 ms), then 50 ms beats it.
        let mut times = [56u64, 50, 70].into_iter();
        let got = time_runs(1, |c| {
            if c < 8 {
                return Ok(Duration::from_millis(c * 7));
            }
            Ok(Duration::from_millis(times.next().unwrap()))
        });
        assert_eq!(got.unwrap(), (8, Duration::from_millis(50)));
        // Rounded up, never down.
        assert_eq!(whole_ms(Duration::from_nanos(1)), 1);
        assert_eq!(whole_ms(Duration::from_millis(50)), 50);
        assert_eq!(whole_ms(Duration::from_nanos(50_000_001)), 51);
    }

    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    #[test]
    fn argon2_memory_is_wiped_on_drop() {
        // Compile-time proof (LD-39).
        wipes(&work_memory(8).unwrap());
    }

    #[test]
    fn calibration_uses_the_card_dummies() {
        // CRY-02.14: I = 1, 64 MiB, min(4, n) lanes, 32-byte zero salt;
        // AES-KDF from 100,000 rounds with a zero seed.
        let argon = |kind| KdfParams::Argon2 {
            kind,
            version: 0x10,
            iterations: 99,
            memory_kib: 8,
            lanes: 1,
            salt: vec![7; 8],
        };
        let dummy = |kind, lanes| KdfParams::Argon2 {
            kind,
            version: 0x13,
            iterations: 1,
            memory_kib: 65_536,
            lanes,
            salt: vec![0; 32],
        };
        assert_eq!(
            calibration_params(&argon(Argon2Type::D), 8),
            dummy(Argon2Type::D, 4)
        );
        assert_eq!(
            calibration_params(&argon(Argon2Type::Id), 2),
            dummy(Argon2Type::Id, 2)
        );
        assert_eq!(
            calibration_params(&argon(Argon2Type::Id), 0),
            dummy(Argon2Type::Id, 1)
        );
        let aes = KdfParams::AesKdf {
            rounds: 5,
            seed: vec![9; 32],
        };
        let want = KdfParams::AesKdf {
            rounds: 100_000,
            seed: vec![0; 32],
        };
        assert_eq!(calibration_params(&aes, 8), want);
    }

    #[test]
    fn fake_clock_at_zero_gives_the_maximum() {
        // CRY-02 T42: a clock that always reports 0 elapsed.
        let mut runs = 0u32;
        let (count, elapsed) = double_until(1, |_| {
            runs += 1;
            Ok(Duration::ZERO)
        })
        .unwrap();
        assert_eq!((count, elapsed), (MAX_COUNT, Duration::ZERO));
        assert!(runs <= 33, "the loop ends once the count is at the maximum");
        assert_eq!(fit(count, elapsed, 1_000), MAX_COUNT);
    }

    #[test]
    fn fake_clock_with_a_huge_result_is_clamped_not_wrapped() {
        // CRY-02 T42: 1 ns per run, so the result overflows the range.
        assert_eq!(fit(MAX_COUNT, Duration::from_nanos(1), 5_000), MAX_COUNT);
        assert_eq!(fit(u64::MAX, Duration::from_nanos(1), 5_000), MAX_COUNT);
    }

    #[test]
    fn fit_follows_the_formula() {
        // ceiling(4 × 1.1 × 1,000 / 250) = 17.6 → 18; slow runs give 1.
        assert_eq!(fit(4, Duration::from_millis(250), 1_000), 18);
        assert_eq!(fit(1, Duration::from_secs(100), 100), 1);
        // The loop stops at the first run of at least 50 ms.
        let (count, _) =
            double_until(1, |c| Ok(Duration::from_millis(c.saturating_mul(7)))).unwrap();
        assert_eq!(count, 8);
    }

    proptest! {
        #[test]
        fn aes_rounds_compose(a in 0u64..40, b in 0u64..40, data in proptest::array::uniform32(any::<u8>())) {
            // R rounds then S rounds equals R + S rounds (CRY-02.1, ECB per block).
            let seed = hex(NIST_KEY);
            let mut split = data.to_vec();
            aes_rounds(&seed, a, &mut split).unwrap();
            aes_rounds(&seed, b, &mut split).unwrap();
            let mut whole = data.to_vec();
            aes_rounds(&seed, a + b, &mut whole).unwrap();
            prop_assert_eq!(split, whole);
        }

        #[test]
        fn fit_stays_in_range_and_meets_the_target(count in 1u64..=MAX_COUNT, nanos in 0u64..10_000_000_000, target in 100u64..=5_000) {
            let result = fit(count, Duration::from_nanos(nanos), target);
            prop_assert!((1..=MAX_COUNT).contains(&result));
            // Unless clamped, result × time ≥ count × 1.1 × target (never weaker).
            if result < MAX_COUNT {
                let lhs = u128::from(result) * u128::from(nanos) * 10;
                let rhs = u128::from(count) * 11 * u128::from(target) * 1_000_000;
                prop_assert!(lhs >= rhs);
            }
        }
    }
}
