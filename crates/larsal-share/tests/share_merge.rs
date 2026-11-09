//! The oracle of the fuzz target `share_merge` on its seeds and on many inputs,
//! so it runs on every lane and not only under the nightly fuzzer.

#[path = "share_merge_oracle/mod.rs"]
mod oracle;

#[test]
fn rt2_the_oracle_holds_on_every_seed() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/corpus/share_merge");
    let mut seen = 0;
    for f in std::fs::read_dir(dir).unwrap().flatten() {
        oracle::check(&std::fs::read(f.path()).unwrap());
        seen += 1;
    }
    assert!(seen >= 14, "the seeds are there: {seen}");
}

/// A fixed stream of inputs, each a run of triples, in the range the target
/// uses. `ponytail:` a plain xorshift, the fuzzer goes further; add more rounds
/// only if a mutant here survives.
#[test]
fn rt2_the_oracle_holds_on_many_inputs() {
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    // More rounds by hand, in place of a run under the nightly fuzzer.
    let rounds = std::env::var("ORACLE_ROUNDS")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(2_000);
    for _ in 0..rounds {
        let len = usize::try_from(next() % 40).unwrap() * 3;
        let data: Vec<u8> = (0..len).map(|_| (next() >> 32) as u8).collect();
        println!("input {data:02x?}");
        oracle::check(&data);
    }
}
