//! E6-S6 benchmark under the system allocator alone; see `bench/mod.rs`.

mod bench;

#[test]
#[ignore = "benchmark, run on demand (bench/mod.rs)"]
fn open_and_save_big_vault_system() {
    bench::run("system");
}
