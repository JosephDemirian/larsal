//! E6-S6 benchmark under the zeroing allocator; see `bench/mod.rs`.

mod bench;

#[global_allocator]
static ALLOC: larsal_platform::memory::Zeroing<std::alloc::System> =
    larsal_platform::memory::Zeroing(std::alloc::System);

#[test]
#[ignore = "benchmark, run on demand (bench/mod.rs)"]
fn open_and_save_big_vault_zeroing() {
    bench::run("zeroing");
}
