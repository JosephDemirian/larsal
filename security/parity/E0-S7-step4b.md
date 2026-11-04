# E0-S7 step 4b: cuts in the crypto copies (2026-10-31)

Builder, 2026-10-31. Story E0-S7 follow-up (plan/epics.md; LD-259 (1), LD-261 (1)), batch 4b of spec/research/dependencies.md section 8 'Step 4: trims', items 4 and 5: the crypto copies, whole files cut only (AGENTS.md rule 3). Checker next; these are crypto copies, so Checker 2 reviews every one of the 55 copies this step touched. No code line changed in any copy, no `Cargo.toml` changed, no package left the tree, both lockfiles are byte-identical, and the compiled `app`, `libapp_ffi.a` and `libapp_hwkey.rlib` are byte-identical before and after (section 9).

Setup: a private copy of the shared tree (`/tmp/e0s7s4b-builder-copy`, `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots`) and a second one that holds the tree before the step (`/tmp/e0s7s4b-builder-base`); both lockfiles had the SHA-256 of step 4a (`e23c677e…`, `d2758a2f…`) and kept it through every run. The check-vendor mutants ran in a third copy (`/tmp/e0s7s4b-builder-mut`), restored by `rsync -a --delete` before each one. Target folders and new empty cargo homes under `/tmp`, a throwaway `HOME` for the test runs, `SSH_AUTH_SOCK` unset, `CARGO_NET_OFFLINE=true`, every cargo call `--offline --locked` (only the mutants that rewrite a lock on purpose did so, in the mutant copy). `RUSTUP_HOME` was the user's and `RUSTUP_AUTO_INSTALL=0`. Nothing was fetched: the published `.crate` files came from the local cargo cache and were unpacked under `/tmp` only. Each empty cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` at the end. The result went to the shared tree in one step (section 13).

## 1. What was cut

The rule for every file: it may go only when it is in a crypto copy (the research table, dependencies.md section 7, marks the package `yes`, `key` or `support`), it is in one of the kinds that items 4 and 5 name (ring: pregenerated assembly and perlasm for other targets, `tests/`; the others: `tests/`, `benches/`, backends for other architectures or systems), and no build of App on aarch64-apple-darwin or x86_64-apple-darwin compiles or reads it, with every feature any crate or copy turns on (section 2). Only whole files went. No `Cargo.toml`, `build.rs`, license file, README or kept source file changed. Each copy stays a plain directory copy in `vendor/crates-io` with a new `.cargo-checksum.json` and cargo vendor's list beside it as `.cargo-checksum.upstream.json`, and is in `cut_copies` in `scripts/check-vendor.sh`. None needs a `[patch]` path copy, because no file changed.

448 files in 55 copies, 112 emptied folders removed:

| Kind | Files | Bytes | Lines |
|---|---|---|---|
| ring: pregenerated assembly for other targets | 81 | 2,819,003 | 110,594 |
| `tests/` (54 copies, ring's 25 files included) | 253 | 2,113,406 | 51,462 |
| 32-bit backends (curve25519-dalek `u32`, p256 `field32` and `scalar32`, polyval `mul32`) | 7 | 295,111 | 6,739 |
| ring: perlasm for 32-bit ARM and x86 | 15 | 257,992 | 9,199 |
| `benches/` (23 copies) | 32 | 146,722 | 4,761 |
| getrandom: backends for other systems (LD-221 (7)) | 40 | 85,576 | 2,422 |
| backends for other architectures (sha2, sha1, cpufeatures: LoongArch, RISC-V, WebAssembly) | 12 | 60,417 | 1,678 |
| curve25519-dalek: the `fiat` backend (fiat-crypto left in step 2) | 4 | 21,861 | 587 |
| getrandom 0.4.3: helpers that only other backends use | 4 | 5,840 | 165 |
| **All** | **448** | **5,805,928** | **187,607** |

Per copy (the counts after include the new upstream list):

| Copy | Files cut | Files (before to after) | Rust lines (before to after) | Bytes (before to after) |
|---|---|---|---|---|
| aead 0.6.1 | 5 | 16 to 12 | 893 to 698 | 64,458 to 59,858 |
| aes 0.9.3 | 6 | 42 to 37 | 4,419 to 4,187 | 288,458 to 166,748 |
| aes-gcm 0.11.1 | 8 | 18 to 11 | 7,822 to 389 | 407,780 to 46,922 |
| argon2 0.6.0 | 2 | 19 to 18 | 3,247 to 2,195 | 138,695 to 106,907 |
| base16ct 1.0.0 | 2 | 17 to 16 | 613 to 381 | 37,354 to 32,834 |
| base64ct 1.8.3 | 10 | 33 to 24 | 2,988 to 2,092 | 131,890 to 102,902 |
| bcrypt-pbkdf 0.11.0 | 1 | 12 to 12 | 388 to 293 | 39,391 to 37,372 |
| blake2 0.11.0 | 10 | 23 to 14 | 973 to 824 | 149,907 to 54,860 |
| block-buffer 0.12.1 | 1 | 13 to 13 | 1,191 to 756 | 59,399 to 47,755 |
| blowfish 0.10.0 | 4 | 15 to 12 | 461 to 441 | 45,129 to 44,095 |
| byteorder 1.5.0 | 1 | 14 to 14 | 5,893 to 5,567 | 186,760 to 177,967 |
| cbc 0.2.1 | 6 | 18 to 13 | 611 to 508 | 52,637 to 37,914 |
| chacha20 0.10.2 | 5 | 26 to 22 | 3,580 to 2,765 | 160,878 to 133,226 |
| cipher 0.5.2 | 2 | 27 to 26 | 2,804 to 2,627 | 131,053 to 127,900 |
| cmov 0.5.4 | 3 | 20 to 18 | 2,259 to 1,702 | 116,107 to 99,936 |
| const-oid 0.10.2 | 4 | 23 to 20 | 7,255 to 6,839 | 374,760 to 361,794 |
| cpufeatures 0.3.1 | 4 | 17 to 14 | 656 to 461 | 48,452 to 43,969 |
| crypto-bigint 0.7.10 | 21 | 226 to 206 | 52,095 to 47,011 | 1,777,328 to 1,634,694 |
| ctr 0.10.1 | 9 | 24 to 16 | 1,261 to 882 | 64,941 to 51,820 |
| ctutils 0.4.6 | 2 | 24 to 23 | 4,076 to 3,900 | 165,936 to 160,580 |
| curve25519-dalek 5.0.0 | 10 | 76 to 66 | 35,200 to 28,197 | 1,452,550 to 1,146,489 |
| curve25519-dalek-derive 0.1.1 | 1 | 10 to 10 | 614 to 466 | 42,362 to 40,212 |
| der 0.8.2 | 9 | 74 to 66 | 16,300 to 14,614 | 566,261 to 516,713 |
| digest 0.11.3 | 2 | 27 to 26 | 2,984 to 2,857 | 140,224 to 139,013 |
| ed25519 3.0.0 | 8 | 20 to 13 | 1,093 to 947 | 68,183 to 64,103 |
| ed25519-dalek 3.0.0 | 8 | 30 to 23 | 4,783 to 3,552 | 282,812 to 238,840 |
| elliptic-curve 0.14.2 | 6 | 35 to 30 | 5,389 to 5,254 | 223,237 to 221,485 |
| ff 0.14.0 | 1 | 15 to 15 | 932 to 771 | 74,631 to 71,372 |
| getrandom 0.2.17 | 22 | 40 to 18 | 1,997 to 934 | 136,523 to 97,998 |
| getrandom 0.4.3 | 30 | 50 to 20 | 2,947 to 811 | 193,617 to 118,904 |
| hkdf 0.13.0 | 10 | 22 to 13 | 583 to 258 | 207,829 to 38,068 |
| hmac 0.13.0 | 12 | 26 to 15 | 548 to 466 | 80,117 to 45,778 |
| hybrid-array 0.4.15 | 3 | 24 to 22 | 3,883 to 3,229 | 148,021 to 132,678 |
| inout 0.2.5 | 2 | 16 to 15 | 1,002 to 888 | 53,237 to 51,532 |
| num-traits 0.2.19 | 1 | 29 to 29 | 8,209 to 7,822 | 276,549 to 267,071 |
| once_cell 1.21.4 | 7 | 29 to 23 | 3,950 to 2,793 | 153,813 to 128,627 |
| p256 0.14.0 | 15 | 39 to 25 | 4,181 to 2,916 | 269,259 to 225,019 |
| pbkdf2 0.13.0 | 2 | 16 to 15 | 1,245 to 1,044 | 81,687 to 75,618 |
| pem-rfc7468 1.0.0 | 13 | 27 to 15 | 1,208 to 1,060 | 75,763 to 62,280 |
| poly1305 0.9.1 | 2 | 28 to 27 | 3,032 to 2,891 | 179,004 to 177,551 |
| polyval 0.7.3 | 4 | 23 to 20 | 1,565 to 1,297 | 94,002 to 87,117 |
| rand_core 0.10.1 | 3 | 19 to 17 | 1,371 to 1,073 | 76,200 to 69,894 |
| rfc6979 0.6.0 | 1 | 12 to 12 | 578 to 513 | 47,316 to 46,246 |
| ring 0.17.14 | 121 | 392 to 271 | 28,240 to 25,725 | 7,790,261 to 4,609,007 |
| salsa20 0.11.0 | 4 | 17 to 14 | 654 to 364 | 75,996 to 37,904 |
| sec1 0.8.1 | 4 | 19 to 16 | 1,417 to 1,274 | 81,460 to 78,619 |
| sha1 0.11.0 | 5 | 21 to 17 | 1,035 to 748 | 57,679 to 48,685 |
| sha2 0.11.1 | 24 | 48 to 25 | 3,036 to 1,678 | 142,072 to 94,231 |
| ssh-cipher 0.3.0 | 1 | 19 to 18 | 1,440 to 1,394 | 79,598 to 78,215 |
| ssh-encoding 0.3.0 | 3 | 29 to 27 | 2,285 to 1,890 | 99,568 to 92,018 |
| subtle 2.6.1 | 1 | 11 to 11 | 1,440 to 1,008 | 58,136 to 47,769 |
| twofish 0.8.0 | 2 | 14 to 13 | 534 to 449 | 37,959 to 36,679 |
| typenum 1.20.1 | 1 | 25 to 25 | 40,601 to 19,354 | 1,233,510 to 606,936 |
| untrusted 0.9.0 | 1 | 18 to 18 | 536 to 402 | 44,824 to 42,554 |
| zeroize 1.9.1 | 3 | 17 to 15 | 1,830 to 1,061 | 84,883 to 69,118 |

- **Item 4, ring 0.17.14** (121 files; 7,790,261 bytes to 4,609,007): in `pregenerated/`, every file for another target: `*-elf.S` (17), `*-linux32.S` (7), `*-linux64.S` (11), `*-win64.S` (11), `*-nasm.asm` (12), `*-nasm.o` (12), `*-win32n.asm` (5), `*-win32n.o` (5) and `ring_core_generated/prefix_symbols_nasm.inc`. Kept: the 11 `*-ios64.S` (arm64), the 12 `*-macosx.S` (x86_64), `prefix_symbols.h` and `prefix_symbols_asm.h`. The perlasm scripts for 32-bit ARM and x86: `chacha-armv4`, `bsaes-armv7`, `ghash-armv4`, `vpaes-armv7`, `armv4-mont`, `sha256-armv4`, `sha512-armv4`, `aesni-x86`, `ghash-x86`, `vpaes-x86`, `x86-mont`, `chacha-x86` (`crypto/**/asm/*.pl`) and `crypto/perlasm/x86asm.pl`, `x86gas.pl`, `x86nasm.pl`. The armv8 and x86_64 perlasm scripts, which make the kept Mac files, stay with `arm-xlate.pl` and `x86_64-xlate.pl`. And `tests/` (25 files).
- **Item 5, `tests/` and `benches/`** of the other 54 copies (260 files; every one of the 55 copies lost a `tests/` or `benches/` folder).
- **Item 5, sha2 0.11.1**: `src/sha256/` and `src/sha512/` `loongarch64_asm.rs`, `wasm32_simd128.rs`, `riscv_zknh.rs`, `riscv_zknh/compact.rs`, `riscv_zknh/unroll.rs` (10). **sha1 0.11.0**: `src/compress/loongarch64_asm.rs`. **cpufeatures 0.3.1**: `src/loongarch64.rs`. The `aarch64`, `x86`, soft and `miri` files stay.
- **Item 5, curve25519-dalek 5.0.0**: the 32-bit serial backend (`src/backend/serial/u32.rs` and `u32/constants.rs`, `field.rs`, `scalar.rs`; built only with `curve25519_dalek_bits = "32"`) and the `fiat` backend (`fiat_u32.rs`, `fiat_u32/field.rs`, `fiat_u64.rs`, `fiat_u64/field.rs`; built only with `curve25519_dalek_backend = "fiat"`, whose fiat-crypto dependency left in step 2). The `u64` serial backend (aarch64) and the vector backends (x86_64 SIMD: `avx2` and `ifma`, with the `docs/` files they `include_str!`) stay.
- **Item 5, p256 0.14.0**: `src/arithmetic/field/field32.rs` and `src/arithmetic/scalar/scalar32.rs` (32-bit targets only). **polyval 0.7.3**: `src/field_element/mul32.rs`.
- **Item 5, getrandom 0.4.3** (LD-221 (7): trimmed to its macOS backend): every file of `src/backends/` except `getentropy.rs` (23: `apple_other`, `custom`, `efi_rng`, `esp_idf`, `extern_impl`, `fuchsia`, `getrandom`, `hermit`, `linux_android_with_fallback`, `linux_raw`, `netbsd`, `rdrand`, `rndr`, `solaris`, `solid`, `unsupported`, `use_file`, `vxworks`, `wasi_p1`, `wasi_p2_3`, `wasm_js`, `windows`, `windows_legacy`) and the helpers only they use (`src/utils/lazy_bool.rs`, `lazy_ptr.rs`, `sanitizer.rs`, `sys_fill_exact.rs`); `src/utils/get_errno.rs` stays (`getentropy.rs` uses it). **getrandom 0.2.17** (ring's): the 17 backend files for other systems (`apple-other`, `espidf`, `fuchsia`, `getrandom`, `hermit`, `js`, `lazy`, `linux_android`, `linux_android_with_fallback`, `netbsd`, `rdrand`, `solaris`, `solid`, `use_file`, `vxworks`, `wasi`, `windows`); `getentropy.rs`, `util.rs`, `util_libc.rs`, `error.rs`, and the feature files `custom.rs` and `error_impls.rs` stay.

### Skipped, and why

- **cfg-if 1.0.5, ecdsa 0.17.0, ghash 0.6.0, rustls 0.23.46: left plain.** Their `tests/` and `benches/` hold 296, 369, 1,341 and 624 bytes, but a cut copy keeps its upstream list (1.1 to 10.9 KB), so the cut would make `vendor/` larger. Their files are as published.
- **10 crypto copies have nothing of these kinds**: cpubits, crypto-common, group, primefield, primeorder, rustls-pki-types, rustls-webpki, signature, universal-hash and wnaf (no `tests/` or `benches/` in their `.crate`, no backend for another target). des and fiat-crypto left in step 2, rustls-platform-verifier was replaced in step 1 and ssh-key is the path copy `vendor/ssh-key`, so 69 of the table's 73 crypto rows are copies here: 55 cut, 14 not.
- **Kept although no Mac build compiles them**, because items 4 and 5 do not name them: files behind features that are off (the `dev` and test-vector modules, aes `hazmat`, chacha20 `xchacha` and the `avx512` opt-in, crypto-bigint's boxed integers, ed25519-dalek `batch`, p256 `ecdh` and `hash2curve`, rustls's second provider and its `#[cfg(test)]` modules, and others); the portable and `miri` backends; ring's other-system Rust files (`src/cpu/arm/linux.rs`, `fuchsia.rs`, `windows.rs`, 7,407 bytes), its hand-written 32-bit ARM code (`crypto/curve25519/asm/x25519-asm-arm.S` 41,448, `crypto/poly1305/poly1305_arm_asm.S` 62,534, `poly1305_arm.c` 7,388) and the `third_party/fiat` 32-bit and MSVC headers (225,013); curve25519-dalek's `vendor/ristretto.sage`; poly1305's `fuzz/` seeds; the `examples/` of once_cell and rustls. A later batch can take them with the same proof.

## 2. Proof that the cut files are never compiled or read

- **aarch64-apple-darwin, the real builds.** In the base copy, one target folder: `cargo build --workspace --all-targets --all-features`, the same with default features, `--release -p app-ffi --features net` (as build-core.sh), `--release -p app-cli -p app-hwkey`, `--release --workspace --all-targets --all-features --keep-going` (note 4 of section 12), `--target x86_64-apple-darwin -p curve25519-dalek-derive` (the proc macro, built for the host), and `cargo check --manifest-path fuzz/Cargo.toml --bins`; then `cargo +nightly fuzz build`. The union of every file named by their 1,232 dep-info files (`*.d`, build scripts included; paths normalized, since `#[path = "../…"]` gives `..`), and the 146 of the fuzz build, which add none, is the compiled set: 922 files in the crypto copies. 0 of the 448 cut files are in it.
- **x86_64-apple-darwin, a module probe.** No x86_64 standard library is installed (nothing may be downloaded), so rustc cannot build for it. rustc writes the dep-info (every module file it loads, `include_str!` files too) before it needs the standard library's items. So the library of each of the 68 crypto copies that are not proc macros was run through `rustc --emit=dep-info --target <t>` with each of its feature sets (from `cargo tree -e features` for that target, section 3), with debug assertions on and off and with `panic=unwind` and `abort`, plus the cfgs that build scripts set (curve25519-dalek: `curve25519_dalek_backend="serial"` on aarch64 and `"simd"` on x86_64, `curve25519_dalek_bits="64"` on both; num-traits `has_total_cmp`), against placeholder `core`, `alloc`, `std` and `compiler_builtins` crates (each an empty `#![no_core]` crate, `RUSTC_BOOTSTRAP=1`, under `/tmp` only) and the real `cfg-if` and `cpubits` built against them. 600 runs. The method was checked on aarch64 first: for all 68 copies the probe gives exactly the file set of the real aarch64 builds (`build.rs` aside). For x86_64 the probe gives 934 files (aarch64: 915); the differences are the x86 backends in place of the aarch64 ones (aes, chacha20, cmov, cpufeatures, curve25519-dalek's vector backends with their `docs/`, poly1305 `avx2`, polyval, ring, sha1, sha2, zeroize). 0 of the 448 cut files are in either set. On the cut copies the probe gives the same sets, row for row, with 0 missing-file errors (E0583 or "couldn't read").
- **ring's build script, both Mac targets.** The copy has no `.git`, so build.rs takes `pregenerated/`, with `ios64` for aarch64 and `macosx` for x86_64 on Apple; it never runs perl and reads no `.pl` file. Its `rerun-if-changed` walk names only files that exist. With `CFLAGS_<target>=-MD`, clang listed every file it read: aarch64 47 (11 `*-ios64.S`, the two prefix headers, 34 C files and headers), x86_64 54 (12 `*-macosx.S`, `third_party/fiat/asm/fiat_curve25519_adx_mul.S` and `_square.S`, the two prefix headers, 38 C files and headers). None of them is cut, and both lists are the same before and after the cut. The build script ran on both targets, debug and release (for x86_64 the Rust libraries then stop with E0463, no `core`); its objects, 24 on aarch64 and 30 on x86_64 in each profile, are equal before and after once `strip -S` drops their paths.
- **Fuzzing (nightly).** `cargo +nightly fuzz build`: 23 targets built from the cut tree, exit 0, 31 s.

## 3. Features: no feature set changed

`cargo tree --offline --locked -e features,normal,build,dev --prefix none -f '{p} [{f}]'`, sorted, the tree's path written the same, for aarch64-apple-darwin and x86_64-apple-darwin, in 10 forms: the workspace with all and with default features, `-p app-ffi` with and without `net`, `-p app-cli`, `-p app-hwkey`, `-p app-core`, `-p app-platform --features net`, and the fuzz workspace with all and with default features. All 20 outputs are byte-identical before and after (919, 879, 651, 591, 453, 359, 452, 142, 391 and 391 lines on aarch64; 921, 881, 653, 593, 477, 383, 476, 142, 415 and 415 on x86_64). No manifest changed, so no feature could. The custom cfgs `curve25519_dalek_backend`, `curve25519_dalek_bits` and `getrandom_backend` are set nowhere in the tree.

## 4. Lockfiles

Unchanged. No package left, no manifest changed, and no cargo run rewrote a lock: `Cargo.lock` `e23c677e…` (200 entries, 186 registry) and `fuzz/Cargo.lock` `d2758a2f…` (99, 89) before, after and after every run (`cmp`). `vendor/crates-io` keeps its 189 copies.

## 5. Diff against the published `.crate`

All 189 copies against their `.crate` from the local cargo cache, unpacked under `/tmp`: for each, the SHA-256 of the `.crate` = the lock checksum (both lockfiles) = the `package` value of `.cargo-checksum.json` and of `.cargo-checksum.upstream.json` where there is one. Then:

- files only in the `.crate`: exactly the 448 cut files of this step, the cuts of earlier steps (ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl`, step 1; the 899 files of step 4a), and the `.gitignore` and `.gitattributes` files that cargo vendor never copies;
- files that differ: 15, each a `Cargo.toml` cut in step 2 or 4a, none changed in this step (`cmp` of every `Cargo.toml` in `vendor/` before and after);
- files only in the copy: `.cargo-checksum.json` and `.cargo-checksum.upstream.json`.

So the 55 copies of this step lack only their cut files, and no file in them differs from its `.crate`. Each new `.cargo-checksum.upstream.json` (50) is the list cargo vendor wrote, unchanged; the 5 copies that already were cut copies (curve25519-dalek, getrandom 0.2.17 and 0.4.3, ring, ssh-cipher) keep theirs as it was. Each new `.cargo-checksum.json` lists every file on disk (the upstream list included) in cargo's compact form, with the same package checksum.

## 6. scripts/check-vendor.sh

`cut_copies` gains the 50 copies that were plain (70 names now). No rule changed: rule 4 already checks that a cut copy's list names only upstream files with their upstream hashes and that no file on disk is unlisted, so a cut file cannot come back changed. PASS on the copy: `Cargo.toml: 200 packages, 186 from vendor/crates-io`, `fuzz/Cargo.toml: 99 packages, 89 from vendor/crates-io`, `stubs (never built for a Mac): 0`, `cut copies (checked against their upstream list): 70`, 2.7 s.

Mutants (one script, each in the mutant copy, restored before the next; `diff -rq --no-dereference` against the private copy at the end: 0 lines). 48 runs: the 46 mutants fail, and the two controls pass:

| Mutant | Result |
|---|---|
| none (control) | PASS, exit 0 |
| N1 (`cfg-if-1.0.5` moved out), N2 (a `file://` git source under /tmp; nothing fetched), N6 | exit 101 |
| N3, N3b, N10 zxcvbn from /tmp; N7 the replacement directory under /tmp; L1 the log facade moved to /tmp; B2, B3, B4, B5 base64ct, base64, rustls, base64 from /tmp with the lock rewritten offline; A1, A2, A3 libc, objc2-app-kit, aho-corasick from /tmp | FAIL, exit 1, `read from outside the tree` |
| B2a, A1a the same, lock not rewritten | exit 101, `--locked` refuses to change the lock |
| N4 | FAIL, `symbolic links in the package folders` |
| N5 | FAIL, `stubs compiled: subtle-2.6.1` (both Mac targets) |
| M1, M2, M3 | FAIL, `not upstream beyond its cut` (curve25519-dalek `src/scalar.rs`, getrandom 0.4.3 `src/added.rs`, ssh-cipher's package checksum) |
| M4, X1, W1, W2, B1 | FAIL, `files not in its list` |
| X2, X3, X4, Y1, Y2 | FAIL, `targets outside their package or not a .rs file` |
| Z1 | FAIL, `a cut copy without its upstream list` |
| Z2 (moved from subtle, now a cut copy, to memchr-2.8.3) | FAIL, `upstream lists in copies not named as cut: memchr-2.8.3` |
| F1, F6 | FAIL, `not upstream beyond its cut` (libc, objc2-foundation) |
| F2 | FAIL, `files not in its list` (objc2-app-kit) |
| **A4, A6 (new)**: ring, getrandom 0.4.3 uncut from their `.crate` under /tmp by the root `[patch.crates-io]`, lock rewritten | exit 101: the published manifests name windows-sys and r-efi, which are not in the tree |
| **A4b, A6b (new)**: the same with the copy's `Cargo.toml` | FAIL, exit 1, `read from outside the tree: ring 0.17.14`, `getrandom 0.4.3` |
| **A5 (new)**: sha2 uncut from /tmp | FAIL, exit 1, `read from outside the tree: sha2 0.11.1` |
| **C1 (new, a `tests/` cut)**: sha2's cut `tests/mod.rs` put back with one line added, listed with its new hash | FAIL, exit 1, `sha2-0.11.1: not upstream beyond its cut: tests/mod.rs` |
| **C2 (new, a backend cut)**: getrandom 0.4.3's cut `src/backends/rdrand.rs` put back, not listed | FAIL, exit 1, `getrandom-0.4.3: files not in its list: src/backends/rdrand.rs` |
| **C3 (new, an assembly cut)**: ring's cut `pregenerated/aesv8-armx-linux64.S` put back changed, listed | FAIL, exit 1, `ring-0.17.14: not upstream beyond its cut: pregenerated/aesv8-armx-linux64.S` |
| **C4 (new, a kept assembly file)**: ring's kept `pregenerated/aesv8-armx-ios64.S` changed, listed | FAIL, exit 1, `ring-0.17.14: not upstream beyond its cut: pregenerated/aesv8-armx-ios64.S` |
| C1b (control): sha2's `tests/mod.rs` put back byte-for-byte, listed with its upstream hash | PASS, exit 0 |

As step 4a says, a cut file put back byte-for-byte with its upstream hash passes: it is upstream code, and the `.crate` diff (section 5) names it.

## 7. Build and tests (private copy, after the cut, a new target folder, an empty cargo home)

- `cargo build --offline --locked --workspace --all-targets --all-features`: exit 0, 72 s (every package compiled from the cut copies).
- `cargo test --offline --locked --workspace --no-fail-fast`: exit 0, 225 s. 2,460 passed, 0 failed, 63 ignored, in 105 result lines (104 test binaries; app-crypto's doc-tests report twice). Per binary (passed, ignored in brackets):
  - app-autotype: lib 3; int05 51; int05_match 38; int05_typing 14; doc-tests 0.
  - app-cli: main 16; bench_system 0 (1); bench_zeroing 0 (1); int10 116; memory_hygiene 1.
  - app-core: lib 25; app05 36 (2); auto_open 4; autotype_support 2; fea01 35 (2); fea02 20; fea03 16; fea04 30; fea05 46 (3); fea06 38; fea07 26; fea08 84; fea09 25; fuzz_seeds 0 (13); mod01 39; mod02 35; mod03 18; mod04 25; mod05 20; mod06 26; mod07 12; mod08 48; mod09 19; mod10 14; mod11 48 (4); mod12 29; mod13 11; no_plain_copies 1; round_trip 3; zxcvbn_copy 2; doc-tests 0.
  - app-crypto: lib 48 (1); base64 7; cipher 21; cipher_large 0 (3); hash 6 (1); kdf 35 (3); mac 8 (1); random 7; secret 10 (1); ssh_wipe 1; stream 19; doc-tests 2 and 7.
  - app-ffi: lib 166 (4); autotype 15; autotype_typing 4; clipboard 9; edit 21; generator 12; key_pages 2 (1); memory 1; messages 7; new_vault 12; option_a 8 (1); reports 3; session 11; ssh 19; vault_settings 7; doc-tests 0.
  - app-format: lib 24; attacks 13; document_read 114 (5); fuzz_seeds 0 (1); header 78; keyfile 154 (5); keys 40; open 68; property 1 (1); redteam_s2 8 (1); testdata 4; version3 51; write_file 53; write_groups 45; write_meta 46; write_pool 53; write_values 39; write_version 33; doc-tests 0.
  - app-hwkey: lib 37; real_key 1 (1); watch 2; doc-tests 0.
  - app-model: lib 35; doc-tests 0.
  - app-platform: lib 31 (7); net_start 0; doc-tests 0.
  - app-sshagent: lib 22; agent 25; own_agent 38; doc-tests 0.
  - log: lib 1; doc-tests 0.
  - uniffi-bindgen-swift: main 0.
  These are the counts of step 4a, binary for binary.
- **The TLS tests over ring and getrandom 0.2**: `cargo test --offline --locked -p app-platform --features net`: lib 44 (7), net_start 1, doc-tests 0, among them `sn03_good_certificate_from_test_anchor_works`, `sn03_bad_certificates_refused` and `ld247_handshake_signed_with_another_key_refused` (local server only).
- `cargo test --offline --locked -p app-ffi --features net`: 297 passed, 6 ignored: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0.
- `cargo test --offline --locked -p app-ffi --test app09 --no-run`: built (it runs App.app, which check.sh's G2 builds first).
- The release timed tests (check.sh's `test-release`): fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52; 250 passed, 0 failed. No timing test failed, so none was run again.
- **AT-B01 in release**: `cargo test --offline --locked --release --no-fail-fast -p app-crypto`: 171 passed, 0 failed, 10 ignored: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `kdf::tests::version_0x10_with_secret_known_answers`, `ssh::tests::sign_ed25519_rfc8032_test_1`, `ssh::tests::sign_p256_rfc6979_sample`, `r5_rfc4648_known_answers` and F-134's `f_134_damaged_speed_record_is_measured_again` are among them.
- `cargo build --release -p app-ffi --features net` and `-p app-cli`: exit 0. `cargo check --manifest-path fuzz/Cargo.toml --bins`: exit 0. `cargo +nightly fuzz build`: exit 0, 31 s.
- `cargo fmt --all -- --check`, the fuzz fmt, and the three clippy steps of check.sh (`--workspace --all-targets`, `-p app-ffi --test app09`, `-p app-platform --features net --all-targets`, each `-D warnings`): exit 0.

The first run had a cut list of 59 copies; the four of section 1 'Skipped' were then put back whole from the base copy (byte-identical to it). The whole run was repeated on the final tree (the same target folder, a new empty cargo home): every step exit 0, and every count above the same, binary for binary. Sections 3, 5, 6, 8, 9 and 10 ran on the final tree.

## 8. Advisories and policy (offline)

`cargo deny --offline --locked check`: `advisories ok, bans ok, licenses ok, sources ok`, the same 2 warnings as before (2 versions of syn; the libfuzzer-sys exception not met in the root graph). deny-fuzz (deny.toml without its `app-platform/net` line): all ok. `cargo audit -n`: 200 crate dependencies, 1 allowed warning (as before), exit 0. `cargo audit -n -f fuzz/Cargo.lock`: 99, exit 0. audit-copies (ssh-key, zxcvbn): exit 0. deny.toml names no cut file, so it needed no change.

## 9. Same compiled bytes

The tree before and the final cut tree, each copied in turn to one path (`/tmp/e0s7s4b-builder-same`), each built with a new target folder and an empty cargo home (`--release`, `SOURCE_DATE_EPOCH=1793232000`, `ZERO_AR_DATE=1`): `app` (`-p app-cli`) `eebabdf05bb4…`, `libapp_ffi.a` (`-p app-ffi --features net`, as build-core.sh) `fff1a8ad27d4…` and `libapp_hwkey.rlib` `aa898cc0e991…`, the same SHA-256 from both trees. So App.app's Rust core with its TLS code over ring, the `app` tool and the hardware-key crate compile to the same bytes; only files no build reads are gone.

## 10. Bill of materials

`scripts/make-sbom.sh` on the tree before and the final tree, each with an empty cargo home: `128 components, 103 license texts, 12 crates without a license file` both times, and `sbom.cdx.json` (`8fcd9714…`), `THIRD-PARTY-NOTICES.md` (`8ad15778…`) and `rust-std-COPYRIGHT.html` (`5647be07…`) byte-identical. **No component changes**: the 55 cut copies keep their name, version, license, top-level license files (the only files make-sbom.sh reads from a copy) and Cargo.lock checksum (the published `.crate`'s; the copy differs from it only by the cut files), and no package joined or left. The pedigree note for cut copies (LD-254 (3)) is still not written: section 12.

## 11. Size

| | Before | After | Removed |
|---|---|---|---|
| vendor/ files | 7,189 | 6,791 | 398 |
| vendor/ bytes (sum of file sizes) | 70,324,248 | 64,608,188 | 5,716,060 |
| vendor/ lines (`wc -l`, every file) | 2,038,237 | 1,850,630 | 187,607 |
| Rust lines in vendor/ (`wc -l` of every .rs) | 1,553,824 | 1,488,215 | 65,609 |
| vendor/ on disk (`du -sh`) | 84 MB | 78 MB | 6 MB |
| vendor/ folders | 1,294 | 1,182 | 112 |
| vendor/crates-io packages | 189 | 189 | 0 |

The 398 files are the 448 cut files less the 50 new upstream lists. Bytes: the cut files hold 5,805,928; the lists add 89,868 net (50 upstream lists added, the 55 new lists shorter). The 55 copies went from 1,944 files, 19,150,456 bytes and 290,127 Rust lines to 1,546 files, 13,434,396 bytes and 224,518 Rust lines; ring alone from 7,790,261 bytes to 4,609,007.

## 12. Notes for the lead

1. **Checker 2 reviews all 55 copies** (plan/team.md: crypto changes get two Checkers), though no code line changed and the compiled bytes are equal (section 9).
2. **Builds that now fail on purpose**: a `getrandom_backend` cfg for any backend but `getentropy` (getrandom 0.4.3, LD-221 (7)); `curve25519_dalek_bits = "32"` or `curve25519_dalek_backend = "fiat"`; a 32-bit target for p256 or polyval; any target that is not a Mac for ring or getrandom 0.2.17. App sets none of them: the only `RUSTFLAGS` in the tree are repro-build.sh's path remap and link arguments.
3. **The first build after the apply runs ring's build script once more**: its last `rerun-if-changed` list names the cut `.pl` and `.S` files, which are gone, so cargo runs it again. Its output and objects are the same (section 2). check.sh needs no `cargo clean` for this step (no package left, LD-257 (2)).
4. **Seen, not changed**: `cargo build --release --workspace --all-targets --all-features` stops with E0425 in app-ffi's lib test, which uses `instance::HIDDEN_VARIABLE`, built only with debug assertions. This is the same on the tree before; check.sh does not run this form. The proof used `--keep-going`.
5. **LD-254 (3), the CycloneDX pedigree note for cut copies, is still open**: 70 cut copies would get a note now.
6. Optional later: the kept files of section 1 'Skipped' (feature-gated modules, ring's other-system Rust files, its hand-written 32-bit ARM code and fiat headers, about 340 KB in ring).
7. No new finding.

## 13. The shared tree

Before the apply (12:06): a read-only process list showed no `scripts/check.sh` and no cargo, rustc or xcodebuild run. `diff -rq --no-dereference` of the shared tree against the base copy (folders named `target` and `app-shots` left out) gave 0 lines: nothing had changed since the base was made, and there was no step 4b proof file.

In one step (12:06), by one script: each of the 448 cut files was first checked to be a plain file equal to the base and absent from the private copy, as were the lists of the 55 copies, `scripts/check-vendor.sh` and `plan/architecture.md`; then the 448 files were deleted, the 112 emptied folders removed, and with plain `cp` (no `-p`, so each file's time is the apply's, LD-261 (2)) the 55 `.cargo-checksum.json`, the 50 new `.cargo-checksum.upstream.json`, `scripts/check-vendor.sh` (its mode stays `rwxr-xr-x`) and `plan/architecture.md` copied in, each then equal to the private copy (SHA-256). `diff -rq --no-dereference` of `vendor/` against the private copy: no difference.

On the shared tree afterwards, with a new empty cargo home and a new target folder under /tmp:
- `cargo build --offline --locked --workspace --all-targets --all-features`: exit 0, 71 s; `cargo build --offline --locked -p app-platform --features net`: exit 0; `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins`: exit 0. The cargo home then held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG`; both lockfiles kept `e23c677e…` and `d2758a2f…`.
- `scripts/check-vendor.sh`: PASS (`Cargo.toml: 200 packages, 186 from vendor/crates-io`; fuzz 99, 89; 0 stubs; 70 cut copies).
- `scripts/check-names.sh` before the records: `names: PASS (10017 files scanned, 16 vault files name-only)`; after them: `names: PASS (10018 files scanned, 16 vault files name-only)`; `--self-test`: PASS.

Then the records, each with plain `cp` after a `cmp` showed the shared file unchanged since the base: this file (new), `spec/research/dependencies.md` (section 17 appended) and one exact append to the E0-S7 status line in `plan/epics.md`.

scripts/check.sh was not run (the lead runs it). No package left in this step, so it needs no `cargo clean` first (LD-257 (2)); ring's build script runs once more on its first build (section 12 note 3).

## 14. Checker 1 (2026-10-31)

Checker 1, round 1: **passed**, no new finding. A private copy (`/tmp/e0s7s4b-checker1-copy`, `rsync -a` with the anchored excludes) made at 12:15, after the apply and the records; at the end `diff -rq --no-dereference` against the shared tree gave 0 lines. A new target folder, new empty cargo homes, a throwaway `HOME`, `RUSTUP_HOME` the user's and `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. Nothing was fetched: each cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` at the end.

- **Build and tests**: `cargo build --offline --locked --workspace --all-targets --all-features` exit 0, 73 s. `cargo test --offline --locked --workspace --no-fail-fast` exit 0: 2,460 passed, 0 failed, 63 ignored in 105 result lines, the counts of section 7 binary for binary. `-p app-platform --features net`: lib 44 (7), net_start 1, doc-tests 0. `-p app-ffi --features net`: 297 passed, 6 ignored, per binary as section 7. app09 `--no-run`: built. The release timed tests: fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52 (250); none failed. AT-B01, `cargo test --offline --locked --release --no-fail-fast -p app-crypto`: 171 passed, 0 failed, 10 ignored (lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7). `cargo fmt --all -- --check`, the fuzz fmt, the three clippy steps of check.sh with `-D warnings` and `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins`: exit 0. `cargo +nightly fuzz build`: 23 targets, exit 0, 29 s.
- **Lockfiles**: `e23c677e…` and `d2758a2f…` (the hashes step 4a recorded) before and after every run; both files still have the time of the step 4a apply (09:56). `Cargo.lock` 200 entries (186 registry), `fuzz/Cargo.lock` 99 (89); every registry entry has its copy, and for every copy the SHA-256 of its `.crate` = its lock checksum = the `package` value of its list. No package left, so no removed package can be in a cargo tree; `cargo tree --workspace --all-features -e normal,build,dev` resolves for both Mac targets and both workspaces (200 and 201 packages; fuzz 94 and 99).
- **Diff against the `.crate`**, all 189 copies (unpacked under /tmp from the local cache): the files only in the `.crate` are exactly the 448 files of section 1 in the 55 copies, ring's `aesni-x86_64.pl` (step 1), the 899 files of step 4a and the `.gitignore` and `.gitattributes` files; the files that differ are the 15 `Cargo.toml` of steps 2 and 4a (times 10-30 18:56, and 10-31 09:56 for regex-automata: none written by this step); the files only in the copy are the two lists.
- **Checksum lists**, all 189 copies: each `.cargo-checksum.json` names exactly the files on disk, each with its true SHA-256. The 70 copies with a `.cargo-checksum.upstream.json` are the 70 names of `cut_copies`; each upstream list is cargo vendor's list (every `.crate` file but `.gitignore` and `.gitattributes`, with its `.crate` hash, and the same package), and every kept file but `Cargo.toml` has its upstream hash. The 5 copies cut before this step keep their upstream list as it was (time 10-30 18:56).
- **Never compiled**: the dep-info of my builds (1,115 `.d` files: debug, release, tests, clippy, the fuzz check) names 920 files in the crypto copies and 0 cut files; the nightly fuzz build's dep-info names 977 files, 0 cut. The gate of every cut code file, read from the source, is the same on both Mac targets: sha2, sha1 and cpufeatures (`target_arch = "loongarch64"`, `wasm32` with `simd128`, the riscv `sha2_backend` cfgs); curve25519-dalek (`curve25519_dalek_bits = "32"`, `curve25519_dalek_backend = "fiat"`; its build script takes 64 bits from the pointer width); p256 and polyval (`cpubits!` 16 or 32); getrandom 0.4.3 (`backends.rs`: `target_os = "macos"` takes `getentropy`, which includes only `utils/get_errno.rs`) and 0.2.17 (`lib.rs`: macOS takes `util_libc` and `getentropy`). No `--cfg`, cfg `RUSTFLAGS` or `cpubits` override is set in the tree.
- **ring's build script on both Mac targets**: no x86_64 standard library is installed, so the file list was first read from `build.rs` (no `.git`, so `pregenerated/`, with `ios64` for aarch64 and `macosx` for x86_64; `RING_SRCS`, the sha256 file made from the sha512 script, and `crypto/constant_time_test.c`): aarch64 24 objects (11 `*-ios64.S`, 13 C files), x86_64 30 (12 `*-macosx.S`, the 2 fiat `.S`, 16 C files); every one of these files is there. Then the build script ran for both targets with `CFLAGS_<target>=-MD` (`-p app-platform --features net`; for x86_64 the Rust libraries stop with no `core`, as expected): aarch64 read 47 files and x86_64 54, with 24 and 30 objects and both libraries made; 0 cut files read, 0 missing. No kept C, header or assembly file of ring names a cut file; only `build.rs`, the manifests and four kept perlasm scripts do, on the `.git` path that is never taken here.
- **check-vendor** on the copy: PASS (200, 186; fuzz 99, 89; 0 stubs; 70 cut copies), 3.4 s. The mutants, made again from section 6 and the records of steps 1 to 4a, each in a mutant copy (`/tmp/e0s7s4b-checker1-mut`) restored before the next (`diff -rq` 0 lines at the end): all 46 fail and both controls (none, C1b) pass, with the exits and messages of section 6 (N1, N2, N6, B2a, A1a, A4 and A6 exit 101; the others FAIL, exit 1). Five more of my own: K1 ring's `tests/aead_tests.rs` back changed and listed, K3 sha2's `src/sha256/loongarch64_asm.rs` back changed and listed, K4 getrandom 0.2.17's `src/rdrand.rs` back changed and listed, K5 a new listed `benches/k5.rs` in p256: each FAIL, exit 1, `not upstream beyond its cut`. K2 (curve25519-dalek's `src/backend/serial/u32.rs` back, listed with its upstream hash, then changed on disk) passes check-vendor by its design, and cargo refuses it (`the listed checksum of … has changed`). K6 (zeroize's `src/lib.rs` changed, its new hash written into both lists) passes: the LD-254 (2) case, outside check-vendor's scope; the `.crate` diff above is its control.
- **Bill of materials** on the copy (an empty cargo home, `SOURCE_DATE_EPOCH` 1793232000): `128 components, 103 license texts, 12 crates without a license file`; `sbom.cdx.json` `8fcd9714…`, `THIRD-PARTY-NOTICES.md` `8ad15778…`, `rust-std-COPYRIGHT.html` `5647be07…`, the hashes step 4a recorded. No license, notice, authors or readme file is among the cut files.
- **Size**: vendor/ 6,791 files, 64,608,188 bytes, 1,850,630 lines (1,488,215 of Rust), 1,182 folders, 78 MB; the 448 cut files hold 5,805,928 bytes, 187,607 lines and 65,609 Rust lines: as section 11.
- **Name guard** on the copy: `names: PASS (9730 files scanned, 16 vault files name-only)`; `--self-test`: PASS. On the shared tree after this section and the status line: `names: PASS (10018 files scanned, 16 vault files name-only)`; `--self-test`: PASS.

Notes, not send-backs:

1. The skip reason is wrong for ghash 0.6.0: its `tests/lib.rs` and `benches/ghash.rs` (1,341 bytes) are larger than its list (1,147 bytes), so its cut would save 413 bytes and 1 file, not make vendor/ larger. For cfg-if, ecdsa and rustls the reason holds (a cut would add 921, 1,168 and 10,099 bytes). Keeping ghash plain is still right, since it saves nearly nothing. Section 1 'Skipped', dependencies.md section 17 and the status line give the reason for all four.
2. Older than this step, in rows this step edited in plan/architecture.md: the approved-crates intro still says packages never built on a Mac are stubs (there are 0 since step 2), and the Ed25519 row still names fiat-crypto 0.3.0 as new in the tree (it left in step 2).

## 15. Checker 2 (2026-10-31): passed

Scope: the crypto copies (plan/team.md: crypto changes get two Checkers). The research table (dependencies.md section 7) marks 73 packages crypto, key or support. 69 of them are copies in `vendor/crates-io`; des and fiat-crypto left in step 2, rustls-platform-verifier was replaced (LD-247 (2)), and ssh-key is the path copy `vendor/ssh-key` (LD-209). This step touched 55 of the 69. I checked all 69.

Setup: a private copy of the shared tree (`/tmp/e0s7s4b-checker2-copy`, `rsync -a` with the anchored excludes) made at 12:41, after the apply and Checker 1's records; before these records, `diff -rq --no-dereference` against the shared tree (folders `target` and `app-shots` left out) gave 0 lines. A second tree holds the state before the step (`/tmp/e0s7s4b-checker2-base`): the copy with the 448 cut files put back from the `.crate`, the 50 new cut copies with cargo vendor's list back as `.cargo-checksum.json`, and the 5 older cut copies with the put-back files added to their list. New empty cargo homes, a throwaway `HOME`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. The `.crate` files came from the local cargo cache, each unpacked into its own folder under `/tmp`. Nothing was fetched: each cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` at the end.

- **Each crypto copy against its `.crate`** (69 copies): for every copy, the SHA-256 of the `.crate` = the `Cargo.lock` checksum (and the `fuzz/Cargo.lock` checksum, for the 62 that are in it) = the `package` value of `.cargo-checksum.json` and of `.cargo-checksum.upstream.json` where there is one. 0 mismatches. `diff -r` against the unpacked `.crate`:
  - files that differ: only the 5 `Cargo.toml` of step 2, lines removed and added: curve25519-dalek 5.0.0, 4 and 0; getrandom 0.2.17, 5 and 0; getrandom 0.4.3, 4 and 0; ring 0.17.14, 7 and 0; ssh-cipher 0.3.0, 7 and 0. Each has the time 2026-10-30 18:56:59 (step 2). No `Cargo.toml` changed in this step;
  - files only in the copy: the two lists;
  - files only in the `.crate`: 461, that is the 448 cut files of this step, ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (step 1, LD-247 (4)) and 12 `.gitignore` and `.gitattributes` files. Per copy, the count equals the table of section 1, copy by copy.

  So no code line changed and no file was added: each copy is its published `.crate` less whole files.
- **Every cut file is of a kind that items 4 and 5 name** (a script put each of the 448 files in one kind, 0 left over): `tests/` 253; `benches/` 32; ring's pregenerated files for other targets 81 (none is a `*-ios64.S`, a `*-macosx.S`, `prefix_symbols.h` or `prefix_symbols_asm.h`); ring's perlasm for 32-bit ARM and x86 15; the backend files named in section 1 for sha2 (10), sha1 (1), cpufeatures (1), curve25519-dalek (8), p256 (2) and polyval (1); getrandom 0.4.3 backends and helpers for other systems 27; getrandom 0.2.17 backends for other systems 17. ring keeps 11 `*-ios64.S`, 12 `*-macosx.S` and both prefix headers in `pregenerated/`.
- **The lists**: every `.cargo-checksum.json` names exactly the files on disk, each with its true SHA-256 (in the 55 cut copies the upstream list is one of them). Each upstream list (55) and each plain copy's list (14) names exactly the `.crate`'s files less `.gitignore` and `.gitattributes`, with the `.crate` hashes and the same package. Every kept file but `Cargo.toml` has its upstream hash. 1,772 kept files, 0 errors.
- **Times on the shared tree**: in `vendor/`, 105 files are newer than 2026-10-31 10:00, all from 12:06 (the apply) and all lists: the 55 `.cargo-checksum.json` and the 50 new `.cargo-checksum.upstream.json`. The 5 older upstream lists keep 2026-10-30 18:56. No file in `vendor/ssh-key` or `vendor/zxcvbn` is newer.
- **The gate of every cut code file, read in the kept source**. `rustc --print cfg` gives `target_os="macos"`, `target_pointer_width="64"`, `target_env=""` and `target_vendor="apple"` for both aarch64-apple-darwin and x86_64-apple-darwin. No gate below is true on either:
  - sha2 `src/sha256.rs` and `src/sha512.rs` (`cfg_if`): `loongarch64_asm` only for `target_arch = "loongarch64"`, `wasm32_simd128` only for `wasm32` with `simd128`, `riscv_zknh` only with `sha2_backend` or `sha2_256_backend = "riscv-zknh"`. On both Mac targets the kept `aarch64_*` or `x86_*` file with `soft` is taken.
  - sha1 `src/compress.rs`: `loongarch64_asm` only for `target_arch = "loongarch64"`. cpufeatures `src/lib.rs`: `mod loongarch64` only for `target_arch = "loongarch64"`.
  - curve25519-dalek `src/backend/serial.rs`: `u32` only with `curve25519_dalek_bits = "32"`; `fiat_u32` and `fiat_u64` only with `curve25519_dalek_backend = "fiat"`. Its `build.rs` reads no file: it takes the bits from `CARGO_CFG_TARGET_POINTER_WIDTH` (64 on both) and the backend `serial` on aarch64 or `simd` on x86_64; `fiat` only when that cfg is given.
  - p256 `src/arithmetic/field.rs` and `scalar.rs`, polyval `src/field_element.rs`: the cut files are the `cpubits!` 32-bit arms (16 and 32 for polyval). cpubits takes 64 from `target_pointer_width = "64"`, unless a `cpubits` cfg is given.
  - getrandom 0.4.3 `src/backends.rs`: each cut file is a `getrandom_backend` arm or a `target_os` arm; `target_os = "macos"` takes `getentropy.rs`, which loads only `utils/get_errno.rs` by `#[path]`. Its `build.rs` reads no file (it sets `getrandom_msan` only under the memory sanitizer).
  - getrandom 0.2.17 `src/lib.rs`: the second `cfg_if` arm, `target_os = "macos"`, takes `getentropy.rs` with `util_libc.rs`. It comes before the arms of the `rdrand`, `js` and `custom` features, so no feature can take a cut file on a Mac; and none of them is on (below).
  - `tests/` and `benches/`: kept files name them only in the `[[test]]` and `[[bench]]` tables of the copies' `Cargo.toml` (cargo builds only the library and the build script of a dependency), in comments, and in one `include_bytes!` in pem-rfc7468 `src/decoder.rs`, inside `#[cfg(test)] mod tests`. Of the 55 copies only ring, curve25519-dalek, getrandom 0.4.3 and num-traits have a build script; the last three read no file (num-traits: one autocfg probe).
  - Outside `vendor/`, no `--cfg`, `RUSTFLAGS` or `.cargo/config.toml` entry sets `curve25519_dalek_backend`, `curve25519_dalek_bits`, `getrandom_backend`, `sha2_backend`, `sha2_256_backend`, `sha2_512_backend`, `sha1_backend` or `cpubits`. The only `RUSTFLAGS`, in `scripts/repro-build.sh`, are path maps and link arguments.
- **Cut tables never selected on a Mac**: `cargo tree --offline --locked -e features,normal,build,dev --prefix none --no-dedupe` for aarch64-apple-darwin and x86_64-apple-darwin, in 4 forms (workspace with all features, workspace with default features, `-p app-ffi --features net`, the fuzz workspace with all features), on the tree before and the cut tree, with the tree's path written the same: all 8 outputs byte-identical before and after (aarch64 `4971deeb`, `25087d21`, `9074ffaa`, `7f694f74`; x86_64 `03a1ce6d`, `7a1f42fb`, `727e9ae4`, `63490768`). With `-f '{p} [{f}]'` (workspace and fuzz, all features, `normal,build,dev`), none names windows-sys, windows-targets, wasi, r-efi, fiat-crypto, des, js-sys, wasm-bindgen or linux-raw-sys, and the crypto copies get the same features on both targets: ring `alloc`, `default`, `dev_urandom_fallback`; getrandom 0.2.17 none; getrandom 0.4.3 at most `std`, `sys_rng`; curve25519-dalek `digest`, `zeroize`; sha2 and sha1 `alloc`, `default`, `oid`, `zeroize`; cpufeatures none; p256 `arithmetic`, `digest`, `ecdsa`, `ecdsa-core`, `sha2`, `sha256`; polyval `hazmat`, `zeroize`; ssh-cipher `aes`, `chacha20poly1305`, `encoding`, `rand_core`, `zeroize`. The two targets differ only in curve25519-dalek-derive (the x86_64 SIMD proc macro) and the syn it needs.
- **ring's build script, both Mac targets**: from `build.rs`: the copy has no `.git`, so it takes `pregenerated/`; `ASM_TARGETS` gives `ios64` for aarch64 and `macosx` for x86_64 on Apple; the `.pl` names in `RING_SRCS` only give the output names (`asm_path`), and perl never runs. Then `cargo build --offline --locked -p app-platform --features net --target <t>` with `CFLAGS_<t>=-MD`, on the cut tree and on the tree before (for x86_64 the Rust libraries then stop with E0463, no `core`, as expected): aarch64 read 47 files (11 `*-ios64.S`), x86_64 54 (12 `*-macosx.S` and the two `third_party/fiat` `.S`); 0 cut files, 0 missing, and the same lists on both trees. The objects, 24 and 30, are equal on both trees after `strip -S`.
- **Never compiled, aarch64**: the dep-info of my builds (610 `.d` files: the workspace with all targets and features, AT-B01 in release, the two `net` test runs, the ring traces, curve25519-dalek-derive for the host) names 985 files in the 69 crypto copies and 0 cut files.
- **Known answers and TLS** (the cut copy, a new target folder, an empty cargo home): `cargo build --offline --locked --workspace --all-targets --all-features` exit 0, 76 s. AT-B01 in release, `cargo test --offline --locked --release --no-fail-fast -p app-crypto`: 171 passed, 0 failed, 10 ignored: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; among them `version_0x10_with_secret_known_answers`, `sign_ed25519_rfc8032_test_1`, `sign_p256_rfc6979_sample`, the three `fips_180_4_vectors`, `chacha20_rfc8439_vectors`, `salsa20_estream_vectors_cry01_t24` and `f_134_damaged_speed_record_is_measured_again`. `cargo test --offline --locked -p app-platform --features net` (TLS over ring and getrandom 0.2, local server only): lib 44 passed (7 ignored), among them `sn03_good_certificate_from_test_anchor_works`, `sn03_bad_certificates_refused` and `ld247_handshake_signed_with_another_key_refused`; net_start 1; doc-tests 0. `cargo test --offline --locked -p app-ffi --features net`: 297 passed, 6 ignored: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0. `scripts/check-vendor.sh`: PASS (200 packages, 186 from vendor/crates-io; fuzz 99, 89; 0 stubs; 70 cut copies). Name guard on the copy: `names: PASS (9730 files scanned, 16 vault files name-only)`.

Notes, not send-backs:

1. Two rows of plan/architecture.md that this step edited say more than the tree holds. "SSH keys": "these copies (not `vendor/ssh-key`) have no `tests/` or `benches/`", but ghash 0.6.0 keeps both (left plain, section 1). "ECDSA P-256": "`p256` and the copies under it are cut copies: no `tests/` or `benches/`", but ecdsa 0.17.0 keeps `tests/` (left plain), and primeorder, primefield, group and wnaf are plain (they have nothing of these kinds). Smallest fix: name ghash and ecdsa as kept whole in these two rows.
2. The cut copies' `Cargo.toml` still name `[[test]]` and `[[bench]]` targets whose files are gone (for example aes-gcm `tests/aes128gcm.rs`). Nothing reads them, since cargo builds only the library and the build script of a dependency, and the manifests stay upstream (rule 3). A copy's own tests cannot run from the tree any more; AT-B01 stays the known-answer check on the copies.
3. x86_64 has no real build here (no x86_64 standard library). It is covered by the gates above, ring's clang trace and cargo tree, and by the module probes of the Builder and Checker 1.

No new finding. Verify next.

## 16. Verify (2026-10-31): signed

Verdict: **signed**. Every E0-S7 check that step 4b covers passed again in a private copy: the offline locked build and every test with an empty cargo home, check-vendor failing on each source outside the tree, the bill of materials with the same components and checksums, every copy (the 69 crypto copies among them) against its published `.crate` with only the recorded cuts, AT-B01 in release, the TLS tests, the name guard, `scripts/build-core.sh` and `xcodebuild build-for-testing`. The Verify agent did not build or check this step, and it changed no product file. No new finding (the next free number is still F-137).

Setup: a private copy, `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots` (`/tmp/e0s7s4b-verify-copy`, made at 13:02, after Checker 2's records; `diff -rq --no-dereference` against the shared tree: only the three excluded folders; Cargo.lock `e23c677e…`, fuzz/Cargo.lock `d2758a2f…`, both with the time of the step 4a apply, 09:56). A mutant copy (`/tmp/e0s7s4b-verify-mut`) was restored by `rsync -a --delete` before each mutant; `diff -rq --no-dereference` against the private copy at the end: 0 lines. Target folders under /tmp, a new empty cargo home per run, a throwaway `HOME`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. Every cargo call was `--offline --locked`, except the lock rewrites of mutants V1 and V2 (mutant copy only). The `.crate` files came from the local cargo cache and were read in memory by a small reader (python3 -I; each archive member checked first: a plain file inside its package folder, no absolute or `..` path); nothing was fetched.

No network: every build and test run, fmt, clippy, the fuzz builds, check-vendor and its mutants, ring's traced builds, make-sbom.sh and build-core.sh ran through `sandbox-exec` with `(allow default)`, `(deny network-outbound (remote ip))`, one allowance for `localhost:*` and a deny on the resolver socket, as in steps 3a to 4a. Inside it, a socket to 192.0.2.1:443 gets "Operation not permitted", a name lookup fails, and a listener on 127.0.0.1 is reached. Outside it, still offline with an empty cargo home: the two tests that cannot run in a sandbox and the release fea06 run (16.1), the name guard and xcodebuild, which does not start inside another sandbox. Each empty cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` (not for the read-only runs) and `registry/CACHEDIR.TAG` afterwards. Both lockfiles kept their SHA-256 through every run.

### 16.1 Build and tests, offline and locked, with an empty cargo home

- `cargo build --offline --locked --workspace --all-targets --all-features -v` (sandbox): exit 0, 71 s. No line names `registry/src` or the cargo cache. 185 of the 189 folders of `vendor/crates-io` were compiled, 69 of the 70 cut copies among them; the other 4 are arbitrary, libfuzzer-sys and jobserver (fuzz workspace only) and curve25519-dalek-derive (x86_64 only), as in step 4a.
- `cargo test --offline --locked --workspace --no-fail-fast` (sandbox): 105 result lines, 2,458 passed, 2 failed, 63 ignored, 228 s. The 2 failures are the sandbox, as in steps 2 to 4a: `fea06_29_offline_streams` (`ps` is refused, "Operation not permitted") and `t53_t57_ssh_signs_in_through_apps_socket` ("Allow Once: ssh signs in with App's key": macOS's `sshd-auth` starts its own sandbox). Each passes alone outside it (1 passed each; the ssh test uses its own `ssh_config` with `IdentityFile=none`, a throwaway known-hosts file and App's own agent socket, LD-203 (6); no `sshd` or `ssh-agent` was left afterwards). So 2,460 pass. Per test binary (ignored in brackets): app-autotype lib 3, int05 51, int05_match 38, int05_typing 14; app-cli main 16, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; app-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 84, fea09 25, fuzz_seeds 0 (13), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 26, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; app-crypto lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; app-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; app-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; app-hwkey lib 37, real_key 1 (1), watch 2; app-model lib 35; app-platform lib 31 (7), net_start 0; app-sshagent lib 22, agent 25, own_agent 38; log lib 1; uniffi-bindgen-swift main 0; the other doc-tests 0. These are the counts of section 7, binary for binary.
- **The TLS tests over ring and getrandom 0.2**, `-p app-platform --features net` (sandbox, local server only): lib 44 passed (7 ignored), net_start 1, doc-tests 0; `sn03_good_certificate_from_test_anchor_works`, `sn03_bad_certificates_refused`, `ld247_handshake_signed_with_another_key_refused` and `ld247_good_chain_through_an_intermediate_works` are among them. `-p app-ffi --features net` (sandbox): 297 passed, 6 ignored, 16 result lines: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0. `-p app-ffi --test app09 --no-run`: built.
- Release, timed tests (`--release -p app-core`): fea01 37, fea05 49, fea07 26, mod08 48, mod11 52 (sandbox) and fea06 38 (outside it, for `fea06_29`): 250 passed, 0 failed. No timing test failed, so none was run again.
- `cargo fmt --all -- --check`, the fuzz workspace's fmt, the three clippy steps of check.sh (`-D warnings`: the workspace with all targets, `-p app-ffi --test app09`, app-platform with `net` and all targets) and `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins` (sandbox): exit 0 each, no warning. `cargo +nightly fuzz build` (sandbox, its own target folder): exit 0, 29 s, 23 target binaries; `cargo +nightly fuzz list`: 23.

### 16.2 Lockfiles and manifests

Both lockfiles are byte-identical to step 4a's (`e23c677e…`, `d2758a2f…`; 200 entries with 186 registry, 99 with 89) and kept their 09:56 time: no package joined or left. `vendor/crates-io` has 189 copies, exactly the registry entries of both lockfiles. In the shared `vendor/`, the files newer than 2026-10-31 10:00 are 105, all with the time 12:06 (the apply) and all lists: 55 `.cargo-checksum.json` and 50 `.cargo-checksum.upstream.json`. Of the 189 `Cargo.toml` files in `vendor/crates-io`, 174 keep their `.crate` time, 14 have 2026-10-30 18:56:59 (step 2) and 1 has 2026-10-31 09:56:13 (regex-automata, step 4a): no manifest was written in this step, so no dependency or feature can have changed (16.5 shows the same by content).

### 16.3 A source outside the tree fails check-vendor

Each mutant was made in the mutant copy, run through check-vendor in the sandbox, then restored. V1, V1a, V2, V4 and V5 are new; V1 and V2 bring a crypto copy that this step cut back uncut from outside the tree (its published files with the copy's manifest, since the published manifests name packages that are not in the tree, as A4b and A6b).

| Mutant | Result |
|---|---|
| None | PASS, exit 0 (`Cargo.toml: 200 packages, 186 from vendor/crates-io`; fuzz 99, 89; stubs 0; cut copies 70) |
| N1: a registry package not vendored (`cfg-if-1.0.5` removed) | exit 101, `no matching package named cfg-if found` |
| N3: the root `[patch]` zxcvbn at a copy under /tmp | FAIL, exit 1: `read from outside the tree: zxcvbn 3.1.1: path at /tmp/e0s7s4b-verify-outside/zxcvbn/Cargo.toml` |
| N7: the replacement directory a copy of `vendor/crates-io` under /tmp | FAIL, exit 1: `read from outside the tree` for both manifests, 275 lines (186 + 89 registry packages, each with its /tmp path) |
| V1 (new): getrandom 0.2.17 uncut, written from its `.crate` under /tmp, put in by the root `[patch.crates-io]`, Cargo.lock rewritten offline (`Adding getrandom v0.2.17 (/tmp/…)`) | FAIL, exit 1: `read from outside the tree: getrandom 0.2.17: path at /tmp/e0s7s4b-verify-outside/getrandom-0.2.17/Cargo.toml` |
| V1a (new): the same, the lock not rewritten | exit 101, `cannot update the lock file … because --locked was passed` |
| V2 (new): curve25519-dalek 5.0.0 uncut from /tmp the same way | FAIL, exit 1: `read from outside the tree: curve25519-dalek 5.0.0: path at /tmp/…/curve25519-dalek-5.0.0/Cargo.toml` |
| V4 (new): p256's cut `src/arithmetic/field/field32.rs` back from the `.crate`, not listed | FAIL, exit 1: `p256-0.14.0: files not in its list: src/arithmetic/field/field32.rs` |
| V5 (new): ring's kept `pregenerated/ring_core_generated/prefix_symbols_asm.h` with one line added, listed with its new hash | FAIL, exit 1: `ring-0.17.14: not upstream beyond its cut: pregenerated/ring_core_generated/prefix_symbols_asm.h` |

The other mutants (sections 6 and 14, 46 runs and 6 more) were not run again: check-vendor.sh changed only in its `cut_copies` list (20 names to 70), and the 70 copies with an upstream list on disk are exactly those 70 names (16.5).

### 16.4 The bill of materials keeps the same components and checksums

`scripts/make-sbom.sh` (sandbox, empty cargo home, output under /tmp): `128 components, 103 license texts, 12 crates without a license file`; `sbom.cdx.json` `8fcd971405cf…`, `THIRD-PARTY-NOTICES.md` `8ad1577893e1…`, `rust-std-COPYRIGHT.html` `5647be074c8e…`: the hashes that step 4a and section 10 recorded, so all three files are byte-identical to step 4a's.

- 114 components carry a SHA-256, and each equals its Cargo.lock checksum (0 mismatches). Every component has its license, except App's own crates and the `log` facade (App's own license is D2, the owner's).
- 54 of the 55 copies this step cut are components, each with its version, its license and the checksum of its `.crate` (for example ring 0.17.14 `Apache-2.0 AND ISC` in App.app; getrandom 0.2.17 `MIT OR Apache-2.0` in App.app; sha2 0.11.1, p256 0.14.0 and curve25519-dalek 5.0.0 in "App.app, app"). The 55th, curve25519-dalek-derive, is a proc macro used only on x86_64, and was not a component before either. Only zxcvbn and ssh-key carry `pedigree` (LD-254 (3) is still open).

### 16.5 Every copy against its published `.crate` (the diff proof, rule 3)

All 189 copies, each against its `.crate` read in memory:

- For each, the archive's SHA-256 equals the checksum in both lockfiles and the `package` value of its list(s). The research table (dependencies.md section 7) marks 73 rows crypto, key or support; 69 of them are copies here.
- A list built from each `.crate` in cargo vendor's form (every file but `.gitignore` and `.gitattributes`, its `.crate` hash, the package checksum, cargo's `$comment` line) is byte-for-byte the same JSON as `.cargo-checksum.json` for each of the 119 plain copies and `.cargo-checksum.upstream.json` for each of the 70 cut copies. The copies with an upstream list are exactly the 70 names of `cut_copies`. Every `.cargo-checksum.json` names exactly the files on disk, each with its true SHA-256; no copy has a symbolic link, and no copy holds a file that its `.crate` lacks. 0 errors.
- Files only in the `.crate`, besides 62 `.gitignore` and `.gitattributes` files: the 899 of step 4a in its six non-crypto copies (libc 390, objc2-app-kit 291, objc2-foundation 161, objc2-core-foundation 34, objc2-io-kit 12, regex-automata 11), ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (step 1, LD-247 (4)) and **exactly 448 files in 55 crypto copies**, per copy the counts of section 1's table (ring 121, getrandom 0.4.3 30, sha2 24, getrandom 0.2.17 22, crypto-bigint 21, p256 15, …).
- Every one of the 448 is of a kind that items 4 and 5 name (a script put each in one kind, 0 left over): `tests/` 253; `benches/` 32; ring's `pregenerated/` files for other targets 81 (none a `*-ios64.S`, a `*-macosx.S`, `prefix_symbols.h` or `prefix_symbols_asm.h`; ring keeps 11 and 12 of the first two and both headers); ring's perlasm for 32-bit ARM and x86 15; the other-architecture backends of sha2 10, sha1 1 and cpufeatures 1 (LoongArch, RISC-V, WebAssembly); curve25519-dalek's `u32` and `fiat` backends 8; p256's 32-bit field and scalar 2; polyval's `mul32` 1; getrandom 0.4.3 27 and getrandom 0.2.17 17 backend and helper files for other systems.
- Files that differ from the `.crate`: 15, each the `Cargo.toml` of a copy in `cut_copies`, from steps 2 and 4a. **In the 69 crypto copies, 64 are byte-identical to their `.crate` apart from removed files, and the other 5 differ only in a `Cargo.toml` that lost lines and gained none** (a subsequence check): curve25519-dalek 5.0.0 4, getrandom 0.2.17 5, getrandom 0.4.3 4, ring 0.17.14 7, ssh-cipher 0.3.0 7, the numbers of step 4a's Verify (16.5). **No code file differs in any copy, and no file was added.** The 14 crypto copies this step left whole are cfg-if, cpubits, crypto-common, ecdsa, ghash, group, primefield, primeorder, rustls, rustls-pki-types, rustls-webpki, signature, universal-hash and wnaf.
- Size, measured on the copy: `vendor/` 6,791 files, 64,608,188 bytes, 1,850,630 lines (1,488,215 of Rust), 1,182 folders, 78 MB; the 448 cut files, read from their `.crate`, hold 5,805,928 bytes, 187,607 lines and 65,609 Rust lines. These are section 11's numbers.

### 16.6 The cut files are never compiled or read on either Mac target

- **aarch64-apple-darwin**: the union of every file named by the dep-info of my builds (1,157 `.d` files: the build, tests, release, AT-B01, clippy, the fuzz check and build-core.sh; build scripts included) names 920 files in the crypto copies and 0 of the 448 cut files; the nightly fuzz build's 146 `.d` files name 977 files in `vendor/crates-io`, 0 cut.
- **ring's build script, both Mac targets**: read from `build.rs` (no `.git`, so `pregenerated/`; `ASM_TARGETS` gives `ios64` for aarch64 and `macosx` for x86_64 on Apple), it takes 24 inputs on aarch64 (11 `*-ios64.S`, 13 C files) and 30 on x86_64 (12 `*-macosx.S`, the two `third_party/fiat/asm` `.S` and 16 C files); all of them are there. Then `cargo build -p app-platform --features net --target <t>` with `CFLAGS_<t>=-MD` (sandbox; for x86_64 with `--keep-going`, since its Rust libraries stop with E0463, no `core`): aarch64 made 24 objects and both libraries and read 47 files; x86_64 made 30 objects and both libraries and read 54. 0 cut files read, 0 missing: the numbers of sections 2, 14 and 15.
- **x86_64, the other cut code**: no x86_64 standard library is installed and nothing may be downloaded, so there is no full x86_64 build (as in steps 2 to 4a). `rustc --print cfg` gives `target_os="macos"`, `target_pointer_width="64"`, `target_env=""` and `target_vendor="apple"` on both targets. The gates read in the kept source: sha2 `src/sha256.rs`/`sha512.rs` take `loongarch64_asm` only for `target_arch = "loongarch64"`, `wasm32_simd128` only for `wasm32` with `simd128`, `riscv_zknh` only with a `sha2_backend`/`sha2_256_backend` cfg; sha1 and cpufeatures `loongarch64` only for that architecture; curve25519-dalek `src/backend/serial.rs` takes `fiat_u32`/`fiat_u64` only under `curve25519_dalek_backend = "fiat"` and `u32` only with `curve25519_dalek_bits = "32"`, and its `build.rs` takes the bits from the pointer width; p256 and polyval take the `cpubits!` 16/32 arms only on 16- or 32-bit targets; getrandom 0.4.3 `src/backends.rs` takes `getentropy` for `target_os = "macos"` after arms that need a `getrandom_backend` cfg, and `getentropy.rs` loads only `utils/get_errno.rs`; getrandom 0.2.17 `src/lib.rs` takes `util_libc` and `getentropy.rs` for `target_os = "macos"`. Each gate gives the same answer on both Mac targets, and nothing in `.cargo/`, the two workspace manifests or `fuzz/` sets any of these cfgs or a `RUSTFLAGS`. This agrees with the module probes of the Builder (section 2) and Checker 1 (section 14).

### 16.7 AT-B01 known answers on the copies, in release

`cargo test --offline --locked --release --no-fail-fast -p app-crypto` (sandbox, empty cargo home): exit 0, **171 passed, 0 failed, 10 ignored**: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. Among them: `kdf::tests::version_0x10_with_secret_known_answers`, `ssh::tests::sign_ed25519_rfc8032_test_1`, `ssh::tests::sign_p256_rfc6979_sample`, `sha256_fips_180_4_vectors`, `sha512_fips_180_4_vectors`, `sha1_fips_180_4_vectors`, `chacha20_rfc8439_vectors`, `salsa20_estream_vectors_cry01_t24`, `r5_rfc4648_known_answers` and F-134's `f_134_damaged_speed_record_is_measured_again`. The TLS tests over ring (16.1) passed too.

### 16.8 The name guard

On the copy before these records: `scripts/check-names.sh --self-test` self-test PASS, and `names: PASS (9730 files scanned, 16 vault files name-only)`. With these records, on the copy and on the shared tree: 16.10.

### 16.9 The Mac app still builds

- `scripts/build-core.sh` (sandbox, empty cargo home, offline and locked): exit 0, 46 s. It made `target/app-core/AppFFI.xcframework`, `Swift/AppCore.swift`, `include/AppFFI.h` and `include/module.modulemap` in the copy. The three generated files are byte-identical to steps 3d and 4a's: `AppCore.swift` `eeed94b4b5d0e29f3574723625ef3dd5d382426e705cac83f571a54ad3b6fdf9`, `AppFFI.h` `fb6e4e99f6ee…`, `module.modulemap` `03a0aa11cd38…`. The Swift interface did not change.
- `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e0s7s4b-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`, exit 0, 22 s, no code warning (only the destination note and two `appintentsmetadataprocessor` notes, "Metadata extraction skipped"). The only resolved package is the local one, `AppCore: …/macos/AppCore @ local`. No test was run, and no window was shown.

### 16.10 The shared tree

Right before these records (13:18): a read-only process list showed no `scripts/check.sh` and no cargo, rustc or xcodebuild run, and `diff -rq --no-dereference` of the shared tree against the copy (folders named `target` and `app-shots` left out) gave 0 lines. This file went to the shared tree with plain `cp` (after a `cmp` showed the shared file had not changed since the copy), and one exact append went to the E0-S7 status line in `plan/epics.md`. After both writes (13:20):
- `scripts/check-names.sh` on the shared tree: `names: PASS (10018 files scanned, 16 vault files name-only)`, exit 0; `--self-test`: self-test PASS, exit 0. On the copy with the same records: `names: PASS (9730 files scanned, 16 vault files name-only)`, exit 0.
- `scripts/check-vendor.sh` on the shared tree (sandbox): PASS, exit 0 (200 packages, 186 from vendor/crates-io; fuzz 99, 89; stubs 0; cut copies 70). Both lockfiles unchanged (`e23c677e…`, `d2758a2f…`).
- `diff -rq --no-dereference` of the shared tree against the copy, as above: 0 lines.

This paragraph was then filled in and the file copied again with plain `cp`; the name guard on the shared tree gave the same PASS afterwards.

### Notes, not findings

1. dependencies.md already has a "Step 4b done" section (section 17, the Builder's), so Verify did not add a second one. Its first line still says "Checker next." The lead updates it, as for steps 3c to 4a.
2. Checker 1's note 1 holds: ghash 0.6.0's `tests/` and `benches/` hold 1,341 bytes and its list 1,147, so its cut would save about 0.4 KB, not grow `vendor/`; for cfg-if (296 bytes against a 1,353-byte list), ecdsa (369 against 1,670) and rustls (624 against 10,865) the reason holds. Keeping all four whole is right. Checker 1's note 2 and Checker 2's note 1 (plan/architecture.md wording) are records only and change no check.
3. Not run here: `scripts/check.sh` (the lead's run; no package left, so it needs no `cargo clean` first, LD-257 (2); ring's build script runs once more on the first build, section 12 note 3), cargo deny and cargo audit (section 8's run; no Check of this step), the same-bytes builds (section 9), the `app09` test binary run (it starts App.app; check.sh G2) and the Xcode tests (build-for-testing only, as the brief says).
4. x86_64 still has no real build (no x86_64 standard library here, and nothing may be downloaded). ring is covered by its build script run for x86_64 (16.6), the other copies by their gates and the two module probes.

### Clean-up

Every process Verify started ended; no `sshd` or `ssh-agent` was left. All `/tmp/e0s7s4b-verify-*` folders are deleted. `scripts/check.sh` was not run. No git command was run.
