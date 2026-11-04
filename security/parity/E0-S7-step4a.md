# E0-S7 step 4a: trims of libc, the objc2 bindings and regex-automata (2026-10-31)

Builder, 2026-10-31. Story E0-S7 follow-up (plan/epics.md; LD-259 (1), LD-261 (1)), batch 4a of spec/research/dependencies.md section 8 'Step 4: trims', items 1 to 3: non-crypto copies, whole files cut only. Checker next. No code line changed in any copy, no crypto copy was touched, and the compiled `app`, `libapp_ffi.a` and `libapp_hwkey.rlib` are byte-identical before and after (section 9).

Setup: a private copy of the shared tree (`/tmp/e0s7s4a-builder-copy`, `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots`) and a second one that holds the tree before the step (`/tmp/e0s7s4a-builder-base`); both lockfiles had the SHA-256 of step 3d (`7b5f1f52…`, `3994fd4a…`). The check-vendor mutants ran in a third copy (`/tmp/e0s7s4a-builder-mut`), restored by `rsync -a --delete` before each one. Target folders and new empty cargo homes under `/tmp`, `CARGO_NET_OFFLINE=true`, every cargo call `--offline`, and `--locked` except the one lockfile rewrite (section 4) and the mutants that rewrite a lock on purpose (B2 to B4). `RUSTUP_HOME` was the user's and `RUSTUP_AUTO_INSTALL=0`. Nothing was fetched: the published `.crate` files came from the local cargo cache and were unpacked under `/tmp` only. The cargo home of the test run held only `registry/CACHEDIR.TAG` and cargo's three cache-lock files at the end. The result went to the shared tree in one step (section 13).

## 1. What was cut

The rule for every item: a `.rs` file may go only when no build of App on aarch64-apple-darwin or x86_64-apple-darwin compiles it, with every feature any crate or copy turns on (section 2). Only `.rs` files went; license files, `Cargo.toml`, `build.rs`, docs and `tests/` stay. Each copy stays a plain directory copy in `vendor/crates-io` with a new `.cargo-checksum.json` and cargo vendor's list beside it as `.cargo-checksum.upstream.json` (step 2.3), and joins `cut_copies` in `scripts/check-vendor.sh`. None needs a `[patch]` path copy, because no file changed.

| Copy | Files (before to after) | `.rs` files cut | Rust lines (before to after) | Bytes (before to after) |
|---|---|---|---|---|
| libc 0.2.191 | 453 to 64 | 390 | 133,739 to 13,920 | 4,645,872 to 656,497 |
| objc2-foundation 0.3.2 | 240 to 80 | 161 | 78,448 to 21,203 | 2,998,938 to 875,990 |
| objc2-app-kit 0.3.2 | 310 to 20 | 291 | 116,524 to 9,228 | 4,740,246 to 599,958 |
| objc2-core-foundation 0.3.2 | 77 to 44 | 34 | 40,647 to 21,607 | 1,527,211 to 836,696 |
| objc2-io-kit 0.3.2 | 26 to 15 | 12 | 53,519 to 25,417 | 2,742,187 to 1,298,639 |
| regex-automata 0.4.18 | 108 to 98 | 11 | 68,447 to 53,757 | 2,743,406 to 2,168,051 |

(The counts after include the new upstream list.)

- **Item 1, libc**: every `.rs` file under `src/` that neither Mac target compiles, except the files under an `apple` folder. Gone: the modules of every other system (`src/unix/linux_like` 70 files, `src/new/glibc` 42, `src/unix/bsd/freebsdlike` and `netbsdlike` 41, `src/new/linux_uapi` 25, and the rest: Windows, WASI, Fuchsia, the BSDs, Solaris, Android, Haiku, Redox, VxWorks, QNX and others). Kept: the 48 files the Mac builds compile, `build.rs` (it reads no file, only environment variables and `rustc --version`), the Apple files only x86_64 compiles (`src/unix/bsd/apple/b64/x86_64/mod.rs`, `src/new/apple/xnu/i386/_mcontext.rs`, `src/new/apple/xnu/mach/i386/_structs.rs`), and `src/unix/bsd/apple/b32/mod.rs` (32-bit Apple: built by neither Mac target, but item 1 cuts only other systems).
- **Item 2, objc2-foundation, objc2-app-kit, objc2-core-foundation, objc2-io-kit**: every generated file (`src/generated/`) of a feature that no build turns on. Kept generated files: Foundation `NSArray`, `NSData`, `NSDictionary`, `NSError`, `NSFileWrapper`, `NSProcessInfo`, `NSSet`, `NSString`, `NSURL` and `mod.rs`; AppKit `NSPasteboard`, `NSPasteboardItem`, `mod.rs`; Core Foundation `CFArray`, `CFData`, `CFDate`, `CFDictionary`, `CFNumber`, `CFPlugInCOM`, `CFRunLoop`, `CFSet`, `CFString`, `CFURL`, `CFUUID`, `mod.rs`; IOKit `hid.rs`, `mod.rs`. These are exactly the features of the one feature set each crate has in every build (section 3).
- **Item 3, regex-automata**: the full-DFA engine of the features `dfa-build` and `dfa-search`, which App does not turn on (`src/dfa/accel.rs`, `automaton.rs`, `dense.rs`, `determinize.rs`, `minimize.rs`, `regex.rs`, `search.rs`, `sparse.rs`, `special.rs`, `start.rs`; `src/dfa/mod.rs`, `onepass.rs` and `remapper.rs` stay, since `dfa-onepass` is on), and `src/util/unicode_data/perl_word.rs`, its own word table, which is built only when `syntax` or `unicode-perl` is off (both are on: App takes the table from regex-syntax). The literal prefilter files (`src/util/prefilter/`) stay: they compile with the prefilter features off too, as stubs.
- **Item 3, a feature cut in regex-automata's Cargo.toml**: its optional dependency `aho-corasick` (the multi-literal prefilter, feature `perf-literal-multisubstring`), never on, as in step 2. Removed: the `[dependencies.aho-corasick]` table, the feature `perf-literal-multisubstring = ["dep:aho-corasick"]` and its entry in `perf-literal`, and the 3 weak entries `aho-corasick?/logging`, `aho-corasick?/perf-literal`, `aho-corasick?/std` (cargo keeps a package in the lockfile while a weak entry names it, step 3a). 10 lines removed, none added or changed. The copy's manifest already sets `unexpected_cfgs = "allow"`, so its `cfg(feature = "perf-literal-multisubstring")` code is simply off. With it, aho-corasick 1.1.5 (48 files, 20,937 Rust lines, 840,203 bytes) left both lockfiles and `vendor/crates-io` (section 4).

### Skipped, and why

- **regex-syntax 0.8.11, its Unicode tables: nothing to cut.** The normal builds take `std`, `unicode-case` and `unicode-perl`, but every test build takes all of them: proptest names regex-syntax with its default features, and Cargo unifies the features when dev-dependencies are built (`cargo tree -e features`: `regex-syntax v0.8.11 [default,std,unicode,unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment]` in the trees of the workspace, with all and with default features, and of app-core, both Mac targets; the fuzz workspace has no proptest and takes `[std,unicode-case,unicode-perl]`). proptest 1.12.0 names regex-syntax as an optional dependency without `default-features = false`, and its default `std` feature turns it on. So every file of `src/unicode_tables/` is compiled by `cargo test`. Of its 34 `.rs` files only `benches/bench.rs` (1,234 bytes, not a table) is never compiled. Cutting it would save nearly nothing, so the copy stays whole and stays a plain copy. Cutting the tables would need proptest's `regex-syntax` feature off (a manifest cut in a test tool, and our tests use its regex strategies), which is out of 4a's items.
- **regex-automata's `perf-literal-substring` (memchr)**: not cut. memchr 2.8.3 stays in the tree for quick-xml and others, so the cut would remove no file and no package, only one dependency name from regex-automata's lock entry.
- **objc2 hand-written files of features that are off** (Core Foundation `bundle.rs`, `error.rs`, `filedescriptor.rs`, `geometry.rs`, `timezone.rs`, `user_notification.rs`; IOKit `consumes_argument.rs`; 23 KB together): kept, because item 2 names the generated files. They are never compiled either, and can go in a later batch if the lead wants.
- `tests/` and `benches/` of the six copies: kept (not in items 1 to 3; for crypto copies they are step 4 item 5).

## 2. Proof that the cut files are never compiled

- **aarch64-apple-darwin, the real builds.** In the private copy before the cut, with one target folder: `cargo build --workspace --all-targets --all-features`, the same with default features, `--release -p app-ffi --features net` (as build-core.sh), `--release -p app-cli -p app-hwkey`, `--release --workspace --all-targets --all-features`, and `cargo check --manifest-path fuzz/Cargo.toml --bins`. The union of every file that their 1,199 dep-info files (`*.d`, build scripts included) name is the compiled set: libc 49 files (with `build.rs`), objc2-foundation 26, objc2-app-kit 4, objc2-core-foundation 29, objc2-io-kit 4, regex-automata 61, regex-syntax 33. All are `.rs` files (no `include_str!` of a doc file). The cut list is every other `.rs` file of section 1's rule: 899 files, none in that union.
- **x86_64-apple-darwin, a module probe.** No x86_64 standard library is installed (nothing may be downloaded), so rustc cannot build for it. But rustc writes the dep-info (every module file it loads) before it needs the standard library's items. So each crate was run through `rustc --emit=dep-info --target <t>` with its exact features as `--cfg`, against placeholder `core`, `alloc`, `std` and `compiler_builtins` crates (each an empty `#![no_core]` crate, `RUSTC_BOOTSTRAP=1`, under `/tmp` only). The method was checked on aarch64 first: for each of the 6 copies (uncut) the probe gives exactly the file set of the real aarch64 builds. For x86_64 it gives the same set, except in libc, where it loads `xnu/i386/_mcontext.rs`, `xnu/mach/i386/_structs.rs` and `apple/b64/x86_64/mod.rs` in place of their `arm`/`aarch64` twins: all three are kept. 0 of the x86_64 files are in the cut list. On the cut copies, the probe for both targets reports no missing module file (0 E0583). Control: the cut libc with `apple/b64/x86_64/mod.rs` removed gives `error[E0583]: file not found for module x86_64` for x86_64 only.
- **The gates, read from the source.** For each of the 572 cut files that a compiled file names in a `mod` item, the attribute above it is one `#[cfg(feature = "…")]` of a feature that is off (objc2: all of them; regex-automata `perl_word.rs`: `all(feature = "unicode-word-boundary", not(all(feature = "syntax", feature = "unicode-perl")))`) or, in libc, a `cfg_if!` branch on `target_os`, `target_env` or `target_vendor`, which are the same on both Mac targets (`target_vendor = "apple"`, `target_os = "macos"`, `target_env = ""`). Among these gates the only `target_arch` and `target_pointer_width` ones are libc's Apple ones above; the probe covers the rest. The other 327 cut files are named only by cut files, or by none. No compiled file has a `#[path]` attribute or an indented out-of-line `mod` that the check could have missed.
- **Fuzzing (nightly).** `cargo +nightly fuzz build` (the sanitizer build of check.sh's smoke): 23 targets built from the cut tree, exit 0, 29 s. None of the six copies has a `cfg(fuzzing)`.

## 3. Features: no feature set changed

`cargo tree --offline --locked -e features,normal,build,dev --prefix none -f '{p} [{f}]'`, sorted, for aarch64-apple-darwin and x86_64-apple-darwin, in 9 forms: the workspace with all features, the workspace with default features, `-p app-ffi --features net`, `-p app-ffi`, `-p app-cli`, `-p app-hwkey`, `-p app-core`, `-p app-platform --features net`, and the fuzz workspace with all features. All 18 outputs are byte-identical before and after (919, 879, 651, 591, 453, 359, 452, 142 and 391 lines on aarch64; 921, 881, 653, 593, 477, 383, 476, 142 and 415 on x86_64). Each of the six copies has one feature set in every form and on both targets: libc `[std]` or `[default,std]` (`default = ["std"]`), objc2-foundation `[NSArray, NSData, NSDictionary, NSError, NSFileWrapper, NSProcessInfo, NSSet, NSString, NSURL, alloc, bitflags, std]`, objc2-app-kit `[NSPasteboard, NSPasteboardItem, alloc, bitflags, std]`, objc2-core-foundation `[CFArray, CFData, CFDate, CFDictionary, CFNumber, CFPlugInCOM, CFRunLoop, CFSet, CFString, CFURL, CFUUID, alloc, bitflags, std]`, objc2-io-kit `[alloc, bitflags, hid, std]`, regex-automata `[alloc, dfa-onepass, hybrid, meta, nfa-backtrack, nfa-pikevm, nfa-thompson, perf-inline, std, syntax, unicode-case, unicode-perl, unicode-word-boundary]`. aho-corasick was in no tree before (nothing built it since step 3a).

## 4. Lockfiles

One offline rewrite by cargo (`cargo metadata --offline --format-version 1`, root and fuzz) after the manifest cut. Removals only, 10 lines in each lockfile, nothing added, no path package added, no other entry changed:

| Lockfile | Entries | Registry | SHA-256 after |
|---|---|---|---|
| Cargo.lock | 201 to 200 | 187 to 186 | `e23c677e…` |
| fuzz/Cargo.lock | 100 to 99 | 90 to 89 | `d2758a2f…` |

Each lost the aho-corasick 1.1.5 entry (9 lines) and the name `aho-corasick` in regex-automata's dependency list. Every build and test run afterwards left both lockfiles byte-identical (`cmp`). `vendor/crates-io`: 190 to 189 copies (`aho-corasick-1.1.5` removed). `cargo metadata`: 200 packages, 186 from vendor/crates-io; fuzz 99, 89.

## 5. Diff against the published `.crate`

For each of the six copies: the `.crate` in `~/.cargo/registry/cache` has a SHA-256 equal to its Cargo.lock checksum and to the `package` value of both lists (libc `65cd87c9…`, objc2-foundation `e3e0adef…`, objc2-app-kit `d49e936b…`, objc2-core-foundation `2a180dd8…`, objc2-io-kit `33fafba3…`, regex-automata `ad8553b9…`). Before the cut each copy was byte-for-byte its `.crate` (only `.cargo-checksum.json` extra). After it, unpacked `.crate` against the copy:

- files only in the `.crate`: exactly that copy's cut list (390, 161, 291, 34, 12, 11);
- files that differ: none, except regex-automata's `Cargo.toml` (section 1, removals only);
- files only in the copy: `.cargo-checksum.json` and `.cargo-checksum.upstream.json`.

`.cargo-checksum.upstream.json` is the list cargo vendor wrote, unchanged; rebuilt from each `.crate` by step 2's method it is byte-identical. The new `.cargo-checksum.json` lists every file on disk (the upstream list included) in cargo's compact form with the same package checksum. When it was removed, aho-corasick-1.1.5 was byte-for-byte its `.crate` (`c982642f…`), but for the `.gitignore` that cargo vendor never copies.

## 6. scripts/check-vendor.sh

`cut_copies` gains the six copies (20 names) and rule 4's comment says that a cut copy may also lose whole files never compiled on a Mac. No rule changed: rule 4 already checks that a cut copy's list names only upstream files with their upstream hashes, and that no file on disk is unlisted, so a cut file cannot come back changed. PASS on the copy: `Cargo.toml: 200 packages, 186 from vendor/crates-io`, `fuzz/Cargo.toml: 99 packages, 89`, 0 stubs, `cut copies (checked against their upstream list): 20`, 2.6 s.

Mutants (one script, each in the mutant copy, restored before the next; `diff -rq --no-dereference` against the private copy at the end: 0 lines). 28 runs, none passes:

| Mutant | Result |
|---|---|
| N1, N2 (a `file://` git source under /tmp; nothing fetched), N6 | exit 101 |
| N3 zxcvbn from /tmp; L1 the log facade moved to /tmp (its workspace keys written out); B2, B3, B4 base64ct, base64, rustls from /tmp with the lock rewritten offline | FAIL, exit 1, `read from outside the tree` |
| B2a base64ct from /tmp, lock not rewritten | exit 101, `--locked` refuses to change the lock |
| N4 | FAIL, `symbolic links in the package folders` |
| N5 | FAIL, `stubs compiled: subtle-2.6.1` (both Mac targets) |
| M1, M2, M3 | FAIL, `not upstream beyond its cut` (src/scalar.rs, src/added.rs, the package checksum) |
| M4, X1, W1, W2, B1 | FAIL, `files not in its list` |
| X2, X3, X4, Y1, Y2 | FAIL, `targets outside their package or not a .rs file` (both workspaces) |
| Z1 | FAIL, `a cut copy without its upstream list` |
| Z2 | FAIL, `upstream lists in copies not named as cut: subtle-2.6.1` |
| **F1 (new, file cut)**: libc's cut `src/unix/linux_like/mod.rs` put back from the `.crate` with one code line added, and listed with its new hash | FAIL, exit 1, `vendor/crates-io/libc-0.2.191: not upstream beyond its cut: src/unix/linux_like/mod.rs` |
| **F2 (new, file cut)**: objc2-app-kit's cut `src/generated/NSAlert.rs` put back unlisted | FAIL, exit 1, `vendor/crates-io/objc2-app-kit-0.3.2: files not in its list: src/generated/NSAlert.rs` |

A cut file put back byte-for-byte with its upstream hash passes, as ring's `.pl` file does (step 2 section 4): it is upstream code, and rule 3's `.crate` diff (section 5) names it.

## 7. Build and tests (private copy, after the cut, a new target folder, an empty cargo home)

- `cargo build --offline --locked --workspace --all-targets --all-features`: exit 0, 77 s (every package compiled from the cut copies).
- `cargo test --offline --locked --workspace --no-fail-fast`: exit 0, 230 s. 2,460 passed, 0 failed, 63 ignored, in 105 result lines (104 test binaries; app-crypto's doc-tests report twice). Per binary (passed, ignored in brackets):
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
  - uniffi-bindgen: main 0.
- `cargo test --offline --locked -p app-platform --features net`: lib 44 (7), net_start 1, doc-tests 0.
- `cargo test --offline --locked -p app-ffi --features net`: 297 passed, 6 ignored (the binaries as above).
- `cargo test --offline --locked -p app-ffi --test app09 --no-run`: built (it runs App.app, which check.sh's G2 builds first).
- The release timed tests (check.sh's `test-release`): fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52; 250 passed, 0 failed, under load (the lead's check.sh was running at the same time for part of it).
- **AT-B01 in release**: `cargo test --offline --locked --release --no-fail-fast -p app-crypto`: 171 passed, 0 failed, 10 ignored: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7.
- `cargo build --release -p app-ffi --features net` and `-p app-cli`: exit 0. `cargo check --manifest-path fuzz/Cargo.toml --bins`: exit 0.
- `cargo fmt --all -- --check`, the fuzz fmt, and the three clippy steps of check.sh (`--workspace --all-targets`, `-p app-ffi --test app09`, `-p app-platform --features net --all-targets`, each `-D warnings`): exit 0.

## 8. Advisories and policy (offline)

`cargo deny --offline --locked check`: `advisories ok, bans ok, licenses ok, sources ok`, the same 2 warnings as before (2 versions of syn; the libfuzzer-sys exception not met in the root graph). deny-fuzz (deny.toml without its `app-platform/net` line): all ok. `cargo audit -n`: 200 crate dependencies, 1 allowed warning (as before), exit 0. `cargo audit -n -f fuzz/Cargo.lock`: 99, exit 0. audit-copies (ssh-key, zxcvbn): exit 0. deny.toml names none of the cut files or aho-corasick, so it needed no change.

## 9. Same compiled bytes

The tree before and the cut tree, each copied in turn to one path (`/tmp/e0s7s4a-builder-same`), each built with a new target folder and an empty cargo home (`--release`, `SOURCE_DATE_EPOCH=1793232000`, `ZERO_AR_DATE=1`): `app` (`-p app-cli`) `7ded5e87…`, `libapp_ffi.a` (`-p app-ffi --features net`, as build-core.sh) `3333540b…` and `libapp_hwkey.rlib` `e00b56ae…`, the same SHA-256 from both trees. So App.app's Rust core, the `app` tool and the hardware-key crate compile to the same bytes; only files no build reads are gone.

## 10. Bill of materials

`scripts/make-sbom.sh` on the tree before and after, each with an empty cargo home: `128 components, 103 license texts, 12 crates without a license file` both times, and `sbom.cdx.json` (`8fcd9714…`), `THIRD-PARTY-NOTICES.md` (`8ad15778…`) and `rust-std-COPYRIGHT.html` (`5647be07…`) byte-identical. No component changes: the six cut copies keep their name, version, license, license files and Cargo.lock checksum (the published `.crate`'s; the copy differs from it only by the cut files and regex-automata's manifest lines), and aho-corasick was no component (nothing ships it since step 3a). The pedigree note for cut copies (LD-254 (3)) is still not written: section 12.

## 11. Size

| | Before | After | Removed |
|---|---|---|---|
| vendor/ files | 8,130 | 7,189 | 941 |
| vendor/ bytes (sum of file sizes) | 84,126,480 | 70,324,248 | 13,802,232 |
| vendor/ lines (`wc -l`, every file) | 2,406,837 | 2,038,237 | 368,600 |
| Rust lines in vendor/ (`wc -l` of every .rs) | 1,920,953 | 1,553,824 | 367,129 |
| vendor/ on disk (`du -sh`) | 99 MB | 84 MB | 15 MB |
| vendor/crates-io packages | 190 | 189 | 1 |

The 941 files are the 899 cut `.rs` files (346,192 lines, 12,992,021 bytes) and aho-corasick's 48 files (22,398 lines, 840,203 bytes), less the 6 new upstream lists. Bytes: those files hold 13,832,224; the lists add 29,992 net (6 upstream lists added, the 6 new lists shorter; regex-automata's manifest lost its 10 lines).

## 12. Notes for the lead

1. **regex-syntax was skipped** (section 1): every table is compiled in the test builds through proptest's default features. If the tables should go, a later batch would turn proptest's regex strategies off or give proptest `default-features = false` without `regex-syntax`, and our property tests would need string strategies without regexes.
2. **LD-254 (3), the CycloneDX pedigree note for cut copies, is still open.** The bill of materials stayed byte-identical in 4a; with it, 20 cut copies would get a note.
3. **LD-257 (2)**: aho-corasick left the tree; start the next scripts/check.sh with `cargo clean --offline --profile dev`, as after every step that removes a package.
4. Seen, not changed: `security-framework = "=3.7.0"` is still pinned in the root `[workspace.dependencies]` and named in the approved-crates row "macOS APIs", but no crate uses it and it is in no lockfile since step 1 (like the `data-encoding` pin of F9).
5. Two Checkers are not needed by team.md's rule: no crypto, format, `unsafe` or secret-handling code changed (no code changed at all, section 9). The lead decides.
6. No new finding.

## 13. The shared tree

Before the apply (09:56): a read-only process list showed no `scripts/check.sh` and no cargo run (the lead's check.sh run, which was going at 09:21, had ended). The shared tree still matched the base copy: both lockfiles, `scripts/check-vendor.sh`, `plan/architecture.md` and `spec/research/dependencies.md` byte-identical, the six copies and aho-corasick with 0 differences (`diff -rq`), and no step 4a proof file. Only `plan/epics.md` had changed since the base, by the lead's note at the end of the E0-S7 status line (kept: this step appends after it), and `fuzz/artifacts/json_reader` was new (not this step's; left as it is).

In one step, with plain `cp` (no `-p`, so each file's time is the apply's, LD-261 (2)): the 899 cut files deleted and their emptied folders removed; the six new `.cargo-checksum.json` and `.cargo-checksum.upstream.json` and regex-automata's `Cargo.toml` copied in; `vendor/crates-io/aho-corasick-1.1.5` removed; both lockfiles, `scripts/check-vendor.sh` (its mode stays `rwxr-xr-x`), `plan/architecture.md`, `spec/research/dependencies.md` and this file copied in. Then `diff -rq --no-dereference` of `vendor/` against the private copy: no difference; `cmp` of each copied file: equal. Last, one exact append to the E0-S7 status line in `plan/epics.md`.

On the shared tree afterwards, with a new empty cargo home and a new target folder under /tmp:
- `cargo build --offline --locked --workspace --all-targets --all-features`: exit 0, 1 min 12 s; `cargo build --offline --locked -p app-platform --features net`: exit 0; `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins`: exit 0. The cargo home then held only `registry/CACHEDIR.TAG` and cargo's three cache-lock files; both lockfiles kept `e23c677e…` and `d2758a2f…`.
- `scripts/check-vendor.sh`: PASS (`Cargo.toml: 200 packages, 186 from vendor/crates-io`; fuzz 99, 89; 0 stubs; 20 cut copies).
- `scripts/check-names.sh`: `names: PASS (10415 files scanned, 16 vault files name-only)`; `--self-test`: PASS.

scripts/check.sh was not run (the lead runs it; LD-257 (2): start with `cargo clean --offline --profile dev`, since aho-corasick left).

## 14. Checker 1, round 1 (2026-10-31): passed

Setup: a private copy of the shared tree after the apply (`/tmp/e0s7s4a-checker1-copy`, `rsync -a` with the anchored excludes); at the end, `diff -rq --no-dereference` of the shared tree against it (target folders and `app-shots` left out): 0 lines. A second copy holds the tree before the step, made again from the published files: the six copies unpacked from their `.crate` with their kept upstream list as `.cargo-checksum.json`, aho-corasick 1.1.5 unpacked from its `.crate` (less `.gitignore`), then one offline lockfile rewrite by cargo (`Adding aho-corasick v1.1.5`): `Cargo.lock` `7b5f1f52…` and `fuzz/Cargo.lock` `3994fd4a…`, the hashes of step 3d. Its `vendor/` has the size of section 11 before (8,130 files, 84,126,480 bytes, 2,406,837 lines). Every run had a new empty cargo home, `CARGO_NET_OFFLINE=true`, the user's `RUSTUP_HOME` and `RUSTUP_AUTO_INSTALL=0`. Nothing was fetched.

- **Build and tests** (the copy, a new target folder, an empty cargo home that held only `registry/CACHEDIR.TAG` and cargo's cache-lock files at the end; both lockfiles unchanged after, `e23c677e…`, `d2758a2f…`): `cargo build --offline --locked --workspace --all-targets --all-features` exit 0, 74 s. `cargo test --offline --locked --workspace --no-fail-fast` exit 0: 2,460 passed, 0 failed, 63 ignored in 105 result lines; the count of every binary is the one in section 7. `-p app-platform --features net`: lib 44 (7 ignored), net_start 1, doc-tests 0. `-p app-ffi --features net`: 297 passed, 6 ignored: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0. `--test app09 --no-run`: built. Release timed tests: fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52. AT-B01 in release (`-p app-crypto`): 171 passed, 0 failed, 10 ignored: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `cargo fmt --all -- --check`, the fuzz fmt, the three clippy steps of check.sh with `-D warnings` and `cargo check --manifest-path fuzz/Cargo.toml --bins`: exit 0.
- **Lockfiles, before against after**: removals only, 0 lines added. Each lost the aho-corasick 1.1.5 entry (9 lines) and the name `aho-corasick` in regex-automata's entry. `Cargo.lock` 201 entries to 200 (registry 187 to 186), `fuzz/Cargo.lock` 100 to 99 (90 to 89). `vendor/crates-io`: 190 folders to 189; only `aho-corasick-1.1.5` is gone.
- **The removed package is in no tree**: `cargo tree --offline --locked -e normal,build,dev --all-features --workspace` for aarch64-apple-darwin and x86_64-apple-darwin, root and fuzz, before and after: aho-corasick in none. `cargo tree -e features,normal,build,dev` in 10 forms (the 9 of section 3 and the fuzz workspace with default features) plus check-vendor's two package lists, both targets: 24 outputs equal before and after, once the tree's own path is written the same.
- **Lists of the six copies**: every file on disk but the list itself is listed with its right SHA-256, no listed file is missing, and the package value is the SHA-256 of the `.crate`. `.cargo-checksum.upstream.json` is beside each, is listed, and is byte-for-byte the list made again from the `.crate`. Against the `.crate`: only the cut files are missing (390, 161, 291, 34, 12, 11) and only regex-automata's `Cargo.toml` differs (10 lines removed, 0 added; no code line). All 189 copies against their `.crate`: the plain copies lack only `.gitignore` and `.gitattributes`, ring only its `.pl` file of step 1, and the 14 copies of step 2 differ only in `Cargo.toml`. So no crypto copy changed in 4a.
- **Never compiled, my own probe**: `rustc --emit=dep-info` of each copy with its feature set, against empty `#![no_core]` placeholder crates, debug assertions off and on. On aarch64 the probe of the uncut copies gives exactly the files that my build's dep-info names, for all six. On x86_64 the sets are the same, except libc's 3 Apple x86 files in place of their arm twins (all kept); 0 probe files are in a cut list; the probe of the cut copies gives the same sets with 0 E0583. No compiled file uses `include!` (only objc2-foundation's test module and regex-automata's doc comments do); `cfg(doc)` is only in cut Linux files, and no script runs `cargo doc`.
- **Same bytes**: the tree before and the cut tree, each in turn at one path, release, `SOURCE_DATE_EPOCH=1793232000`, `ZERO_AR_DATE=1`: `app` `40612a07…`, `libapp_ffi.a` (`net`) `bc08f67c…`, `libapp_hwkey.rlib` `776e69d1…`, equal from both trees.
- **Bill of materials**: `scripts/make-sbom.sh` on both trees: 128 components, 103 license texts; `sbom.cdx.json` `8fcd9714…`, `THIRD-PARTY-NOTICES.md` `8ad15778…`, `rust-std-COPYRIGHT.html` `5647be07…`, the same from both and the same as section 10.
- **Size**: measured on both trees, the numbers of section 11 (7,189 files, 70,324,248 bytes, 2,038,237 lines, 1,553,824 of Rust after; 99 MB to 84 MB).
- **Guards**: `scripts/check-vendor.sh` PASS (200 packages, 186 from vendor/crates-io; fuzz 99, 89; 0 stubs; 20 cut copies). `scripts/check-names.sh` PASS on the copy (10,127 files) and on the shared tree (10,415 files); `--self-test` PASS.
- **Mutants of check-vendor** (my own script, made from section 6 and the step 2, 3b and 3d records; the mutant copy restored by `rsync -a --delete` before each, `diff -rq` 0 lines at the end): 28 runs, none passes. N1 exit 101 (no package `cfg-if`); N2 exit 101 (offline mode, nothing fetched); N3 FAIL, `read from outside the tree: zxcvbn 3.1.1`, also with the path written through `..`; N4 FAIL, symbolic links; N5 FAIL, `stubs compiled: subtle-2.6.1` (both targets, both workspaces); N6 exit 101 (no package `regex-syntax`); M1, M2, M3 FAIL, `not upstream beyond its cut` (`src/scalar.rs`, `src/added.rs`, the package checksum); M4, X1 FAIL, `files not in its list`; X2, X3, X4, Y1, Y2 FAIL, `targets outside their package or not a .rs file`; Z1 FAIL, `a cut copy without its upstream list`; Z2 FAIL, `not named as cut: subtle-2.6.1`; W1, W2 FAIL, `files not in its list: build.rs`; L1 FAIL, `read from outside the tree: log 0.4.999`; B1 FAIL, `files not in its list: src/added.rs`; B2a exit 101 (`--locked`); B2, B3, B4 FAIL, `read from outside the tree` (base64ct, base64, rustls); F1 FAIL, `libc-0.2.191: not upstream beyond its cut: src/unix/linux_like/mod.rs`; F2 FAIL, `objc2-app-kit-0.3.2: files not in its list: src/generated/NSAlert.rs`. Four more of my own: F3, regex-automata's cut `src/dfa/dense.rs` put back with one line added and listed: FAIL, `not upstream beyond its cut`; F4, objc2-foundation's cut `NSCalendar.rs` put back byte-for-byte and listed: PASS (upstream code, as section 6 says); F5, aho-corasick's folder put back without a list: exit 101; F5b, the same with a right list: PASS (note 1).

Notes, not send-backs:

1. check-vendor does not check that `vendor/crates-io` holds only packages that a lockfile names: a removed package's folder put back with a right list passes (F5b). Cargo never compiles such a folder, and in 4a the folder is gone (checked above). Step 5 could add the rule, with F5b as its mutant.
2. libc and the four objc2 copies keep their upstream `Cargo.toml`, but as cut copies rule 4 now exempts it. Before 4a they were plain copies, which rule 4 does not compare with upstream at all, so no check is weaker. Optional later: also compare `Cargo.toml` with upstream for cut copies whose manifest was not cut.
3. x86_64 is proven by two separate probes (the Builder's and mine), not by a build. The first real x86_64 build (the E14 x86_64 slice) covers it.
4. No code line changed and the compiled bytes are equal, so this is not a crypto or `unsafe` change by plan/team.md; the lead decides on a second Checker.

No new finding. Verify (or Checker 2) next.

## 15. Checker 2 (2026-10-31): passed

Scope: the crypto copies (plan/team.md: crypto changes get two Checkers). The research table (dependencies.md section 7) marks 73 packages crypto, key or support. 69 of them are copies in `vendor/crates-io`; des and fiat-crypto left in step 2, rustls-platform-verifier was replaced (LD-247 (2)), and ssh-key is the path copy `vendor/ssh-key` (LD-209). Batch 4a touches none of them: its six copies (libc, the four objc2 bindings, regex-automata) and aho-corasick are all "no" in that column.

Setup: a private copy of the shared tree (`/tmp/e0s7s4a-checker2-copy`, `rsync -a` with the anchored excludes) and a second one that holds the tree before the step (`/tmp/e0s7s4a-checker2-base`): the six copies unpacked again from their `.crate` with their kept upstream list as `.cargo-checksum.json`, aho-corasick 1.1.5 unpacked from its `.crate` (less `.gitignore`) with a list made as cargo vendor makes it, then one offline lockfile rewrite (`Adding aho-corasick v1.1.5`, twice). Its lockfiles have the hashes of step 3d, `7b5f1f52c1c3e8f8…` and `3994fd4ad38800e9…`. New empty cargo homes, `CARGO_NET_OFFLINE=true`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`. The `.crate` files came from the local cargo cache and were unpacked under `/tmp` only. Nothing was fetched.

- **Each crypto copy against its `.crate`** (69 copies, 2,220 files): for every copy, the SHA-256 of the `.crate` = the `Cargo.lock` checksum = the `package` value of its `.cargo-checksum.json`. `diff -rq` against the unpacked `.crate`: 64 copies have no difference but the `.gitignore` and `.gitattributes` that cargo vendor leaves out and the checksum lists. The other 5 are the cut copies of steps 1 and 2. In them only `Cargo.toml` differs, plus ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (cut in step 1, LD-247 (4)). No code file differs and no file was added.
- **The 5 manifest cuts, lines removed and added**: curve25519-dalek 5.0.0, 4 and 0 (the `cfg(curve25519_dalek_backend = "fiat")` table of fiat-crypto); getrandom 0.2.17, 5 and 0 (the `cfg(target_os = "wasi")` table of wasi and the `wasi/rustc-dep-of-std` entry of `rustc-dep-of-std`); getrandom 0.4.3, 4 and 0 (the `cfg(all(target_os = "uefi", getrandom_backend = "efi_rng"))` table of r-efi); ring 0.17.14, 7 and 0 (the aarch64 Windows table of windows-sys 0.52); ssh-cipher 0.3.0, 7 and 0 (the `tdes` feature, its `des?/zeroize` entry and the optional `des` dependency). Only feature entries and target tables. Each of these files has the time 2026-10-30 18:56:59 (step 2).
- **The lists**: my own script made each list again from the unpacked `.crate`. For the 64 plain copies, `.cargo-checksum.json` is that list, and it matches the files on disk. For the 5 cut copies, `.cargo-checksum.upstream.json` is that list, it names the same package, and the new list matches the disk. Against upstream, only `Cargo.toml` changed (and ring's one cut file). 0 errors.
- **Not touched in 4a**: in `vendor/`, only 13 files have a time after 2026-10-31 00:00: the two lists of each of the six copies and regex-automata's `Cargo.toml`, all at the apply (09:56). The newest file of any crypto copy is from 2026-10-30 18:56:59. The newest file of `vendor/ssh-key` is from 2026-10-29 20:43:04. `diff -rq` of `vendor/` before and after: only the six copies and the folder `aho-corasick-1.1.5` differ. The lockfiles, before and after: 0 lines added, and only the aho-corasick entry and its name in regex-automata's entry are removed.
- **Cut tables never selected on a Mac**: `cargo tree --offline --locked -e features,normal,build,dev --prefix none --no-dedupe` for aarch64-apple-darwin and x86_64-apple-darwin, in 4 forms (workspace with all features, workspace with default features, app-ffi with `net`, the fuzz workspace with all features). All 8 outputs are byte-identical before and after (aarch64 `c4eab5a1`, `32211beb`, `55edac2d`, `d66ab005`; x86_64 `2d45656e`, `d54e93a1`, `8b47c2c9`, `d5625830`). None of them names windows-sys, windows-targets, wasi, fiat-crypto, r-efi, des or aho-corasick. On both targets the crypto copies get the same features: ring `alloc`, `default`, `dev_urandom_fallback`; ssh-cipher `aes`, `chacha20poly1305`, `default`, `encoding`, `rand_core`, `zeroize` (no `tdes`); curve25519-dalek `digest`, `zeroize`; getrandom 0.2.17 `default` and getrandom 0.4.3 `default`, `std`, `sys_rng` (no `rustc-dep-of-std` in either); cpufeatures `default`. The two custom cfgs `curve25519_dalek_backend` and `getrandom_backend` are set nowhere in the tree: not in `.cargo/config.toml`, `Cargo.toml`, `fuzz/Cargo.toml`, `crates/` or `scripts/`. curve25519-dalek's build script picks fiat only when that cfg is given.
- **libc under the crypto copies**: on a Mac, getrandom 0.2.17 and 0.4.3 call libc for `getentropy`, `__error`, `EINTR`, `c_int`, `c_void` and `ssize_t`. On aarch64 only, cpufeatures and ring call it for `sysctlbyname`, `c_char`, `c_ulong` and `c_void` (their libc tables are aarch64-and-Apple only). Each of these is declared in a kept file that both Mac targets compile: `lib.rs`, `primitives.rs`, `unix/mod.rs`, `unix/bsd/mod.rs` or `unix/bsd/apple/mod.rs`. None is declared only in an architecture file. No file under an Apple path of libc was cut, no kept libc file differs from the `.crate`, and `unix/bsd/apple/b64/mod.rs` picks `x86_64` or `aarch64`, both kept.
- **Known answers and TLS** (the copy, a new target folder, an empty cargo home that held only `registry/CACHEDIR.TAG` and cargo's cache-lock files at the end): AT-B01 in release, `cargo test --offline --locked --release -p app-crypto`: 171 passed, 0 failed, 10 ignored. Per binary: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `cargo test --offline --locked -p app-platform --features net` (TLS over ring and getrandom 0.2, local server only): lib 44 passed (7 ignored), among them `sn03_good_certificate_from_test_anchor_works`, `sn03_bad_certificates_refused` and `ld247_handshake_signed_with_another_key_refused`; net_start 1; doc-tests 0. `scripts/check-vendor.sh` on the copy: PASS (20 cut copies; fuzz 99 packages, 89 from vendor/crates-io; 0 stubs).

Notes, not send-backs:

1. The table marks libc "no", but on a Mac it gives getrandom its `getentropy` call and gives cpufeatures and ring their CPU check. The cut keeps all of these (above), and the Builder and Checker 1 show the same compiled bytes. A later trim of libc (for example b32) needs the same check.
2. x86_64 has no real build here (no x86_64 standard library and no `rust-src`). It is covered by the two module probes of the Builder and Checker 1 and by the source check above.

No new finding. Verify next.

## 16. Verify (2026-10-31): signed

Verdict: **signed**. Every E0-S7 check that step 4a covers passed again in a private copy: the offline locked build and every test with an empty cargo home, check-vendor failing on each source outside the tree, the bill of materials with the same components and checksums, every copy against its published `.crate` (the crypto copies with only the cuts on record), AT-B01 in release, the name guard, `scripts/build-core.sh` and `xcodebuild build-for-testing`. The Verify agent did not build or check this step, and it changed no product file. No new finding (the next free number is still F-137).

Setup: a private copy, `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots` (`/tmp/e0s7s4a-verify-copy`, made at 10:37; `diff -rq --no-dereference` against the shared tree: only the three excluded folders; Cargo.lock `e23c677e…`, fuzz/Cargo.lock `d2758a2f…`). The tree before, made again in `/tmp/e0s7s4a-verify-before` from the published files: the six copies and aho-corasick 1.1.5 written from their `.crate` in the local cargo cache by a small reader (python3 -I; each archive member checked first: a plain file inside its package folder, no absolute or `..` path; `.gitignore` and `.gitattributes` left out, as cargo vendor does), each with the list cargo vendor writes, then one offline lockfile rewrite for the root and one for fuzz (`Adding aho-corasick v1.1.5`): Cargo.lock `7b5f1f52c1c3…` and fuzz/Cargo.lock `3994fd4ad388…`, the hashes of step 3d. A mutant copy (`/tmp/e0s7s4a-verify-mut`) was restored by `rsync -a --delete` before each mutant; `diff -rq --no-dereference` against the private copy at the end: 0 lines. Target folders under /tmp, a new empty cargo home per run, a throwaway `HOME`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. Every cargo call was `--offline --locked`, except the two lockfile rewrites of the tree before and the lock rewrites of mutants A1 to A3 (mutant copy only).

No network: every build and test run, fmt, clippy, the fuzz builds, check-vendor and its mutants, `cargo tree`, make-sbom.sh and build-core.sh ran through `sandbox-exec` with `(allow default)`, `(deny network-outbound (remote ip))`, one allowance for `localhost:*` and a deny on the resolver socket, as in steps 3a to 3d. Inside it, a socket to 192.0.2.1:443 gets "Operation not permitted", a name lookup fails, and a listener on 127.0.0.1 is reached. Outside it, still offline with an empty cargo home: the two tests that cannot run in a sandbox and the release fea06 run (16.1), the libc module probe (16.6), the name guard and xcodebuild, which does not start inside another sandbox. Each empty cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` afterwards. Both lockfiles kept their SHA-256 through every run.

### 16.1 Build and tests, offline and locked, with an empty cargo home

- `cargo build --offline --locked --workspace --all-targets --all-features -v` (sandbox): exit 0, 74 s. No line names `registry/src` or the cargo cache. 185 of the 189 folders of `vendor/crates-io` were compiled, the six cut copies among them; the other 4 are arbitrary, libfuzzer-sys and jobserver (fuzz workspace only) and curve25519-dalek-derive (x86_64 only).
- `cargo test --offline --locked --workspace --no-fail-fast` (sandbox): 105 result lines, 2,458 passed, 2 failed, 63 ignored, 225 s. The 2 failures are the sandbox, as in steps 2 to 3d: `fea06_29_offline_streams` (`ps` is refused, "Operation not permitted") and `t53_t57_ssh_signs_in_through_apps_socket` ("Allow Once: ssh signs in with App's key": macOS's `sshd-auth` starts its own sandbox). Each passes alone outside it (1 passed each; the test's throwaway ssh config with `IdentityFile=none` and App's own agent socket, LD-203 (6); no `sshd` or `ssh-agent` left afterwards). So 2,460 pass. Per test binary (ignored in brackets): app-autotype lib 3, int05 51, int05_match 38, int05_typing 14; app-cli main 16, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; app-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 84, fea09 25, fuzz_seeds 0 (13), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 26, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; app-crypto lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; app-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; app-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; app-hwkey lib 37, real_key 1 (1), watch 2; app-model lib 35; app-platform lib 31 (7), net_start 0; app-sshagent lib 22, agent 25, own_agent 38; log lib 1; uniffi-bindgen-swift main 0; the other doc-tests 0. These are the counts of section 7.
- `-p app-platform --features net` (sandbox): lib 44 passed (7 ignored), net_start 1, doc-tests 0. `-p app-ffi --features net` (sandbox): 297 passed, 6 ignored, 16 result lines: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0. `-p app-ffi --test app09 --no-run`: built.
- Release, timed tests (`--release -p app-core`): fea01 37, fea05 49, fea07 26, mod08 48, mod11 52 (sandbox) and fea06 38 (outside it, for `fea06_29`), 0 failed. No timing test failed, so none was run again.
- `cargo fmt --all -- --check`, the fuzz workspace's fmt, the three clippy steps of check.sh (`-D warnings`: the workspace with all targets, `-p app-ffi --test app09`, app-platform with `net` and all targets) and `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins` (sandbox): exit 0 each, no warning. `cargo +nightly fuzz build` (sandbox, its own target folder): exit 0, 30 s, 23 target binaries; `cargo +nightly fuzz list`: 23.

### 16.2 Lockfiles and features against the tree before

| Lockfile | Before | Now | Lines removed | Lines added | Entries gone |
|---|---|---|---|---|---|
| Cargo.lock | 201 (registry 187) | 200 (registry 186) | 10 | 0 | aho-corasick 1.1.5 |
| fuzz/Cargo.lock | 100 (registry 90) | 99 (registry 89) | 10 | 0 | aho-corasick 1.1.5 |

The 10 lines of each: the aho-corasick entry (its checksum `c982642f…` is the SHA-256 of its `.crate`) and the name `aho-corasick` in regex-automata's dependency list. `diff -rq --no-dereference` of `vendor/` before against now: only the six copies and the folder `aho-corasick-1.1.5` differ; `vendor/zxcvbn`, `vendor/ssh-key` and the other 183 copies are the same. No `Cargo.toml` in the tree names aho-corasick any more (crates/, both workspace manifests, `vendor/`, `deny.toml`).

`cargo tree --offline --locked -e features,normal,build,dev --prefix none -f '{p} [{f}]'`, sorted, the tree's own path written the same, for aarch64-apple-darwin and x86_64-apple-darwin, in 10 forms (the workspace with all and with default features, `-p app-ffi` with and without `net`, `-p app-cli`, `-p app-hwkey`, `-p app-core`, `-p app-platform --features net`, the fuzz workspace with all and with default features): all 20 outputs are byte-identical before and now. None names aho-corasick. Each cut copy has one feature set in every form and on both targets, the sets of section 3. regex-syntax has every Unicode feature in the forms that take proptest's dev edges (the workspace forms and app-core) and `[std,unicode-case,unicode-perl]` in the others: proptest 1.12.0's `std` feature names `regex-syntax`, which it takes without `default-features = false`. This confirms the Builder's reason to skip its tables.

### 16.3 A source outside the tree fails check-vendor

Each mutant was made in the mutant copy, run through check-vendor in the sandbox, then restored. Nothing was fetched: the `git` source of N2 names a folder that does not exist, and every run is offline. A1 to A3 and F6 are new; A1 to A3 bring an uncut or removed package of this step back from outside the tree.

| Mutant | Result |
|---|---|
| None | PASS, exit 0 (200 packages, 186 from vendor/crates-io; fuzz 99, 89; stubs 0; cut copies 20) |
| N1: a registry package not vendored (`cfg-if-1.0.5` moved out) | exit 101, `no matching package named cfg-if found` |
| N2: the root `[patch]` zxcvbn as a `git` source | exit 101, `failed to load source for dependency zxcvbn`, `can't checkout … you are in the offline mode` |
| N3: the root `[patch]` zxcvbn at a copy under /tmp | FAIL, exit 1: `read from outside the tree: zxcvbn 3.1.1: path at /tmp/e0s7s4a-verify-outside/zxcvbn/Cargo.toml` |
| N3b: the same path written as `vendor/../../…` | FAIL, exit 1, the same message with the resolved path |
| N4: a copy that is a link out of the tree (`subtle-2.6.1`) | FAIL, exit 1: `symbolic links in the package folders` |
| N6: no source replacement in `.cargo/config.toml` | exit 101, `no matching package named regex-syntax found` |
| N7: the replacement directory a copy of `vendor/crates-io` under /tmp | FAIL, exit 1: `read from outside the tree`, every registry package with its /tmp path |
| N10: the fuzz workspace's `[patch]` zxcvbn at a copy under /tmp | FAIL, exit 1: `fuzz/Cargo.toml: read from outside the tree: zxcvbn 3.1.1` |
| L1: `crates/log` moved to /tmp (its workspace keys written out), the patch pointed at it | FAIL, exit 1: `read from outside the tree: log 0.4.999` |
| A1 (new): libc 0.2.191 uncut, written from its `.crate` under /tmp, put in by the root `[patch.crates-io]`, both lockfiles rewritten offline | FAIL, exit 1: `read from outside the tree: libc 0.2.191: path at /tmp/…/libc-0.2.191/Cargo.toml` |
| A1a: the same, lockfiles not rewritten | exit 101, `--locked` refuses to change the lock |
| A2 (new): objc2-app-kit 0.3.2 uncut from /tmp the same way | FAIL, exit 1: `read from outside the tree: objc2-app-kit 0.3.2` |
| A3 (new): aho-corasick 1.1.5 from its `.crate` under /tmp as a path dependency of app-core, both lockfiles rewritten | FAIL, exit 1: `read from outside the tree: aho-corasick 1.1.5`, for Cargo.toml and fuzz/Cargo.toml |
| F1: libc's cut `src/unix/linux_like/mod.rs` back from the `.crate` with one line added, listed with its new hash | FAIL, exit 1: `libc-0.2.191: not upstream beyond its cut: src/unix/linux_like/mod.rs` |
| F2: objc2-app-kit's cut `src/generated/NSAlert.rs` back from the `.crate`, not listed | FAIL, exit 1: `objc2-app-kit-0.3.2: files not in its list: src/generated/NSAlert.rs` |
| F6 (new): objc2-foundation's kept `src/generated/NSString.rs` with one line added, listed with its new hash | FAIL, exit 1: `objc2-foundation-0.3.2: not upstream beyond its cut: src/generated/NSString.rs` |
| F5b (Checker 1's): the folder `aho-corasick-1.1.5` put back in `vendor/crates-io` with a right list | PASS, exit 0 (note 2) |

The other mutants of rule 4 (M, W, X, Y, Z, B) are sections 6 and 14's; check-vendor.sh changed only in its `cut_copies` list and one comment, so they were not run again here.

### 16.4 The bill of materials keeps the same components and checksums

`scripts/make-sbom.sh` ran on both trees (sandbox, empty cargo home, output under /tmp). Both print `128 components, 103 license texts, 12 crates without a license file`, and all three files are byte-identical before and now: `sbom.cdx.json` `8fcd9714…`, `THIRD-PARTY-NOTICES.md` `8ad15778…`, `rust-std-COPYRIGHT.html` `5647be07…` (the hashes of sections 10 and 14).

- 114 components carry a SHA-256, and each equals its Cargo.lock checksum. Every component has its license, except App's own crates and the `log` facade (App's own license is D2, the owner's).
- The six cut copies are components with their version, their license and the checksum of their `.crate`: libc 0.2.191 (MIT OR Apache-2.0), objc2-foundation 0.3.2 (MIT), objc2-app-kit, objc2-core-foundation and objc2-io-kit 0.3.2 (Zlib OR Apache-2.0 OR MIT), regex-automata 0.4.18 (MIT OR Apache-2.0); each ships in "App.app, app". aho-corasick is no component. Only zxcvbn and ssh-key carry `pedigree` (LD-254 (3) is still open).

### 16.5 Every copy against its published `.crate` (the diff proof, rule 3)

Every copy in `vendor/crates-io` was compared with its `.crate` from the local cargo cache, read from the archive in memory (each member checked as in the setup):

- 189 folders, exactly the registry entries of both lockfiles (none missing, none extra). For each, the archive's SHA-256 equals the lockfile checksum and the copy's `package` value.
- A list built from each `.crate` in cargo vendor's form is byte-for-byte `.cargo-checksum.json` for each of the 169 plain copies and `.cargo-checksum.upstream.json` for each of the 20 cut copies. The copies with an upstream list are exactly the 20 names of `cut_copies`. Every file on disk (6,927, the 209 lists aside) is in its list with the listed SHA-256, no listed file is missing, no copy has a symbolic link, and no copy holds a file that its `.crate` lacks.
- Files that differ from the `.crate`: 15, each the `Cargo.toml` of a copy in `cut_copies` (the 14 of step 2 and regex-automata). Only in the `.crate`, besides `.gitignore` and `.gitattributes`: the cut files of the six copies (libc 390, objc2-foundation 161, objc2-app-kit 291, objc2-core-foundation 34, objc2-io-kit 12, regex-automata 11; all `.rs` files under `src/`) and ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (step 1, LD-247 (4)). **No code file differs in any copy.**
- regex-automata's `Cargo.toml`: 216 lines to 206; the new file is the upstream file with 10 lines left out, nothing added or changed (a subsequence check): the 3 weak `aho-corasick?/…` entries, `perf-literal-multisubstring` in `perf-literal`, its own feature line and the 5 lines of `[dependencies.aho-corasick]`, as section 1 says.
- The crypto rows of the research table (yes, key, support): 69 are copies, none of them a copy this step cut. **64 of the 69 are byte-identical to their `.crate`.** The other 5 only lost manifest lines, nothing added or changed (the same subsequence check): curve25519-dalek 5.0.0 4, getrandom 0.2.17 5, getrandom 0.4.3 4, ring 0.17.14 7 (and its one `.pl` file), ssh-cipher 0.3.0 7. This is the table of step 3d's Verify (19.5) and of section 15.
- In the shared tree's `vendor/`, only 13 files are newer than 2026-10-31 00:00: the two lists of each of the six copies and regex-automata's `Cargo.toml` (09:56, the apply). No file of `vendor/ssh-key` or `vendor/zxcvbn` is among them.
- Size, measured on both trees: `vendor/` 8,130 files, 84,126,480 bytes, 2,406,837 lines (1,920,953 of Rust), 99 MB before; 7,189 files, 70,324,248 bytes, 2,038,237 lines (1,553,824 of Rust), 84 MB now; `vendor/crates-io` 190 copies to 189. These are section 11's numbers.

### 16.6 The cut files are never compiled on either Mac target

- **aarch64-apple-darwin**: the cut tree built in every form of 16.1 (debug and release, all and default features, app-ffi with `net`, build-core.sh, the fuzz check and the nightly fuzz build). A cut module that one of these builds needs would stop it with E0583.
- **x86_64-apple-darwin, libc (a third probe, after the Builder's and Checker 1's)**: `rustc --emit=dep-info --target <t>` of libc's `src/lib.rs` with the real build's features (`default`, `std`), against an empty `#![no_core]` placeholder `core` built for each target (`RUSTC_BOOTSTRAP=1`, under /tmp only). libc's `build.rs` sets no `cfg` for macOS on either target (its output in this build has only `rustc-check-cfg` lines; its source adds a `cfg` only for FreeBSD, Emscripten, VxWorks, Linux, musl, glibc, uClibc or the CI). On aarch64 the probe of the uncut libc names exactly the 48 `.rs` files that the dep-info of the real debug and release builds names. On x86_64 it names 48 too; they differ only in `src/new/apple/xnu/i386/_mcontext.rs`, `src/new/apple/xnu/mach/i386/_structs.rs` and `src/unix/bsd/apple/b64/x86_64/mod.rs` in place of their arm and aarch64 twins, and all three are kept. 0 probe files are in the cut list on either target, and the probe of the cut copy gives the same sets with 0 E0583.
- **The objc2 copies and regex-automata**: no out-of-line module in their `.crate` is gated on `target_arch`, `target_pointer_width` or `target_endian` (each `mod` item's attributes read by a script; in their `lib.rs` the only such `cfg`s are a type alias in objc2-foundation, a constant in objc2-app-kit and a `compile_error!` in regex-automata, none on a module). So their module set follows their features alone, and their features are the same on both Mac targets (16.2).

### 16.7 AT-B01 known answers on the copies, in release

`cargo test --offline --locked --release --no-fail-fast -p app-crypto` (sandbox, empty cargo home): exit 0, **171 passed, 0 failed, 10 ignored**: lib 48 (1), base64 7, cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `kdf::tests::version_0x10_with_secret_known_answers`, `ssh::tests::sign_ed25519_rfc8032_test_1`, `ssh::tests::sign_p256_rfc6979_sample`, `r5_rfc4648_known_answers` and F-134's `f_134_damaged_speed_record_is_measured_again` are among them. The TLS tests over ring (16.1, `net`: lib 44) passed too.

### 16.8 The name guard

- The copy before these records: `scripts/check-names.sh --self-test` self-test PASS, exit 0, and `names: PASS (10127 files scanned, 16 vault files name-only)`, exit 0.
- With these records, on the copy and on the shared tree: 16.10.

### 16.9 The Mac app still builds

- `scripts/build-core.sh` (sandbox, empty cargo home, offline and locked): exit 0, 47 s. It made `target/app-core/AppFFI.xcframework`, `Swift/AppCore.swift`, `include/AppFFI.h` and `include/module.modulemap` in the copy. The three generated files are byte-identical to the ones in the shared `target/app-core` (written at 09:26, before the apply) and to step 3d's (`AppCore.swift` `eeed94b4b5d0e29f3574723625ef3dd5d382426e705cac83f571a54ad3b6fdf9`, `AppFFI.h` `fb6e4e99…`, `module.modulemap` `03a0aa11…`): the Swift interface did not change.
- `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e0s7s4a-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`, exit 0, 22 s, no code warning (only the destination note and two `appintentsmetadataprocessor` notes, "Metadata extraction skipped"). The only resolved package is the local one, `AppCore: …/macos/AppCore @ local`. No test was run, and no window was shown.

### 16.10 The shared tree

Right before these records (11:03): a read-only process list showed no `scripts/check.sh` and no cargo, rustc or xcodebuild run. `diff -rq --no-dereference` of the shared tree against the copy (folders named `target` and `app-shots` left out) named only this file, and `vendor/` and `crates/` compared in full gave 0 lines; both lockfiles, both `Cargo.toml` files, `deny.toml`, `rust-toolchain.toml`, `clippy.toml` and `.cargo/config.toml` are equal (`cmp`). Since 09:00 the shared tree changed only in the files of section 13 (09:56), `security/parity/E0-S7-step3d.md` (09:12) and `spec/decisions.md` (09:15), both before the apply, and in this file and `plan/epics.md` (10:34, Checker 2's records). This file went to the shared tree with plain `cp` (after a `cmp` showed the shared file had not changed since the copy), and one exact append went to the E0-S7 status line in `plan/epics.md`.

After both writes:
- `scripts/check-names.sh` on the shared tree: `names: PASS (10415 files scanned, 16 vault files name-only)`, exit 0; on the copy with the same records: `names: PASS (10127 files scanned, 16 vault files name-only)`, exit 0.
- `scripts/check-vendor.sh` on the shared tree (sandbox): PASS, exit 0 (200 packages, 186 from vendor/crates-io; fuzz 99, 89; stubs 0; cut copies 20). Both lockfiles unchanged (`e23c677e…`, `d2758a2f…`).
- `diff -rq --no-dereference` of the shared tree against the copy, as above: 0 lines.

### Notes, not findings

1. dependencies.md already has a "Step 4a done" section (section 16, the Builder's), so Verify did not add a second one. Its first line still says "Checker next." The lead updates it, as for steps 3c and 3d.
2. Checker 1's note 1 holds (mutant F5b): a removed package's folder put back in `vendor/crates-io` with a right list passes check-vendor. Cargo never reads a folder that no lockfile names, the folder is gone here (16.5), and the gap is older than this step. Step 5 can add the rule with F5b as its mutant.
3. The regex-syntax skip holds (16.2). Its tables can go only if proptest's `regex-syntax` feature goes, which needs other string strategies in our property tests.
4. Not run here: `scripts/check.sh` (the lead's run; after this step it starts with `cargo clean --offline --profile dev`, LD-257 (2), since aho-corasick left), cargo deny and cargo audit (section 8's run; no Check of this step), the same-bytes builds (sections 9 and 14, two separate agents), the `app09` test binary run (it starts App.app; check.sh G2) and the Xcode tests (build-for-testing only, as the brief says).
5. x86_64 still has no real build (no x86_64 standard library here, and nothing may be downloaded): libc is covered by three separate probes, the other five copies by their features (16.6).

### Clean-up

Every process Verify started ended; no `sshd` or `ssh-agent` was left. All `/tmp/e0s7s4a-verify-*` folders are deleted. `scripts/check.sh` was not run. No git command was run.
