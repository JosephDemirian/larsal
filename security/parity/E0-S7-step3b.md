# E0-S7 step 3b: our own crates without thiserror and log

Builder, 2026-10-31. Story E0-S7 (plan/epics.md), batch 3b of step 3 (spec/research/dependencies.md section 8, LD-255 (3)): R4 thiserror and R6 log are built. R5 base64 and R8 getrandom 0.4 are not built: each stops at a rule, and the lead decides (section 6). Checker next.

Work was done in a private copy (`/tmp/e0s7s3b-builder-copy`, rule 11), proven there, then applied to the shared tree in one step after a read-only process list showed no `scripts/check.sh` run and every shared file to be changed was still the state the copy was made from (section 8). A second copy held the state before the step (`/tmp/e0s7s3b-builder-basecopy`) for the before and after runs, and a third one the check-vendor mutants (`/tmp/e0s7s3b-builder-mut`). Nothing left this Mac: `CARGO_NET_OFFLINE=true`, `RUSTUP_AUTO_INSTALL=0`, every cargo call `--offline`, and `--locked` except the one lockfile rewrite (section 3).

## 1. Files

| File | Change |
|---|---|
| `crates/larsal-crypto/src/error.rs` | `Error` (9 messages): hand-written `Display` and `std::error::Error` |
| `crates/larsal-format/src/error.rs` | `Error` (10), `KeyFileReason` (8), `HardwareKeyReason` (6): the same |
| `crates/larsal-core/src/error.rs` | `Error` (12) |
| `crates/larsal-core/src/import/mod.rs` | `JsonReason` (8), `ImportError` (28) |
| `crates/larsal-autotype/src/error.rs` | `Error` (17) |
| `crates/larsal-hwkey/src/lib.rs` | `Reason` (6) |
| `crates/larsal-sshagent/src/lib.rs` | `Error` (20) |
| `crates/larsal-platform/src/net.rs` | `NetError` (7) |
| `crates/larsal-ffi/src/session.rs` | `LarsalError` (9) |
| `crates/larsal-ffi/src/larsal_settings.rs` | `LarsalSettingsError` (4) |
| `crates/larsal-ffi/src/cli.rs`, `crates/larsal-cli/src/main.rs` | The two tests that compare larsal-crypto's dependencies with its crypto list (APP-09.4, INT-10.3) no longer skip `thiserror`: it is not there |
| `crates/*/Cargo.toml` (8) | `thiserror` gone from larsal-autotype, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-hwkey, larsal-platform (and from its `net` feature) and larsal-sshagent |
| `crates/log/Cargo.toml`, `crates/log/src/lib.rs` | New: Larsal's own `log` facade (section 2) |
| `Cargo.toml` | The `thiserror` pin gone (no crate uses it, as `data-encoding` in step 2); `[patch.crates-io] log = { path = "crates/log" }` with its note |
| `Cargo.lock`, `fuzz/Cargo.lock` | Rewritten by cargo offline (section 3) |
| `vendor/crates-io/` | `log-0.4.34` removed. `diff -rq` against the tree before: this one "Only in" line and nothing else, so no crypto copy and no other copy changed (rule 3 untouched) |
| `plan/architecture.md` | The approved-crates rows "Errors, data" and "HTTPS for opt-in features" |

13 enums, 144 messages, 13 `Display` and 13 `Error` impls. Diff size (lines out, in): larsal-crypto error.rs 10, 19; larsal-format error.rs 27, 54; larsal-core error.rs 13, 22; import/mod.rs 38, 60; larsal-autotype error.rs 18, 39; larsal-hwkey lib.rs 7, 16; larsal-sshagent lib.rs 21, 40; net.rs 8, 17; session.rs 10, 22; larsal_settings.rs 7, 17.

## 2. The replacements

- **R4 thiserror.** Each `#[error("...")]` text moved word for word into one arm of a `match self` in `impl std::fmt::Display`: a text with no placeholder is `f.write_str("...")` (`{{` and `}}` written as `{` and `}`, as `format!` would print them: MI05-11 `A { or } has no partner.`), a text with fields is `write!(f, "...")` with the same placeholders on the bound fields (`{0}` to `{v}`, `{0:?}` to `{v:?}`, named fields by name, and the extra arguments `path.display()` and `.0.name()` as `v.name()`); `Refused(v)` is `f.write_str(v)`. No variant used `#[from]`, `#[source]`, `#[error(transparent)]` or a field named `source`, so thiserror's `source()` was `None` for every one, and the empty `impl std::error::Error` keeps that. No `{0}` field is a `Path` or `PathBuf`, so thiserror's `.display()` rule for paths did not apply. uniffi's flat errors send `Display` to Swift; it is the same text.
- **R6 log.** `crates/log` (package `log`, version 0.4.999: meets ureq's `0.4.25`, ureq-proto's `0.4.22` and goblin's `0.4`, and is no published version, as Firefox's own crates in `build/rust` use x.999), in place of log 0.4.34 by `[patch.crates-io]`. Its API is what the callers use (grep of their `src/`): goblin `debug!` and `warn!` (by `use log::...` and `log::warn!`), ureq `debug!`, `trace!`, `warn!`, `log_enabled!` with `log::Level::Trace` and `log::Level::Debug` (by `#[macro_use] extern crate log` and `log::trace!`), ureq-proto `debug!` and `trace!`. Each message macro is `if false { let _ = format_args!(...); }`: the arguments are type-checked as in the published crate and never run. `log_enabled!` evaluates its level and is `false`. That is what the published crate did here: no crate in the tree calls `set_logger` (grep of `crates/`, `vendor/`), so its maximum level stayed `Off`, no message was formatted and `log_enabled!` was false. So ureq keeps redacting the `Location` header and the path in its debug output, as before. `#![forbid(unsafe_code)]`, `no_std` outside its test. As a workspace member it gets fmt, clippy, the unsafe count and the tests. Unit test `nothing_is_enabled_and_no_argument_is_evaluated`: both levels off, and a counter in the arguments of all three macros stays 0.

## 3. Lockfiles, copies and who still needs what

One rewrite: `cargo metadata --offline` for both workspaces, then `cargo update --offline -p log@0.4.34` (a `[patch]` with another version than the locked one is used only after that). Every later cargo call `--locked`.

- `Cargo.lock`: 202 entries, as before; registry 189 to 188. log 0.4.34 (crates.io) became the path package log 0.4.999: its `source` and `checksum` lines gone, its version line changed. The 8 dependency names `thiserror` of our crates gone. 11 lines out, 1 in (the new version line). No other entry changed.
- `fuzz/Cargo.lock`: 111 to 109 (registry 101 to 99), removals only (25 lines): thiserror 2.0.21, thiserror-impl 2.0.21 and 5 dependency names.
- The one path package added: `log` 0.4.999 (`crates/log`, Larsal's own code).
- `vendor/crates-io`: 192 to 191; both lockfiles' registry packages and the folders match one to one (191, none missing, none extra).
- **Stay, and who needs them:**
  - thiserror 2.0.21 and thiserror-impl 2.0.21 (and syn 3.0.9): cargo_metadata 0.23.1, which uniffi and uniffi_bindgen use in the bindings generator (`crates/uniffi-bindgen`). They are no longer compiled into Larsal or the `larsal` tool (bill of materials, section 5).
  - base64 0.23.1: R5 is not built (section 6). Without R5 it would still stay for ureq and ureq-proto (basic auth and proxy) until their trim (dependencies.md section 8, step 4.7).
  - getrandom 0.4.3: R8 is not built (section 6). Without R8 it would still stay for tempfile (through uniffi_pipeline, compiled into larsal-ffi until the uniffi trim), rand (proptest) and jobserver (cc).
- `cut_copies` in check-vendor.sh unchanged: no cut copy left.

## 4. Larsal's tests for the new code

- **R4, every message before and after.** A harness test (a temporary file in the private copy, `crates/larsal-ffi/tests/zz_s3b_messages.rs`, deleted after) built every one of the 144 variants, fields filled with demo values (a text, a path, an `io::ErrorKind`, a nested reason, a limit, numbers, a character, two modifiers), and wrote for each its `Display`, its `Debug` and whether `source()` is `None`. Run with thiserror (`cargo test -p larsal-ffi --features net`, before) and with the new impls (after): 144 lines each, `cmp` identical, SHA-256 `f184245ff3e45ad13c468a7503e59aeb1761532226e6aede3e6149973c5a3fff` both. The message tests of the crates (the M-codes: MI05, MI06, MI07, M09, FMT, MSG-*) pass unchanged (section 7).
- **R6.** `crates/log` unit test (section 2). Its mutants, each in the mutant copy: `log_enabled!` true, and each of `trace!`, `debug!`, `warn!` running its arguments (`if true`): `cargo test -p log` fails on all 4. Two message mutants of R4, in the mutant copy: R4a (MI05-12 `repeats more than 99 times`) fails larsal-autotype `int05` `t08_repeat_over_100`; R4b (larsal-sshagent `NoPassphrase` text) passes larsal-sshagent's tests, because the screen text of MI06-14 comes from `messages.rs` by `Error::id`, not from `Display`; the harness above compares that `Display` too. The network client's tests with the facade: `cargo test -p larsal-platform --features net`: lib 44 (7 ignored), net_start 1, doc-tests 0, as before.

## 5. Bill of materials

`scripts/make-sbom.sh`, the tree before and after: 140 to 138 components. Gone: thiserror 2.0.21, thiserror-impl 2.0.21, log 0.4.34. Added: log 0.4.999, as one of Larsal's own crates (no license, purl or checksum, no row in the notices, like the app crates; ships in Larsal.app). Every other component identical as JSON. In the dependency graph only these change: the 8 app crates no longer depend on thiserror, and ureq and ureq-proto depend on log 0.4.999. 106 license texts, 12 crates without a license file, as before.

## 6. What stops R5 and R8 (for the lead)

- **R5 base64.** The brief: base64ct must be an approved crate in plan/architecture.md, or R5 stops. It is not: no row of the approved-crates table names it (it is in the tree through argon2, pem-rfc7468 and ssh-encoding; only `deny.toml` names it, for one version). So the larsal-crypto wrapper, the callers in larsal-core, larsal-format and larsal-sshagent, and their tests are not written. base64 would not leave the lockfile with R5 anyway: ureq and ureq-proto still need it.
- **R8 getrandom 0.4.** dependencies.md F8 and section 8 say R8 runs "after the LD-221 line". The line there, addendum (7), says the opposite: "getrandom is Larsal's random source, so it stays a crypto copy trimmed to its macOS backend; no home-made replacement (rule 3 unchanged)". Also, larsal-crypto has `#![forbid(unsafe_code)]` (Rust rule 2: unsafe only in larsal-platform and larsal-hwkey), and a direct `getentropy` call is an `unsafe` foreign call; `libc` is approved for larsal-platform `macos/` only. And getrandom 0.4.3 would stay in both lockfiles for tempfile, rand and jobserver, so nothing would leave. So `random.rs` is unchanged.

## 7. Checks

In the private copy, a new empty cargo home (afterwards it held only `registry/CACHEDIR.TAG`, `.global-cache`, `.package-cache` and `.package-cache-mutate`), `RUSTUP_HOME` the user's, offline:

- `cargo build --workspace --offline --locked`: exit 0.
- `cargo test --offline --locked --workspace`: exit 0, 2,440 passed, 0 failed, 62 ignored, 104 result lines: step 3a's 2,439 in 102 lines plus `log` (lib 1, doc-tests 0). Per binary: larsal-autotype lib 3, int05 51, int05_match 38, int05_typing 14; larsal-cli main 15, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; larsal-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 82, fea09 25, fuzz_seeds 0 (12), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 24, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; larsal-crypto lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19; larsal-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; larsal-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; larsal-hwkey lib 37, real_key 1 (1), watch 2; larsal-model lib 28; larsal-platform lib 31 (7), net_start 0; larsal-sshagent lib 22, agent 25, own_agent 38; log lib 1; uniffi-bindgen main 0; doc-tests larsal_crypto 2 and 7, every other crate 0.
- `-p larsal-platform --features net`: lib 44 (7), net_start 1, doc-tests 0. `-p larsal-ffi --features net`: 297 passed, 6 ignored, 16 result lines, as step 3a.
- AT-B01 in release (`--release -p larsal-crypto`): 163 passed, 10 ignored: lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. F-134's speed test passed in this run.
- Timed tests in release (`--release -p larsal-core --test fea01 --test fea05 --test fea06 --test fea07 --test mod08 --test mod11`): fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52, 0 failed.
- `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins`: exit 0.
- `cargo fmt --all -- --check`, the fuzz workspace's fmt, the three clippy steps of check.sh (`-D warnings`: the workspace with `--all-targets`, `-p larsal-ffi --test app09`, `-p larsal-platform --features net --all-targets`): exit 0.
- `cargo deny --offline --locked check`: advisories, bans, licenses, sources ok, 2 warnings, as the tree before. The fuzz run of it: ok, 15 warnings, the tree before 16: the one gone is `found 2 duplicate entries for crate 'syn'` (thiserror-impl was the fuzz build's only user of syn 3.0.9). `cargo audit -n` on Cargo.lock (202), on fuzz/Cargo.lock (111 to 109), and on the path-copy lockfile (zxcvbn 3.1.1, ssh-key 0.7.0-rc.11; `crates/log` is Larsal's code, not a copy, and is not in `vendor/`): no vulnerability, the same 1 allowed warning on Cargo.lock as before.
- Both lockfiles byte-identical after all runs (SHA-256 `8df5654b7320f6464f53d563e7622413d26c04adf52992141967571cf2b910e5` and `86522dc8a8677c5e8707bd8225bddad486545920bab6388d146e29b034a38319`).
- `scripts/check-vendor.sh`: PASS (Cargo.toml 195 packages, 181 from vendor/crates-io; fuzz 109, 99; 0 stubs; 14 cut copies). Its mutants (step 2 record section 4), each in the mutant copy, restored by `rsync -a --delete` and checked with `diff -rq` (0 lines) before each one and at the end: none PASS, exit 0. N1 (cfg-if moved out), N2 (a git source) and N6 (no source replacement) exit 101, nothing fetched. N3 (zxcvbn read from /tmp: `read from outside the tree`), N4 (`symbolic links in the package folders`), N5 (`stubs compiled: subtle-2.6.1`, both Mac targets), M1 to M3 (`not upstream beyond its cut`: `src/scalar.rs`, `src/added.rs`, `the package checksum`), M4 and W1, W2 (`files not in its list`: `src/lib_mut.rs`, `build.rs`), X1 (`files not in its list` and `targets outside their package or not a .rs file`), X2 to X4, Y1, Y2 (`targets outside their package or not a .rs file`, both workspaces), Z1 (`a cut copy without its upstream list`), Z2 (`upstream lists in copies not named as cut: subtle-2.6.1`): FAIL, exit 1. New, L1: `crates/log` moved to a folder under /tmp and `[patch.crates-io] log` pointed at it: FAIL, exit 1, `Cargo.toml: read from outside the tree: log 0.4.999: path at /tmp/…/log/Cargo.toml`.
- `scripts/check-names.sh`: PASS (private copy 11,071 files).

## 8. The shared tree

Before the apply: a read-only process list showed no `scripts/check.sh` run (the one running when the copy was made had ended), and each of the 24 shared files to change (both lockfiles, the root and 8 crate `Cargo.toml` files, the 12 source files, plan/architecture.md) was byte-identical to the state the copy was made from, `vendor/` too (`diff -rq` 0 lines); spec/research/dependencies.md and plan/epics.md were read again right before their appends. Applied in one step: the 24 files copied from the private copy, `crates/log` added, `vendor/crates-io/log-0.4.34` removed; then `cmp` of every applied file and `diff -rq` of `crates/` and `vendor/` against the private copy: 0 differences. Then on the shared tree, with a new empty cargo home and a target folder under /tmp: `cargo build --workspace --offline --locked` exit 0, `cargo build --offline --locked -p larsal-platform --features net` exit 0, `scripts/check-vendor.sh` PASS (195 packages, 181 from vendor/crates-io; fuzz 109, 99; 0 stubs; 14 cut copies), both lockfiles with the SHA-256 of section 7 before and after, and `scripts/check-names.sh` PASS (11,360 files) after the records were written.

## 9. Notes for the lead

1. R5 and R8 are not built (section 6): the decisions are in the Builder's report.
2. plan/architecture.md Rust rule 8 still says "One error type per crate (`thiserror`)"; it is outside the approved-crates rows this step may edit. Suggested: "(hand-written `Display` and `Error` impls)".
3. `crates/log` is a workspace member named `log`, because `[patch.crates-io]` needs the name; the naming table in AGENTS.md and the crate list in plan/architecture.md do not name it.
4. The brief named 2026-10-30 for the status line; the work ran on 2026-10-31, so the records say 2026-10-31.
5. No new finding.

## 10. Checker 1 (2026-10-31): passed

Checker 1 did not build this step. Scope: R4 and R6 as built (LD-258 (3)). Work in a private copy (`/tmp/e0s7s3b-checker1-copy`) with a new empty cargo home, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0` and `CARGO_NET_OFFLINE=true`; mutants in a second copy, restored by rsync and checked with `diff -rq` (0 lines) before each one and at the end.

- **Build and tests.** `cargo build --workspace --offline --locked`: exit 0. `cargo test --offline --locked --workspace`: exit 0, 2,440 passed, 0 failed, 62 ignored, 104 result lines, the same per binary as section 7. `-p larsal-platform --features net`: lib 44 (7 ignored), net_start 1, doc-tests 0. `-p larsal-ffi --features net`: 297 passed, 6 ignored, 16 result lines: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0. AT-B01 in release (`--release -p larsal-crypto`): 163 passed, 10 ignored: lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; F-134's speed test passed. Release timed tests: fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52, 0 failed. fmt, the fuzz workspace's fmt, the three clippy steps of check.sh (`-D warnings`) and `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins`: exit 0. Both lockfiles kept section 7's SHA-256 through all runs. `cargo deny --offline --locked check licenses bans sources`: ok, 2 warnings. check.sh's unsafe count on `crates/log` (cargo geiger): 0 unsafe, forbids unsafe.
- **The 144 messages against the code before the step.** The shared `target/debug/deps` still holds libraries that runs on the step 3a tree built between 00:20 and 00:43, before the apply at 00:46 (each one names thiserror; the new ones do not). One program, built against those old libraries and against the new ones, makes all 144 variants of the 13 enums (fields: a text with `{`, `}`, `"` and a non-ASCII letter, a path, an `io::ErrorKind`, nested reasons, both limit types, numbers, a character, two modifiers) and prints for each its `Display`, its `Display` padded to 90 columns, its `Debug` and `source().is_none()`. An exhaustive `match` on each enum compiled against both, so the variants are the same. Both outputs: 144 lines, `cmp` identical, SHA-256 `882d3c95238512b40657d1d3a48561a7022b5677e2f57e786e56ff31d7aed1ee`; `source()` is `None` for every variant. Built against the R4b mutant, the program shows that one line different.
- **Nothing else in the 10 files.** Section 1's "in" line counts equal, file by file, the lines of the new `Display` and `Error` impls (with one blank line each) plus one changed derive line per enum.
- **Swift.** `uniffi-bindgen-swift` on the new `liblarsal_ffi.a` (`--features net`), as build-core.sh runs it: `LarsalCore.swift`, `LarsalFFI.h` and `module.modulemap` are byte-identical to the ones build-core.sh wrote from the step 3a tree at 00:26 (`LarsalCore.swift` SHA-256 `eeed94b4b5d0e29f3574723625ef3dd5d382426e705cac83f571a54ad3b6fdf9`).
- **Lockfiles: removals only.** The step 3a state was rebuilt in a third copy: thiserror put back in the 8 manifests, the `net` feature and the workspace pins; the log patch and `crates/log` taken out; `vendor/crates-io/log-0.4.34` made again from its `.crate` (SHA-256 `f9f8bd3e56ce4dfc153cf470fffbfa98c7620958b312ca5c3a4b8d5181fd13c6`, the old lockfile checksum); then one `cargo metadata --offline` per workspace. It gave 202 entries (registry 189) and 111 (registry 101), as the step 3a records say. Against the tree now: `Cargo.lock` 11 lines out, 1 in (`version = "0.4.999"`): the `thiserror` names of larsal-autotype, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-hwkey, larsal-platform and larsal-sshagent, and log's source and checksum. `fuzz/Cargo.lock` 25 lines out, 0 in: thiserror, thiserror-impl and the names of larsal-autotype, larsal-core, larsal-crypto, larsal-format and larsal-sshagent. The one addition is the path package log 0.4.999.
- **Trees.** `cargo tree --all-features -e normal,build,dev` for aarch64-apple-darwin and x86_64-apple-darwin, the root workspace and fuzz: log 0.4.34 is in none (only log 0.4.999 at `crates/log`); thiserror is in neither fuzz tree, and in the root trees only under cargo_metadata 0.23.1 (uniffi, uniffi_bindgen). `-p larsal-ffi` and `-p larsal-cli`, all features, normal and build edges, both targets: no thiserror and no cargo_metadata. None of our 10 crates names thiserror on any edge.
- **Copies.** `vendor/crates-io` holds 191 folders, exactly the registry entries of both lockfiles. For each, the `.crate` SHA-256 equals the lockfile checksum and the `package` value; all 7,904 files on disk are in the list with their hash. Against the `.crate`, only the `Cargo.toml` of the 14 cut copies differs, and ring's step 1 cut is the one missing file. Each of the 14 keeps `.cargo-checksum.upstream.json`, equal to the `.crate`'s list (ring: without the cut file) and listed in the new list with its own hash. The same on the shared tree. `vendor/ssh-key/src` against its `.crate`: only LD-209's 3 files differ. No vendor file is newer than the step 3a apply.
- **Bill of materials.** `scripts/make-sbom.sh` on the rebuilt step 3a copy and on the copy now: 140 to 138 components; gone log 0.4.34, thiserror 2.0.21, thiserror-impl 2.0.21; added log 0.4.999 with the same fields as the app crates; every other component the same.
- **Mutants, again.** check-vendor: none PASS; N1, N2 and N6 exit 101; N3, N4, N5, M1 to M4, X1 to X4, Y1, Y2, Z1, Z2, W1 and W2 FAIL, exit 1, each with section 7's message. L1: with `crates/log` moved to /tmp unchanged, cargo cannot read its workspace keys (exit 101); with `edition` and `publish` written out, FAIL, exit 1, `read from outside the tree: log 0.4.999`. R4a fails int05 `t08_repeat_over_100`; R4b passes larsal-sshagent's tests (lib 22, agent 25, own_agent 38), as section 4 says; each of the 4 log mutants fails `cargo test -p log`.
- **Checks.** check-vendor PASS in the private copy and on the shared tree (195 packages, 181 from vendor/crates-io; fuzz 109, 99; 0 stubs; 14 cut copies). Name guard: self-test PASS, private copy PASS, shared tree PASS after this record.
- **R5 and R8.** Both stops were right: base64ct was in no approved-crates row, and LD-221 (7) and Rust rule 2 rule out R8. The lead ruled in LD-258.
- **Notes, not send-backs.** (1) Section 9 items 2 and 3 are still open: Rust rule 8 names `thiserror`, and the naming table and the crate list do not name `crates/log`; LD-258 does not cover them. (2) The 144-message program is not in the tree, so a later change to a `Display` text that no message test reads (as R4b) still passes every test.

## 11. Checker 2 (2026-10-31): passed

Scope: the crypto copies, as section 7 of spec/research/dependencies.md marks them (crypto, key or support: 73 rows). Step 3b changed no crypto copy: thiserror, thiserror-impl and log are all "no" in that column, and R5 and R8 were not built (LD-258: R8 dropped, R5 moved to batch 3d). So there is no `random.rs` change and no base64 wrapper to review: `crates/larsal-crypto/src/random.rs` was last written on 2026-10-27, and in larsal-crypto only `error.rs` and `Cargo.toml` carry the step's time (2026-10-31 00:46). This review proves that every crypto copy is still the copy step 3a left, and that the step changed nothing in how a crypto copy is built on a Mac. Of the 73 rows, 69 are copies in `vendor/crates-io`; ssh-key 0.7.0-rc.11 is the path copy `vendor/ssh-key` (LD-209); des, fiat-crypto and rustls-platform-verifier left in steps 1 and 2.

Setup: a private copy (`rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots`), and three more copies made from it: the step 3a state (rebuilt as Checker 1 did: thiserror back in the 8 manifests, the `net` feature and the workspace pins; the log patch and `crates/log` out; `vendor/crates-io/log-0.4.34` made again from its `.crate`; one `cargo metadata --offline` per workspace gave 202 entries, registry 189, and 111, registry 101), one with the upstream manifests, and one for mutants (restored by `rsync -a --delete` before each mutant and at the end; `diff -rq --no-dereference` 0 lines each time). Target folder under `/tmp`, an empty cargo home, a throwaway `HOME` with `RUSTUP_HOME` the user's and `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, every cargo call `--offline`, and `--locked` except the lockfile rewrites of the two rebuilt copies. Each `.crate` came from `~/.cargo/registry/cache` and was unpacked under `/tmp`. Lists were read with python3's standard library. At the end the shared tree still matched the private copy: `vendor/`, `crates/`, both lockfiles, both `Cargo.toml` files, `.cargo/`, `deny.toml`, `scripts/check-vendor.sh` and `scripts/make-sbom.sh`.

### Byte for byte (rule 3)

- All 191 `.crate` files: the SHA-256 equals the checksum in Cargo.lock or fuzz/Cargo.lock and the copy's `package` value, and for the 14 cut copies also the `package` value of the upstream list. 191 registry entries, 191 folders, none missing, none extra.
- `diff -rq` of each unpacked `.crate` against its copy, all 191: 284 lines. 205 are the two lists, only in the copy (191 + 14). 64 are `.gitignore` and `.gitattributes` files that cargo vendor never copies. 1 is ring's step 1 cut. 14 are `Cargo.toml`, in exactly the 14 copies of `cut_copies`. No other file differs, and no copy holds a file its `.crate` lacks, the lists aside. Step 3a had 286 lines; the 2 fewer are log-0.4.34's list and its one git file.
- The 69 crypto copies: 64 are byte-for-byte their `.crate` (the lists and the never-copied git files aside). The other 5 are the cut copies of step 2, and each `Cargo.toml` only lost lines (`Cargo.toml.orig` is the same as in the `.crate` in all 5): ring 0.17.14 7 out, 0 in (the aarch64 Windows table of windows-sys); getrandom 0.2.17 5 out, 0 in (the WASI table and `"wasi/rustc-dep-of-std"`); getrandom 0.4.3 4 out, 0 in (the UEFI table of r-efi); curve25519-dalek 5.0.0 4 out, 0 in (the fiat backend table); ssh-cipher 0.3.0 7 out, 0 in (the feature `tdes`, `"des?/zeroize"` and the optional `des`). This is the table of section 9 of the step 3a record, line for line. No code file differs.
- Lists, all 191 copies: every file on disk is in its list with the right hash, and no file is unlisted. The list of each plain copy equals a list built from its `.crate` (every file but `.gitignore` and `.gitattributes`). For the cut copies, the upstream list equals the list built from the `.crate`, and every entry of the new list but `Cargo.toml` and the upstream list has its upstream hash; the only upstream entry a new list lacks is ring's cut file. Entries of the 5 cut crypto copies, new and upstream: ring 391 and 391, getrandom 0.2.17 39 and 38, getrandom 0.4.3 49 and 48, curve25519-dalek 75 and 74, ssh-cipher 18 and 17.
- `vendor/ssh-key` against its `.crate` (SHA-256 `f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`): in `src/`, only `lib.rs`, `private/ecdsa.rs` and `private/opaque.rs` differ; `Cargo.toml` differs; README, CHANGELOG, `tests/`, `Cargo.lock`, `Cargo.toml.orig` and `.cargo_vcs_info.json` are left out. That is what LD-209 lists, as in step 3a.
- In the shared tree, no file in `vendor/` is newer than 2026-10-30 23:14 (the step 3a apply). The step 3b apply removed `log-0.4.34` and wrote nothing in `vendor/`.

### The step changed nothing in how a crypto copy is built

- `cargo tree --offline --locked --workspace --all-features -e normal,build,dev --target <target> --prefix depth -f '{p} [{f}]'` on the step 3a copy and on the copy now, both workspaces, both Mac targets. For each crypto copy in a tree: its features and its direct dependencies with their features. The two states give identical lists in all 4 trees (crypto packages present, `vendor/ssh-key` included: root 69 on aarch64-apple-darwin and 70 on x86_64-apple-darwin, fuzz 62 and 63).
- Their features on a Mac, as steps 2 and 3a recorded: ring `alloc, default, dev_urandom_fallback`; getrandom 0.2.17 none; getrandom 0.4.3 `std, sys_rng` (and none on its build edge); curve25519-dalek `digest, zeroize`; ssh-cipher `aes, chacha20poly1305, encoding, rand_core, zeroize`.
- No crypto copy depends on log or thiserror. `cargo tree -i log`, both Mac targets: only ureq, ureq-proto and goblin pull in log 0.4.999 (`crates/log`). `cargo tree -i thiserror`: only cargo_metadata, under uniffi and uniffi_bindgen (the bindings generator). rustls is built with `ring, std, tls12`: its optional `logging` is off, so the facade is in no crypto copy's build. larsal-crypto's own tree (`-p larsal-crypto --all-features`, normal and build edges) has no log, thiserror or base64.
- The full trees with features (`-e normal,build,dev,features`) differ only where the step says: thiserror, thiserror-impl and their proc-macro packages leave our crates' edges, log 0.4.34 becomes log 0.4.999, and `crates/log` is one more workspace member.
- Bill of materials (`scripts/make-sbom.sh` on both states, output under `/tmp`): 140 to 138 components (gone log 0.4.34, thiserror 2.0.21, thiserror-impl 2.0.21; added log 0.4.999); the 69 crypto components are the same, with every field the same.

### The cut tables are never selected on a Mac

The upstream-manifest copy, as in steps 2 and 3a, now on the step 3b tree: the 5 cut crypto copies got back their upstream `Cargo.toml` and list (ring also its cut file), and the 14 packages the cut tables and the cut feature name came back, each unpacked whole from its `.crate` with a list of its files: des 0.9.0, fiat-crypto 0.3.0, r-efi 6.0.0, wasi 0.11.1, windows-sys 0.52.0, windows-targets 0.52.6 and the 8 windows_* 0.52.6 crates (under `/tmp` only; never in the project folder). `cargo metadata --offline` rewrote the lockfiles: Cargo.lock gained those 14 packages (105 lines) and fuzz/Cargo.lock gained des, fiat-crypto and r-efi (24 lines); no line removed.

`cargo tree --offline --locked --workspace --all-features -e normal,build,dev,features --target <target> --prefix depth -f '{p} [{f}]'`, the copy's path replaced by one word, on the private copy and on the upstream-manifest copy:

| Workspace | Target | Lines | Cut against upstream manifests |
|---|---|---|---|
| root | aarch64-apple-darwin | 1,575 | byte-identical |
| root | x86_64-apple-darwin | 1,583 | byte-identical |
| fuzz | aarch64-apple-darwin | 631 | byte-identical |
| fuzz | x86_64-apple-darwin | 667 | byte-identical |

So with every feature of our crates, on both Mac targets, in both workspaces, the packages and their features are the same with or without the cuts. With `--target all`, the upstream-manifest copy names fiat-crypto, r-efi, wasi, windows-sys 0.52.0, windows-targets and the 8 windows_* crates (root, 13 packages), and fiat-crypto and r-efi (fuzz): the tables are real on other systems, and only the Mac cfg leaves them out. des is in no tree, because nothing turns on `tdes`.

Custom cfgs: outside `vendor/`, `curve25519_dalek_backend` and `getrandom_backend` are named only in the records, and `RUSTFLAGS` is set only in `scripts/repro-build.sh` (path maps and linker flags). `.cargo/config.toml` sets no flags.

### Mutants on the crypto copies (check-vendor.sh)

| Mutant | check-vendor |
|---|---|
| None | PASS, exit 0 |
| C1: ring `pregenerated/sha256-armv8-ios64.S`, one `nop` line added, its hash written into the new list | FAIL, exit 1, `ring-0.17.14: not upstream beyond its cut: pregenerated/sha256-armv8-ios64.S` |
| C2: getrandom 0.4.3 `src/backends/getentropy.rs` (Larsal's random source on macOS), `GETENTROPY_MAX` 256 to 512, its hash written into the new list | FAIL, exit 1, `getrandom-0.4.3: not upstream beyond its cut: src/backends/getentropy.rs` |
| C3: getrandom 0.2.17 `src/lib.rs`, `pub const UNLISTED_MUTANT: u8 = 1;` added, its hash written into the new list | FAIL, exit 1, `getrandom-0.2.17: not upstream beyond its cut: src/lib.rs` |
| C4: curve25519-dalek `src/scalar.rs`, Scalar addition calls `UnpackedScalar::sub`, its hash written into the new list | FAIL, exit 1, `curve25519-dalek-5.0.0: not upstream beyond its cut: src/scalar.rs` |
| C5: a new `build.rs` in ssh-cipher, nothing else changed | FAIL, exit 1, `ssh-cipher-0.3.0: files not in its list: build.rs` |
| C6: ssh-cipher's cut `Cargo.toml`, one feature line added, its hash written into the new list | PASS, exit 0 |

C6 is a cut copy's `Cargo.toml` rewritten with its list: out of check-vendor's scope (LD-254 (2)), since a cut copy's `Cargo.toml` may differ from upstream. The `.crate` diff above finds it (a cut `Cargo.toml` may only lose lines; all 5 lost lines and gained none). Not a send-back.

### Known answers on the copies (AT-B01)

- `cargo test --offline --locked --release --no-fail-fast -p larsal-crypto`: exit 0. 163 passed, 0 failed, 10 ignored: lib 47 (1 ignored), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. F-134's speed test passed.
- `cargo test --offline --locked --no-fail-fast -p larsal-platform --features net` (ring and getrandom 0.2.17): exit 0. lib 44 passed (7 ignored), net_start 1, doc-tests 0.

### The crypto crate's own change

`crates/larsal-crypto/src/error.rs` (R4): 9 variants, none holds data, each `Display` arm is one fixed `f.write_str` text, and `impl std::error::Error` is empty, so `source()` is `None`. No key, IV, nonce, password or other input can reach the text (rule 4). The crate keeps `#![forbid(unsafe_code)]`, and `Cargo.toml` lost only `thiserror` (the tree check above: no new package). `crates/log` (R6) has `#![forbid(unsafe_code)]` and no dependency, and its macros never evaluate their arguments, so nothing a dependency formats can reach a log (rule 4).

No finding. No file in the shared tree changed but these records. scripts/check.sh was not run (the lead runs it).

## 12. Verify (2026-10-31): signed

Verdict: **signed**. Every E0-S7 check that step 3b covers passed again in a private copy. Scope: R4 and R6 as built (LD-258 (3)); R8 is dropped and R5 runs as batch 3d (LD-258 (1), (2)). The Verify agent did not build or check this step, and it changed no product file. No new finding (the next free number is F-137).

Setup: a private copy, `rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots` (`/tmp/e0s7s3b-verify-copy`, made at 01:31; at that time both lockfiles had section 7's SHA-256); a mutant copy (`/tmp/e0s7s3b-verify-mut`, restored by `rsync -a --delete` before each mutant; `diff -rq --no-dereference` then 0 lines each time); and a copy that holds the step 3a state (`/tmp/e0s7s3b-verify-step3a`, section 12.2). Target folders under `/tmp`, a new empty cargo home per run, a throwaway `HOME`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. Every cargo call was `--offline --locked`, except the lockfile rewrite of the step 3a copy (under `/tmp`). The published `.crate` files were read from `~/.cargo/registry/cache` and unpacked only under `/tmp`.

No network: every build and test run, check-vendor, make-sbom.sh and build-core.sh went through `sandbox-exec` with `(allow default)`, `(deny network-outbound (remote ip))`, one allowance for `localhost:*`, and a deny on the resolver socket, as in step 3a. Inside it, a socket to 192.0.2.1:443 gets "Operation not permitted", a name lookup fails, and 127.0.0.1 connects. Outside it, still offline with an empty cargo home: the three test runs that cannot run in a sandbox (section 12.1), `cargo fmt`, `cargo tree` and the name guard; and xcodebuild, because it refuses to start inside another sandbox (it resolved only the local package). The empty cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` afterwards. Both lockfiles kept their SHA-256 (`8df5654b…`, `86522dc8…`) through every run. At the end the shared tree matched the copy: `crates/`, `vendor/` and `macos/` (`diff -rq --no-dereference` 0 lines), and both lockfiles, both `Cargo.toml` files, `.cargo/config.toml`, `deny.toml`, every script in `scripts/` and `plan/architecture.md` (SHA-256 unchanged since the copy was made).

### 12.1 Build and tests, offline and locked, with an empty cargo home

- `cargo build --offline --locked --workspace --all-targets -v` (sandbox): exit 0, 84 s. No line names `registry/src` or the cargo cache. 178 package folders under `vendor/crates-io/` were compiled (step 3a: 179; log-0.4.34 is gone). `crates/log` was compiled as `log v0.4.999`. thiserror and thiserror-impl were compiled only for cargo_metadata (the one crate given `--extern thiserror`), and cargo_metadata only for uniffi and uniffi_bindgen.
- `cargo test --offline --locked --workspace --no-fail-fast` (sandbox): 104 result lines, 2,438 passed, 2 failed, 62 ignored, 195 s. The 2 failures are the sandbox, as in steps 2 and 3a: `fea06_29_offline_streams` (setuid `ps` is refused) and `t53_t57_ssh_signs_in_through_apps_socket` (macOS's `sshd-auth` starts its own sandbox). Each passes alone outside it. So 2,440 pass. Per test binary (ignored in brackets): larsal-autotype lib 3, int05 51, int05_match 38, int05_typing 14; larsal-cli main 15, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; larsal-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 82, fea09 25, fuzz_seeds 0 (12), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 24, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; larsal-crypto lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; larsal-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; larsal-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; larsal-hwkey lib 37, real_key 1 (1), watch 2; larsal-model lib 28; larsal-platform lib 31 (7), net_start 0; larsal-sshagent lib 22, agent 25, own_agent 38; log lib 1; uniffi-bindgen-swift main 0; the other doc-tests 0. This is section 7's list.
- `-p larsal-platform --features net` (sandbox): lib 44 passed (7 ignored), net_start 1, doc-tests 0. `-p larsal-ffi --features net` (sandbox): 297 passed, 6 ignored, 16 result lines: lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7, doc-tests 0.
- Release, timed tests (`--release -p larsal-core`): fea01 37, fea05 49, fea07 26, mod08 48, mod11 52 (sandbox) and fea06 38 (outside it, for `fea06_29`), 0 failed.
- `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins` (sandbox): exit 0. `cargo fmt --all -- --check`, the fuzz workspace's fmt and the three clippy steps of check.sh (`-D warnings`) (sandbox): exit 0.

### 12.2 Both lockfiles against the step 3a state: removals only

The step 3a state was rebuilt in a third copy: `thiserror = "=2.0.21"` back in the workspace pins, `thiserror = { workspace = true }` in larsal-autotype, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-hwkey and larsal-sshagent, and in larsal-platform as optional with `dep:thiserror` in its `net` feature (the old libraries in the shared target agree: larsal-platform names thiserror only when built with `net`); the `[patch.crates-io] log` lines and `crates/log` taken out; `vendor/crates-io/log-0.4.34` made again from its `.crate` (every file but `.gitignore` and `.gitattributes`, with a list of each file's SHA-256; package SHA-256 `f9f8bd3e56ce4dfc153cf470fffbfa98c7620958b312ca5c3a4b8d5181fd13c6`). `cargo metadata --offline` then added exactly log 0.4.34 to Cargo.lock, and thiserror 2.0.21 and thiserror-impl 2.0.21 to fuzz/Cargo.lock: 202 entries (registry 189) and 111 (registry 101), the step 3a counts.

| Lockfile | Step 3a | Now | Lines removed | Lines added | Entries gone | Entries new |
|---|---|---|---|---|---|---|
| Cargo.lock | 202 (registry 189) | 202 (registry 188) | 11 | 1 | log 0.4.34 (crates.io) | log 0.4.999 (path) |
| fuzz/Cargo.lock | 111 (registry 101) | 109 (registry 99) | 25 | 0 | thiserror 2.0.21, thiserror-impl 2.0.21 | none |

Cargo.lock: the 8 lines out are the `thiserror` names of larsal-autotype, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-hwkey, larsal-platform and larsal-sshagent; the other 3 are log's version, source and checksum, and the 1 line in is `version = "0.4.999"`. fuzz/Cargo.lock: the 2 entries (20 lines with their headers and blank lines) and the `thiserror` names of 5 app crates. Every other entry keeps its version, its source and its checksum. The only path package added is `log` 0.4.999 (`crates/log`, Larsal's own code).

`cargo tree --offline --locked --workspace --all-features -e normal,build,dev` for aarch64-apple-darwin and x86_64-apple-darwin: log 0.4.34 is in none of the 4 trees (root: only log 0.4.999 at `crates/log`; fuzz: no log). thiserror is in neither fuzz tree; in the root trees it is only under cargo_metadata 0.23.1, under uniffi and uniffi_bindgen. `-p larsal-ffi --features net` and `-p larsal-cli`, normal and build edges, both targets: no thiserror and no cargo_metadata. Only goblin, ureq and ureq-proto name log in either lockfile.

### 12.3 A source outside the tree fails check-vendor

Each mutant was made in the mutant copy, restored before the next one, and run through check-vendor in the sandbox. Nothing is fetched: the `git` source of N2 names a folder that does not exist, and every run is offline.

| Mutant | Result |
|---|---|
| None | PASS, exit 0 (195 packages, 181 from vendor/crates-io; fuzz 109, 99; stubs 0; cut copies 14) |
| N1: a registry package not vendored (`cfg-if-1.0.5` moved out) | exit 101, `no matching package named cfg-if found` |
| N2: the root `[patch]` zxcvbn as a `git` source | exit 101, `failed to load source for dependency zxcvbn`, `can't checkout … you are in the offline mode` |
| N3: the root `[patch]` zxcvbn at a copy under /tmp | FAIL, exit 1: `read from outside the tree: zxcvbn 3.1.1: path at /tmp/e0s7s3b-verify-outside/zxcvbn/Cargo.toml` |
| N3b: the same path written as `vendor/../../…` | FAIL, exit 1, the same message with the normalized path |
| N4: a copy that is a link out of the tree (`subtle-2.6.1`) | FAIL, exit 1: `symbolic links in the package folders` |
| N6: no source replacement in `.cargo/config.toml` (the build would need the registry) | exit 101, `no matching package named regex-syntax found` |
| N7: the replacement directory a copy of `vendor/crates-io` under /tmp | FAIL, exit 1: `read from outside the tree`, every registry package with its /tmp path |
| L1a: `crates/log` moved to /tmp unchanged, the patch pointed at it | exit 101: cargo cannot inherit its workspace keys there |
| L1: the same with `edition` and `publish` written out | FAIL, exit 1: `read from outside the tree: log 0.4.999: path at /tmp/e0s7s3b-verify-outside/log/Cargo.toml` |
| L2: the `[patch.crates-io] log` line removed (ureq would need log from crates.io) | exit 101, `no matching package named log found` |
| L3: `crates/log` a link to a copy under /tmp | FAIL, exit 1: `symbolic links in the package folders` |

### 12.4 The bill of materials keeps the same components and checksums

`scripts/make-sbom.sh` ran in both states (sandbox, empty cargo home, output under /tmp). The step 3a state prints `140 components, 106 license texts, 12 crates without a license file`; the tree now prints `138 components, 106 license texts, 12 crates without a license file`.

- Gone: log 0.4.34, thiserror 2.0.21, thiserror-impl 2.0.21. New: log 0.4.999, with the same fields as the app crates (`bom-ref`, `name`, `version`, `type`, `scope`, `larsal:ships-in` Larsal.app; no license, purl or checksum). Each of the other 137 components is identical as JSON.
- 124 components carry a SHA-256 (step 3a 127, less the 3), and each equals its Cargo.lock checksum. zxcvbn and ssh-key carry `pedigree` instead. The other top-level fields are identical.
- In the dependency graph only these change: the 8 app crates lose their edge to thiserror, thiserror loses thiserror-impl, and ureq and ureq-proto point at log 0.4.999 in place of log 0.4.34.
- THIRD-PARTY-NOTICES.md: the step 3a file less the 3 crate rows and less those 3 crates in the "Used by" lines is exactly the new file (6,519 to 6,516 lines). No new text, no text gone. `rust-std-COPYRIGHT.html` is byte-identical.

### 12.5 Crypto copies against upstream (the diff proof, rule 3)

Every copy in `vendor/crates-io` was compared with its published `.crate`, read from the archive in the local cargo cache (python3 -I, standard library):

- 191 folders, exactly the registry entries of both lockfiles (none missing, none extra). For each, the archive's SHA-256 equals the lockfile checksum and the copy's `package` value, and for the 14 cut copies also the upstream list's `package` value.
- A list built from each `.crate` (every file but `.gitignore` and `.gitattributes`, in cargo vendor's format) is byte-identical to the copy's `.cargo-checksum.json` for each of the 177 plain copies and to `.cargo-checksum.upstream.json` for each of the 14 cut copies.
- Files that differ from the `.crate`: 14, each the `Cargo.toml` of a copy named in `cut_copies`. Only in the archive: the 64 `.gitignore` and `.gitattributes` files that cargo vendor never copies, and ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (step 1, LD-247 (4)). Only in the copy: the lists. **No code file differs in any copy, and no copy holds a file its archive lacks.**
- All 7,904 files on disk (the lists aside) are in their list with the listed SHA-256; none is unlisted.
- The 5 cut crypto copies only lost manifest lines: ring 0.17.14 7 removed, getrandom 0.2.17 5, getrandom 0.4.3 4, curve25519-dalek 5.0.0 4, ssh-cipher 0.3.0 7, and 0 added in each; `Cargo.toml.orig` is the `.crate`'s in all 14 cut copies. This is the table of step 3a.
- `vendor/ssh-key` against ssh-key-0.7.0-rc.11.crate (SHA-256 `f9a32fae…`): in `src/`, only `lib.rs`, `private/ecdsa.rs` and `private/opaque.rs` differ, and `Cargo.toml`; README, CHANGELOG, `tests/`, `Cargo.lock`, `Cargo.toml.orig` and `.cargo_vcs_info.json` are left out (LD-209).
- In the shared tree, nothing in `vendor/` is newer than the step 3a apply (2026-10-30 23:14) but the folder `vendor/crates-io` itself, whose time (00:46) is the removal of log-0.4.34.

### 12.6 AT-B01 known answers on the copies, in release

`cargo test --offline --locked --release --no-fail-fast -p larsal-crypto` (sandbox, empty cargo home): exit 0, **163 passed, 0 failed, 10 ignored**: lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `kdf::tests::version_0x10_with_secret_known_answers`, `ssh::tests::sign_ed25519_rfc8032_test_1`, `ssh::tests::sign_p256_rfc6979_sample` and F-134's `f_134_damaged_speed_record_is_measured_again` are among them.

### 12.7 R4 messages and R6 facade

- **Messages against the step 3a libraries.** The 13 hand-written `Display` impls have 144 arms, one per variant. Their fixed texts, split at the placeholders (`{{` and `}}` read as `{` and `}`), are 157 pieces. Each piece is present byte for byte in the step 3a libraries still in the shared `target/debug/deps` (built 00:20 to 00:25 from the step 3a tree with thiserror, before the 00:46 apply; larsal-platform's with `net`) and in the new ones. The check sees a change: with the last character of each of the 151 pieces of 6 or more characters changed, none of the 151 is found in the old libraries. This adds to Checker 1's full program (section 10), which compared every variant's text, `Debug` and `source()`.
- **The facade.** No file in `vendor/`, `crates/` or `fuzz/` calls `set_logger`, `set_boxed_logger` or `set_max_level`, so the published crate never had a logger here. The callers' uses (goblin, ureq, ureq-proto) are `log_enabled!`, `debug!`, `trace!`, `warn!` and `log::Level`, none with a `target:` argument. Each of 4 mutants fails `cargo test -p log` (`log_enabled!` true; `trace!`, `debug!` and `warn!` each `if true`). `crates/log` has `#![forbid(unsafe_code)]` and no dependency.

### 12.8 The name guard

- The copy: `scripts/check-names.sh --self-test` self-test PASS, and `names: PASS (11072 files scanned, 16 vault files name-only)`.
- `vendor/` holds 8,162 files (`find vendor -type f`), every one scanned in that run: step 3a's 8,185 less the 23 of log-0.4.34 (22 files and its list).
- The shared tree after these records: `names: PASS (11360 files scanned, 16 vault files name-only)`, exit 0.

### 12.9 The Mac app still builds

- `scripts/build-core.sh` (sandbox, empty cargo home, offline and locked): exit 0, 52 s. It made `target/larsal-core/LarsalFFI.xcframework`, `Swift/LarsalCore.swift`, `include/LarsalFFI.h` and `include/module.modulemap`. All three generated files are byte-identical to the ones in the shared `target/larsal-core`, which build-core.sh wrote from the step 3a tree at 00:26 (`LarsalCore.swift` SHA-256 `eeed94b4b5d0e29f3574723625ef3dd5d382426e705cac83f571a54ad3b6fdf9`).
- `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e0s7s3b-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`, exit 0, 25 s, no code warning. The only resolved package is the local one, `LarsalCore: …/macos/LarsalCore @ local`. No test was run, and no window was shown.

### 12.10 check-vendor on the shared tree

`scripts/check-vendor.sh` (sandbox): PASS, exit 0 (195 packages, 181 from vendor/crates-io; fuzz 109, 99; stubs 0; cut copies 14). Both lockfiles unchanged.

### Notes, not findings

1. spec/research/dependencies.md section 13 still says "Checker next." This brief lets Verify add only a new section there, so the lead updates that line, as section 12 was updated for step 3a.
2. Still open, as recorded (section 9 items 2 and 3): Rust rule 8 in plan/architecture.md names `thiserror`, and the naming table in AGENTS.md and the crate list do not name `crates/log`.
3. Section 10 says each cut copy's upstream list equals the `.crate` list "(ring: without the cut file)". ring's upstream list does name the cut file; it is byte-identical to the list built from the whole `.crate`. Only its new list lacks the file, as section 11 says. The tree is right; only the words are off.
4. The brief named 2026-10-30 for the status line; the work ran on 2026-10-31, so the records say 2026-10-31.

### Clean-up

Every process Verify started ended; no `sshd` was left. All `/tmp/e0s7s3b-verify-*` folders are deleted. `scripts/check.sh` was not run (the lead runs it). No git command was run.
