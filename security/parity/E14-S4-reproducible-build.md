# E14-S4 Reproducible build and bill of materials (AT-J04)

Story: E14-S4, plus the third-party notices part of E14-S2. Decision: LD-222 (and LD-226 (5) for where the notices live).
Date: 2026-10-29 (the session date; the Mac's clock read 2026-10-30 01:08 to 01:18 CET during the runs).
Role: Verify. I did not build or check this story. I did not open the reference and did not need it.
Result: **signed.**

AT-J04 says: "Two clean builds: same binary hash, or every difference explained." It holds. Two clean builds were made from two fresh copies at paths of different length, at different times, with different time zone, locale and umask, each with its own target folder. They gave the same SHA-256 for all 23 release files, and the three products match byte for byte. No difference was left to explain. The bill of materials and the notices were checked against `cargo metadata` and against the crate paths found inside the shipped binaries. They list every crate that ships and no dev-only crate. Every third-party license matches the crate's own Cargo.toml, and every license has its text.

## Setup

- **Source.** Both copies were made back to back from the shared tree with `rsync -a --exclude target --exclude app-shots`:
  - A: `/tmp/e14s4-verify-a` (physical path 27 characters)
  - B: `/tmp/e14s4-verify-b-copy-at-a-second-and-much-longer-path-for-verify` (76 characters)
- **Stub.** The shared tree does not compile right now. `crates/app-ffi/src/edit.rs:70` and `:105` use `crate::hwkey::Choice`, and `lib.rs` declares no `hwkey` module (F-107 work in progress, another agent's). Both copies got the same three lines at the end of `crates/app-ffi/src/lib.rs`: a doc comment and `pub(crate) mod hwkey { pub(crate) struct Choice; }`. The Builder and Checker 1 used the same stub. The shared tree was not touched.
- **Same input.** `diff -r` of the two copies gave rc=0. Its one message is the dangling relative link `macos/AppCore/Generated -> ../../target/app-core`, which is the same in both. `cmp` shows that `scripts/repro-build.sh`, `scripts/make-sbom.sh`, `scripts/licenses/*`, `Cargo.toml` and `Cargo.lock` in copy A equal the shared tree's.
- **Toolchain** (BUILDINFO, the same in both): rustc 1.99.1 (58cf8f9c3), cargo 1.99.1, LLVM 23.1.1, Xcode 27.0 (27A266a), macOS SDK 26A425, macOS 26.6 (25G5057c), SOURCE_DATE_EPOCH 1793232000.
- **Derived data.** The script always builds in its fixed folder `/private/tmp/app-repro` (its `target/xcode-release` is the derived data), empty at the start and deleted at the end. So the brief's separate derived-data folders do not apply. Each run got its own output folder through `CARGO_TARGET_DIR`. Between the runs I stopped the `ibtoold` daemons of run A, so run B also started a fresh asset-catalog daemon.

## The two builds

| | Run A | Run B |
|---|---|---|
| Command | `CARGO_TARGET_DIR=/tmp/e14s4-verify-target-1 /tmp/e14s4-verify-a/scripts/repro-build.sh` | `CARGO_TARGET_DIR=/tmp/e14s4-verify-target-2 <copy B>/scripts/repro-build.sh` |
| Environment | as the shell has it (CET, umask 022) | `TZ=Pacific/Auckland`, `LANG=LC_ALL=de_DE.UTF-8`, `umask 027` (variations taken from reprotest's list) |
| Time | 01:09:06 to 01:12:20 CET | 01:12:51 to 01:17:46 CET (the log shows 13:12:51 to 13:17:46, Auckland time) |
| Exit | rc=0 | rc=0 |
| Clean | every crate compiled (`Compiling ring`, `Compiling app-ffi`, 280 lines) | the same |
| Catalog retry | none | one, on its own: "Assets.car appearance order differs, building App again" |

Run B hit actool's appearance-order race by itself. The retry rebuilt App from an empty derived-data folder, and the result still matched run A. So the retry path is proven by a natural hit, not only by a forced one.

## Comparison

- `diff` of the two SHA256SUMS: rc=0, 23 lines.
- `diff -r -x xcodebuild.log` of the two output folders: rc=0. The log is not shipped and is not hashed.
- `cmp` rc=0, byte for byte:

| File | Bytes | SHA-256 (both runs) |
|---|---|---|
| `app` | 4,173,136 | 42db6f1051152d002353b0b66bc167f88e3fc2a7536513810dbb59918850ef86 |
| `libapp_ffi.a` | 73,436,056 | d77af8d17a6f18c76c9bb2aa4ca66513e1230afd39d205c294c02bd20bfe3add |
| `App.app/Contents/MacOS/App` | 10,355,040 | ff68477e205ed3ad1e8701a657269fde754d474778c98df9a68c93bfc697c592 |
| `App.app/Contents/Resources/Assets.car` | 189,288 | 84b28129a34f2e05… |
| `App.app/Contents/_CodeSignature/CodeResources` | 5,532 | 288ce3f51086a3c2… |

The other 18 files are Info.plist, PkgInfo, the fonts and their licenses, `LICENSES.md`, `BUILDINFO`, `THIRD-PARTY-NOTICES.md` (2caa0f86…), `sbom.cdx.json` (c479bd6b…) and `rust-std-COPYRIGHT.html`. All are equal.

`app` and App equal Checker 1's hashes from an hour earlier (42db6f10…, ff68477e…). `libapp_ffi.a` does not (a4260638… then), because other agents have edited app-ffi since. Only two runs of the same source are compared here.

Signals inside the files:

- **LC_UUID.** App FCC25568-FDE7-3D4B-B58C-CD0A9EC6161C, `app` E9BFA650-8070-345A-A847-27991CCEC6D2, the same in both runs. These are the values that changed with the path length in Checker 1's first round.
- **Archive dates.** `ar -tv libapp_ffi.a`: every member is dated 1970-01-01 (`ZERO_AR_DATE`).
- **Signature.** `codesign --verify --strict` passes on both App.app copies, and `codesign -dv` shows `Signature=adhoc` with no team.
- **Info.plist.** It records only the toolchain (DTXcode 2700, DTSDKBuild 26A425, BuildMachineOSBuild 25G5057c). No path, user or time is in it.

## Leak check

- `strings -a <file> | grep -cE '/Users/|josephilhan|e14s4|app-repro|/tmp/|/private/|verify-a|longer-path'` gave 0 for `app` and App in both runs. For `libapp_ffi.a` it gave 1 in both runs, a false positive: the hit is `/cargo/registry/src/index.crates.io-…/serde_core-1.0.229/src/private/doc.rs`, a file inside that crate.
- `grep -rlaE 'josephilhan|/Users/|e14s4|app-repro|longer-path'` over each whole output folder, excluding `xcodebuild.log` and `BUILDINFO`, gave 0 files. BUILDINFO records `Build path: /private/tmp/app-repro` on purpose, as Debian's `.buildinfo` does.
- The crate paths left in the binaries for panic messages read `/cargo/registry/src/…` and `/rustc/<commit>/…`, the fixed names of LD-222.

## Bill of materials against cargo metadata

`sbom.cdx.json` has 155 components: 153 crates, `uniffi_bindgen` (its templates are App's Swift glue) and the Rust standard library. I checked it two ways, neither of them `cargo tree`, which is what the script uses.

1. **Upper bound: `cargo metadata`'s resolve graph.** I walked `cargo metadata --locked --filter-platform aarch64-apple-darwin` (and again with `--features app-ffi/net`) from `app-cli` and `app-ffi`. The walk follows normal edges only and does not descend into proc macros. It reached 186 crates, and every SBOM component is among them except the standard library, which is not a cargo package. So no dev-only crate is listed. The walk has 32 crates the SBOM leaves out, because `cargo metadata` unifies features across the whole workspace and its dev-dependencies, while the script builds each product in its own cargo run:
   - 10 are in App's own tree only under the `uniffi_macros` proc macro, which runs at build time: camino, fs-err, serde_spanned, siphasher, toml, toml_datetime, toml_parser, toml_writer, uniffi_meta, winnow. `cargo tree -p app-ffi --features net -i <crate>` shows each one.
   - 18 are in neither product's own resolution. `cargo tree -i <crate>` for each product prints "did not match any packages". They are uniffi's generator, which the `uniffi-bindgen` workspace member turns on, and `cargo tree -p uniffi-bindgen -i <crate>` finds each one: askama, askama_macros, cargo-platform, cargo_metadata, clap_derive, glob, goblin, minimal-lexical, nom, plain, scroll, scroll_derive, semver, smawk, strsim, textwrap, uniffi_udl, weedle2.
   - 4 are edges that `cargo metadata`'s graph lists for features that no build turns on. `cargo tree --workspace --all-features -e all --target all -i <crate>` prints "nothing to print" for each:
     - des, zlib-rs and unicode-width are optional dependencies whose feature is off on the parent's own node: ssh-cipher has no `tdes`, flate2 no `zlib-rs`, textwrap no `unicode-width`.
     - time-macros: metadata marks `time`'s `macros` feature on, but `cargo tree -e features` over the whole workspace with every feature shows only `alloc`, `default` and `std`. The shipped `time` (through zxcvbn) has the same three.

   The same unification is why the walk also puts clap, clap_builder, clap_lex and anstyle in App.app. `cargo tree -p app-ffi --features net -i clap` finds no clap, and the binaries agree (see 2).
2. **Lower bound: what is inside the binaries.** I took every `/cargo/registry/src/<index>/<crate>-<version>` path from `strings -a` of each shipped binary. Those are the crates whose code is linked. `app` holds 30, `libapp_ffi.a` 81 and App 68. Every one of them is in the SBOM with that product in its `app:ships-in` property. None of the 32 left-out crates has code in any binary, and clap_builder and clap_lex appear only in `app`.

The SBOM sits between the two bounds, and the only crates it leaves out are build-time ones.

Other fields:

- **Checksums.** Every crates.io component's SHA-256 equals its `Cargo.lock` checksum, and its purl is `pkg:cargo/<name>@<version>`.
- **Vendored crates.** Both vendored crates (`vendor/zxcvbn` 3.1.1, `vendor/ssh-key` 0.7.0-rc.11) carry `pedigree` with the upstream purl and no checksum, and both are in the notices table.
- **App's own crates.** They have no license entry (D2, the owner's).

## Third-party notices against the crates' own files

- **Licenses.** For all 145 third-party crates, the SBOM's license expression equals the crate's own `license` field from `cargo metadata` (the old `A/B` form read as `A OR B`), and the notices table has the same row. 0 mismatches.
- **License files.** Every license, copying, notice, copyright or authors file that a crate publishes in its folder is attached in the notices under that crate's name. 0 missing, and fancy-regex's AUTHORS is there.
- **Text per term.** For each crate, at least one OR choice has a text for every AND term among the texts attached to it (matched on each license's own wording). That holds for 145 of 145. `ring` (`Apache-2.0 AND ISC`) has both.
- **Crates without a license file.** The 10 crates that publish none (objc2 and uniffi crates) get the standard MIT or MPL-2.0 text from `scripts/licenses/`, named as such.
- **Expressions in use:** MIT OR Apache-2.0 (84), Apache-2.0 OR MIT (31), MIT (10), MPL-2.0 (6), Unlicense OR MIT (3), BSD-3-Clause (3), MIT OR Zlib OR Apache-2.0 (2), ISC (2), and one each of 0BSD OR MIT OR Apache-2.0, Zlib OR Apache-2.0 OR MIT, Apache-2.0 AND ISC, Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT, and Apache-2.0 OR ISC OR MIT.
- **Where they live.** The notices and the SBOM are release outputs under `target/repro/` and are not kept in the tree (LD-222 (4), LD-226 (5)). This report quotes no copyright line.

## Run check

- `app --version` from run A printed `0.1.0`, rc=0.
- App.app was not launched, so no window could reach the owner's screen (rule 10). Its executable is byte-identical to the one Checker 1 built.

## Not covered (no change to the verdict)

- **Other toolchain or machine.** A different user account, home folder, toolchain or macOS build is not tested. BUILDINFO names what a rebuild needs, as the Reproducible Builds definition allows.
- **Signing.** Developer ID signing and notarization (D7, E14-S3) will change the signature. The comparison then has to be made with the signature removed. Today App.app is signed ad hoc, and the two ad-hoc signatures are equal.
- **x86_64 slice.** It waits for E14-S3.
- **Schema.** The SBOM is not validated against the official CycloneDX 1.6 schema, because that needs a download.
- **One run at a time.** The script uses one fixed folder, so only one run can happen on this Mac at a time.
- **Hashes.** They come from today's source with the `hwkey` stub. Any code edit changes them, so a later check compares its own two runs.

## Cleanup

- I stopped the `ibtoold` daemons by PID after checking that their environment named my copy: 45898 and 45899 after run A, and 55170 and 55944 after run B. I left 46312 and 46313 running, because their working folder was `/tmp/e13s6g-verify-copy`, another agent's.
- All my `/tmp/e14s4-verify*` folders and logs are deleted, and `/private/tmp/app-repro` does not exist.
- `scripts/check.sh` was not run.
