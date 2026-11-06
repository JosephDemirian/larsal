# Own every dependency: research (E0-S7)

Story: E0-S7 in [plan/epics.md](../../plan/epics.md). Ruling: LD-221 in [spec/decisions.md](../decisions.md). Owner direction 2026-10-29: no outside dependencies; every package becomes Larsal's own copy in the tree; small ones are replaced by our own code; crypto is copied unchanged, only cut to what we use.

Date: 2026-10-29. Research only: no build file and no product code was changed (E14-S4 edits the build files now; E0-S7 builds after it).

## 1. Summary

- **259 outside packages**: 254 from crates.io in `Cargo.lock`, the 2 patched copies already in `vendor/` (zxcvbn LD-136, ssh-key LD-209), and 3 more that only `fuzz/Cargo.lock` has (libfuzzer-sys, arbitrary, jobserver). Our crates name 44 of them directly (LD-221 counted 40), the fuzz workspace one more.
- **What they are**: 142 are compiled into Larsal or the `larsal` tool (18 of them only with the `net` feature, 2 only in larsal-hwkey, which nothing links yet), 48 run only at build time, 13 only in tests, 3 only in fuzzing, 31 are for other systems and never compile on a Mac, 22 sit in `Cargo.lock` only (optional features nobody turns on).
- **Disposition**: 16 replace (R), 35 copy and trim (T), 70 crypto copy (C), 75 tool copy (B), 10 gone when a replacement lands (G), 53 cut because they are never built for Larsal on a Mac (X).
- **Effect**: Larsal's own compile goes from 142 outside packages to 104 (plus our own `log` facade) once the 16 replacements and the uniffi trim land.
- **Size**: a plain `cargo vendor` brings 212 MB and 2.70 million lines of Rust; 1.42 million of those lines are the 53 cut packages (the two windows-sys versions alone are 719,000).

Top 10 replace candidates, in build order (smallest risk first):

| # | Package | What we write instead | Our lines (estimate) | Also leaves Larsal |
|---|---|---|---|---|
| 1 | lazy_static | `std::sync::LazyLock` in our zxcvbn copy | 0 | - |
| 2 | itertools | `join` (2 call sites) and `unique` (1) in our zxcvbn copy | 15 | either |
| 3 | time | the current year from `SystemTime` in our zxcvbn copy (3 call sites) | 15 | time-core, deranged, powerfmt, num-conv |
| 4 | thiserror | `Display` and `Error` impls for our 18 error enums (144 messages) | 40 (one `macro_rules!`) | (thiserror-impl stays only for cargo_metadata, build time) |
| 5 | base64 | a wrapper over base64ct, the constant-time crate we keep anyway | 25 | - |
| 6 | log | a no-op facade: dependencies never log (rule 4) | 40 | - |
| 7 | regex | zxcvbn's 3 patterns on regex-automata, which Larsal already ships | 10 | aho-corasick |
| 8 | getrandom 0.4 | `getentropy` through libc in larsal-crypto, the call getrandom makes on macOS | 30 | - (needs a line in LD-221, finding F8) |
| 9 | clap | Larsal's own option parser in larsal-cli (INT-10.2) | 180 | clap_builder, clap_lex, anstyle, strsim |
| 10 | ico | Larsal's own ICO directory and BMP decoder in larsal-core | 170, plus 60 in tests | - |

The other six: fancy-regex (60 lines in zxcvbn; bit-set and bit-vec leave), serde_json and serde (about 300 lines; serde_core and zmij leave), percent-encoding and utf8-zero (cut inside our ureq copy), static_assertions (5 lines inside our uniffi_core copy).

## 2. How proven projects do it (rule 9)

### Firefox

- Every third-party Rust crate is vendored into `third_party/rust`; the build never downloads. `mach vendor rust` vendors, checks licenses and runs `cargo vet`: "All vendored crates must be audited." It also notes that "all dependencies will be vendored, even ones that aren't used due to disabled features". Source: <https://firefox-source-docs.mozilla.org/build/buildsystem/rust.html>
- Crates Firefox does not want are replaced through `[patch.crates-io]` in the top-level `Cargo.toml` by small crates in `build/rust/`: empty crates for r-efi, redox_syscall, redox_users and hermit-abi; a smaller windows-targets; dummy oslog and terminal_size; and old versions mapped onto new ones (base64 0.21 to 0.22, itertools 0.13 and 0.14 to 0.15, wasi 0.11 to 0.14) by a crate that only re-exports the new one. The empty r-efi crate has version 5.999.999 and no code. Sources: <https://github.com/mozilla-firefox/firefox/blob/main/Cargo.toml>, <https://github.com/mozilla-firefox/firefox/blob/main/build/rust/r-efi/Cargo.toml>, <https://github.com/mozilla-firefox/firefox/blob/main/build/rust/base64/lib.rs>
- `supply-chain/config.toml` imports the audits of Google, Mozilla, Bytecode Alliance, ISRG and Embark; `supply-chain/audits.toml` holds 1,431 of Firefox's own audits. Sources: <https://github.com/mozilla-firefox/firefox/blob/main/supply-chain/config.toml>, <https://github.com/mozilla-firefox/firefox/blob/main/supply-chain/audits.toml>

### Chromium

- Crates live in `third_party/rust/chromium_crates_io/vendor/<crate>-v<epoch>/`; `gnrt vendor` downloads them and applies the patches kept in `chromium_crates_io/patches/<crate>/`; each crate gets a `README.chromium`. Source: <https://chromium.googlesource.com/chromium/src/+/main/third_party/rust/README.md>
- `gnrt vendor` writes `{"files":{}}` as each crate's `.cargo-checksum.json` and removes the checksums from `Cargo.lock`; it deletes per-crate files listed under `remove_vendored_files`; and it turns crates listed in `remove_crates`, and crates not resolved for Chromium's platforms, into placeholder crates (same name, version, dependencies and feature names; an empty `lib.rs`). Source: <https://chromium.googlesource.com/chromium/src/+/main/tools/crates/gnrt/vendor.rs>
- Every import and every update is reviewed by `//third_party/rust/OWNERS`: a reviewer looks at each `unsafe` block (the rule of 2) and checks that `build.rs` and proc macros keep the build hermetic. A shipping crate whose `unsafe` fails review moves to the `sandbox` group and may not run in a privileged process. Sources: <https://chromium.googlesource.com/chromium/src/+/main/third_party/rust/OWNERS-review-checklist.md>, <https://chromium.googlesource.com/chromium/src/+/main/third_party/rust/README-importing-new-crates.md>
- Updates come from a weekly rotation that runs `create_update_cl.py`. `global-min-publish-age = "14 days"`: cargo only takes versions published at least 14 days earlier, "This reduces the risk of ingesting a malicious release before it is detected and yanked." A security fix may skip the wait for one crate. Chromium keeps its cargo vet audits in `supply-chain/audits.toml`, imported into Google's audit set. Sources: <https://chromium.googlesource.com/chromium/src/+/main/tools/crates/create_update_cl.md>, the README above.

### Android

- `external/rust/android-crates-io` holds the crates.io crates, managed by `crate_tool`; "Most of the files here should not be edited manually, and pre-upload checks will catch and prevent such changes." Build rules come from `cargo_embargo.json`. Updates: `crate_tool update <crate> <version>`, with `analyze-updates` and `suggest-updates`. Patches live in `patches/` and are re-applied on update, but "You should avoid creating patches, if possible. Every patch file is an ongoing operational burden". Sources: <https://android.googlesource.com/platform/external/rust/android-crates-io/+/refs/heads/main/README.md>, <https://android.googlesource.com/platform/development/+/main/tools/cargo_embargo/>

### Fuchsia

- External crates live in `//third_party/rust_crates/vendor`, chosen by `//third_party/rust_crates/Cargo.toml`; `fx update-rustc-third-party` downloads them and updates `Cargo.toml` and `Cargo.lock`. Adding a crate needs the Open Source Review Board's approval first; an update needs it again when the license changes or a new crate comes in. Forks go through `[patch.crates-io]`. Source: <https://fuchsia.dev/fuchsia-src/development/languages/rust/external_crates>

### Cargo

- `cargo vendor` "will vendor all crates.io and git dependencies"; it deletes the existing vendor folder unless `--no-delete` is given; `--versioned-dirs` puts the version in every folder name; `-s <manifest>` adds another workspace (our `fuzz/`). "Cargo treats vendored sources as read-only": to change a crate, use `[patch]` or a path dependency. Source: <https://doc.rust-lang.org/cargo/commands/cargo-vendor.html>
- It copies every package in `Cargo.lock` for every platform; Cargo has no platform filter (issue rust-lang/cargo#7058; the outside tool cargo-vendor-filterer exists only for this). Sources: <https://github.com/rust-lang/cargo/issues/7058>, <https://github.com/cgwalters/cargo-vendor-filterer>
- Source replacement: `[source.crates-io] replace-with` a `directory` source. Each crate there has a `.cargo-checksum.json` "to protect against accidental modifications. It is not a security mechanism". Cargo assumes "the source code is exactly the same from both sources". Source: <https://doc.rust-lang.org/cargo/reference/source-replacement.html>
- `[patch]`: <https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html>. `net.offline`: <https://doc.rust-lang.org/cargo/reference/config.html#netoffline>

### cargo vet

- Records audits per crate version in `supply-chain/audits.toml` against criteria. safe-to-run: the crate "can be compiled, run, and tested on a local workstation or in controlled automation" without surprises. safe-to-deploy: it "will not introduce a serious security vulnerability to production software exposed to untrusted input"; the auditor must reason about every `unsafe` block and powerful import. An update can be covered by a delta audit of the diff. Other organizations' audits are imported and cached in `imports.lock` (`--locked` skips fetching); a central registry lists published sets (Mozilla, Google, Bytecode Alliance, ISRG, Zcash and others). Sources: <https://mozilla.github.io/cargo-vet/>, <https://mozilla.github.io/cargo-vet/built-in-criteria.html>, <https://mozilla.github.io/cargo-vet/importing-audits.html>, <https://github.com/mozilla/cargo-vet/blob/main/registry.toml>

### Security advisories for copied crates

- RustSec advisories are matched by package name and version from `Cargo.lock` (cargo audit, cargo deny; <https://rustsec.org/>). Source replacement keeps the crates.io source in `Cargo.lock`, so plain vendored copies stay covered. The projects above take a fix by updating the copy: Chromium a one-crate update that skips the 14-day wait, Android `crate_tool update`, Firefox `mach vendor rust` with a vet audit of the diff.
- Proven here (finding F2): cargo audit reports nothing for a package without a source in `Cargo.lock`, which is how a `[patch]` path copy appears. Path copies need a check of their own.

### What Larsal takes from this

1. One folder of plain copies, made once by `cargo vendor`, used through source replacement, never re-made wholesale (all four projects).
2. Code we change lives in `[patch]` path copies (Cargo's rule; Firefox `build/rust`; our LD-136 and LD-209 copies). Copies that only lose whole files stay plain copies with a rewritten checksum file (Chromium `remove_vendored_files`), and the original checksum file is kept for the diff proof.
3. Packages never built on a Mac are cut from their parents' manifests, or become empty placeholder crates (Chromium removed crates, Firefox's empty crates).
4. Every copy and every update is reviewed: `unsafe` blocks, build scripts, proc macros (Chromium checklist, cargo vet safe-to-deploy). Larsal's AT-J03 review is this review.
5. Updates take versions at least 14 days old unless they fix an advisory (Chromium); a cut is preferred to a patch where it is enough (Android).
6. Advisories keep running on name and version; path copies get their own audit list (F2).

## 3. Findings in this tree

- **F1 `vendor/` itself cannot be the directory source.** Probe (cargo 1.99.1, a scratch project under /tmp, empty `CARGO_HOME`): a directory source holding one crate folder without `.cargo-checksum.json` fails with "failed to load source for dependency `foo`" (caused by "No such file or directory"). `vendor/zxcvbn` and `vendor/ssh-key` have no checksum file, and `cargo vendor` empties its target folder by default. So the plain copies go to `vendor/crates-io/` and the two patched copies stay where they are. The same probe showed that a checksum file of `{"files":{},"package":null}` is accepted.
- **F2 cargo audit does not see path copies.** Probe: a two-entry `Cargo.lock` with time 0.1.40. With `source = "registry+https://github.com/rust-lang/crates.io-index"`, `cargo audit --no-fetch` reports RUSTSEC-2020-0071; the same entry without a source reports nothing. Today `vendor/zxcvbn` (3.1.1) and `vendor/ssh-key` (0.7.0-rc.11) are not checked by the audit gate of `scripts/check.sh`. Step 1 (6d) closes this.
- **F3 Step 1 needs no network.** All 257 `.crate` files are in the local cargo cache (33 MB), so `cargo vendor --offline` works.
- **F4 Size.** A plain vendor is 212 MB unpacked and 2.70 million Rust lines. The 53 cut packages are 1.42 million of them: windows-sys 0.52 and 0.61 (719,000), linux-raw-sys (479,000), fiat-crypto (93,000).
- **F5 14 shipped packages have no license file**: objc2, objc2-encode, objc2-foundation, objc2-app-kit, objc2-core-foundation, objc2-io-kit and the 8 uniffi crates (6 others are cut packages). LD-222 (3) already supplies the standard text from `scripts/licenses/`; the copy check must accept that for these 14.
- **F6 uniffi compiles unused code into larsal-ffi.** uniffi 0.32.2 always depends on uniffi_pipeline, which the runtime does not use; through it tempfile, fastrand, rustix, errno, heck, indexmap, hashbrown, equivalent and getrandom 0.4 compile into larsal-ffi (deny.toml: not linked). A manifest trim of our uniffi copy takes them out of Larsal's build.
- **F7 rustls is crypto here.** LD-221 (4) lists rustls with the large non-crypto packages to trim. rustls and rustls-webpki run the TLS key schedule and the certificate checks, so this research puts them under rule (3): cut files and features only, never change code. The lead confirms.
- **F8 getrandom and rule 3.** LD-221 (2) names "getrandom's one call" for replacement; rule 3 says random numbers come only from approved crates. The replacement calls the same OS function getrandom 0.4 calls on macOS (`getentropy`, at most 256 bytes per call). It needs one line in LD-221; until then getrandom 0.4 stays a crypto copy.
- **F9 Unused pin.** `data-encoding` is pinned in `[workspace.dependencies]` but no crate uses it; it is in `Cargo.lock` only through rcgen's optional `x509-parser` feature.
- **F10 Two syn generations.** syn 3.0.9 (thiserror-impl, serde_derive, clap_derive, askama_derive) and syn 2.0.119 (uniffi, curve25519-dalek-derive, scroll_derive): both build time only (B). Not a problem for Larsal; noted because every proc macro runs code at build time and AT-J03 reviews it.

## 4. Method

Read-only commands, no builds:

- `cargo metadata --offline --locked --format-version 1 --all-features`
- Larsal: `cargo tree --offline --locked -e normal,no-proc-macro --target <t>` for `-p larsal-ffi --features net`, `-p larsal-ffi`, `-p larsal-cli`, `-p larsal-hwkey`, with `<t>` = aarch64-apple-darwin and x86_64-apple-darwin.
- Build time: `cargo tree --offline --locked --workspace --all-features -e normal,build --target <t>`.
- Tests and other systems: `cargo tree --offline --locked --workspace --all-features -e normal,build,dev` for both Mac targets and for `--target all`.
- Fuzz: the same on `--manifest-path fuzz/Cargo.toml`; its lock differs from the root lock only by larsal-fuzz, libfuzzer-sys, arbitrary and jobserver.
- Lines: non-blank `.rs` lines that do not start with `//`, outside `tests/`, `benches/`, `examples/` and `fuzz/`, in `~/.cargo/registry/src` (in `vendor/` for the two patched copies); build scripts count. Unsafe: the number of `unsafe {` in those lines (blocks only; `unsafe fn` and `unsafe impl` are not counted).
- Our use: grep of `crates/*/src`, `crates/*/tests` and `vendor/zxcvbn/src`.
- Gone: a graph from the `cargo tree` output; each replacement removes its edges; packages no longer reachable from our crates are gone. aho-corasick is counted gone because regex-automata pulls it only through `perf-literal`, which only regex turns on (regex-automata 0.4.18 `Cargo.toml`).
- Kind: Larsal = compiled into larsal-ffi (with `net`), larsal-cli or larsal-hwkey for a Mac target; build = build scripts, proc macros and the bindings generator only; test = dev-dependencies only; fuzz = the fuzz workspace only; other OS = only with `--target all`; lock only = in `Cargo.lock` but in no tree.

## 5. Disposition rules

- **R replace**: our code, or a copy we already change (zxcvbn, ureq, uniffi_core), calls the package, and our version is small (about 200 lines or less). serde_json is the one bigger case (about 300 lines), chosen because it takes 4 packages and 32,000 lines out of Larsal. The test that proves each one is named in the build order.
- **T copy and trim**: large or deep non-crypto code. Copy it, cut unused features, platforms and modules, do not rewrite it. "copy whole" means nothing worth cutting.
- **C crypto copy**: crypto, key handling and TLS, plus the small crates those copies need unchanged ("support"). The code stays byte-for-byte upstream; only files and features we never build are cut; AT-B01 known answers run on the copies.
- **B tool copy**: build time, test or fuzz only. Copy whole; lowest priority; cuts are welcome but not needed.
- **G gone**: transitive only; it disappears when the named replacement lands, so no copy is kept after that.
- **X cut**: never compiled for Larsal on a Mac. Step 1 copies it, step 2 removes it by cutting the parent's optional feature or target table, or by an empty placeholder crate.

A package we replace but that a tool still needs (thiserror, serde, clap, time, getrandom 0.4) stays as a tool copy until that tool changes; its row says so.

Crypto column: yes = crypto; key = key handling (key encodings, certificates, wiping, constant time); support = needed unchanged by a crypto copy; no = not crypto.

## 6. Counts

By kind and disposition:

| Kind | R | T | C | B | G | X | All |
|---|---|---|---|---|---|---|---|
| Larsal | 13 | 25 | 62 | 14 | 8 | 0 | 122 |
| Larsal (net) | 3 | 8 | 7 | 0 | 0 | 0 | 18 |
| Larsal (hwkey) | 0 | 2 | 0 | 0 | 0 | 0 | 2 |
| build | 0 | 0 | 1 | 45 | 2 | 0 | 48 |
| test | 0 | 0 | 0 | 13 | 0 | 0 | 13 |
| fuzz | 0 | 0 | 0 | 3 | 0 | 0 | 3 |
| other OS | 0 | 0 | 0 | 0 | 0 | 31 | 31 |
| lock only | 0 | 0 | 0 | 0 | 0 | 22 | 22 |
| All | 16 | 35 | 70 | 75 | 10 | 53 | 259 |

Rust lines by disposition (as copied today, before any cut): R 84,948; T 554,175; C 230,986; B 379,169; G 39,858; X 1,424,649. The 14 Larsal rows marked B are compiled into Larsal today only through uniffi_pipeline (9) and through time in zxcvbn (4), and serde_core; they leave Larsal with the uniffi trim and the zxcvbn and serde_json replacements but stay for build or tests.

Packages leaving Larsal's compile (37) when every R lands with the uniffi trim: aho-corasick, anstyle, base64, bit-set 0.8, bit-vec 0.8, clap, clap_builder, clap_lex, deranged, either, equivalent, errno, fancy-regex, fastrand, getrandom 0.4, hashbrown, heck, ico, indexmap, itertools, lazy_static, num-conv, percent-encoding, powerfmt, regex, rustix, serde, serde_core, serde_json, static_assertions, tempfile, thiserror, time, time-core, uniffi_pipeline, utf8-zero, zmij. `log` stays in Larsal as our own facade.

## 7. Every package

Pulled in by: "direct" names our crates (larsal-fuzz is the fuzz workspace, uniffi-bindgen our bindings generator); "via" names the packages that depend on it. Lines and unsafe as in section 4.

| Package | Version | License | Pulled in by | Kind | Rust lines | unsafe blocks | Crypto | Disp. | Notes |
|---|---|---|---|---|---|---|---|---|---|
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | via miniz_oxide 0.8.9, miniz_oxide 0.9.1 | Larsal | 218 | 0 | no | T | copy whole (small, used by copies we do not edit) |
| aead | 0.6.1 | MIT OR Apache-2.0 | via aes-gcm, ssh-cipher | Larsal | 441 | 0 | yes | C |  |
| aes | 0.9.3 | MIT OR Apache-2.0 | direct: larsal-crypto; via aes-gcm, ssh-cipher | Larsal | 3,015 | 60 | yes | C |  |
| aes-gcm | 0.11.1 | Apache-2.0 OR MIT | via ssh-cipher | Larsal | 211 | 0 | yes | C |  |
| aho-corasick | 1.1.5 | Unlicense OR MIT | via regex, regex-automata | Larsal | 11,729 | 52 | no | G | gone with regex (regex-automata's perf-literal is turned on only by regex) |
| anstyle | 1.0.14 | MIT OR Apache-2.0 | via clap_builder | Larsal | 1,091 | 1 | no | G | gone with clap |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | via uniffi, uniffi_bindgen, uniffi_core, uniffi_internal_macros +3 | Larsal | 2,420 | 67 | no | T | uniffi runtime error type; copy whole |
| arbitrary | 1.5.0 | MIT OR Apache-2.0 | via libfuzzer-sys | fuzz | 2,130 | 5 | no | B | fuzz workspace only; libfuzzer-sys bundles LLVM libFuzzer C++ source (NCSA) |
| argon2 | 0.6.0 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 1,440 | 9 | yes | C |  |
| askama | 0.16.1 | MIT OR Apache-2.0 | via uniffi_bindgen | build | 3,780 | 5 | no | B | build time |
| askama_derive | 0.16.1 | MIT OR Apache-2.0 | via askama_macros | build | 10,822 | 9 | no | B | build time |
| askama_macros | 0.16.1 | MIT OR Apache-2.0 | via askama | build | 16 | 0 | no | B | build time |
| askama_parser | 0.16.1 | MIT OR Apache-2.0 | via askama_derive | build | 6,841 | 5 | no | B | build time |
| asn1-rs | 0.7.2 | MIT OR Apache-2.0 | via der-parser, oid-registry, x509-parser | lock only | 7,113 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| asn1-rs-derive | 0.6.0 | MIT OR Apache-2.0 | via asn1-rs | lock only | 799 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| asn1-rs-impl | 0.2.0 | MIT/Apache-2.0 | via asn1-rs | lock only | 86 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| autocfg | 1.5.1 | Apache-2.0 OR MIT | via fs-err, num-traits | build | 532 | 0 | no | B | build time |
| base16ct | 1.0.0 | Apache-2.0 OR MIT | via elliptic-curve, sec1 | Larsal | 221 | 4 | key | C | key encodings |
| base64 | 0.23.1 | MIT OR Apache-2.0 | direct: larsal-core, larsal-ffi, larsal-format, larsal-fuzz, larsal-sshagent; via ureq, ureq-proto | Larsal | 6,014 | 10 | no | R | a 25-line wrapper in larsal-crypto over base64ct (already kept): standard encode, padded and padding-indifferent decode, `decode_slice`, length helpers, URL-safe no-pad encode; the ureq copies drop basic auth and proxy (their only base64 use) |
| base64ct | 1.8.3 | Apache-2.0 OR MIT | via argon2, pem-rfc7468, ssh-encoding | Larsal | 1,348 | 4 | key | C | constant-time base64 for keys; also carries Larsal's base64 (see base64) |
| basic-toml | 0.1.10 | MIT OR Apache-2.0 | via askama_derive | build | 2,678 | 0 | no | B | build time (askama); RUSTSEC-2026-0374 unmaintained, ignored in deny.toml |
| bcrypt-pbkdf | 0.11.0 | MIT OR Apache-2.0 | direct: larsal-crypto; via ssh-key | Larsal | 211 | 0 | yes | C |  |
| bit-set | 0.11.1 | Apache-2.0 OR MIT | via proptest | test | 596 | 2 | no | B | tests only (proptest) |
| bit-set | 0.8.0 | Apache-2.0 OR MIT | via fancy-regex | Larsal | 1,005 | 2 | no | G | gone with fancy-regex |
| bit-vec | 0.10.1 | Apache-2.0 OR MIT | via bit-set 0.11.1, proptest | test | 2,252 | 0 | no | B | tests only (proptest) |
| bit-vec | 0.8.0 | Apache-2.0 OR MIT | via bit-set 0.8.0 | Larsal | 1,947 | 0 | no | G | gone with fancy-regex |
| bit-vec | 0.9.1 | Apache-2.0 OR MIT | via bit-set, proptest, yasna | lock only | 2,144 | 0 | no | X | lock only: an optional `borsh` feature, never on |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | via objc2-app-kit, objc2-core-foundation, objc2-foundation, objc2-io-kit +4 | Larsal | 4,718 | 0 | no | T | objc2 generated types, png, security-framework; copy whole |
| blake2 | 0.11.0 | MIT OR Apache-2.0 | via argon2 | Larsal | 705 | 1 | yes | C |  |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 | via cipher, digest | Larsal | 474 | 18 | yes | C |  |
| blowfish | 0.10.0 | MIT OR Apache-2.0 | via bcrypt-pbkdf | Larsal | 385 | 0 | yes | C |  |
| borsh | 1.8.1 | MIT OR Apache-2.0 | via bit-vec | lock only | 2,934 | 5 | no | X | lock only: an optional `borsh` feature, never on |
| borsh-derive | 1.8.1 | Apache-2.0 | via borsh | lock only | 4,439 | 0 | no | X | lock only: an optional `borsh` feature, never on |
| byteorder | 1.5.0 | Unlicense OR MIT | via blowfish, ico | Larsal | 2,719 | 39 | support | C | only blowfish needs it once ico is replaced |
| bytes | 1.12.1 | MIT | via combine, http, uniffi_core | Larsal | 4,059 | 62 | no | T | uniffi_core buffers and http; cut serde and loom parts |
| camino | 1.2.6 | MIT OR Apache-2.0 | via cargo_metadata, uniffi, uniffi_bindgen, uniffi_macros | build | 1,804 | 32 | no | B | build time |
| cargo-platform | 0.3.3 | MIT OR Apache-2.0 | via cargo_metadata | build | 579 | 0 | no | B | build time |
| cargo_metadata | 0.23.1 | MIT | via uniffi, uniffi_bindgen | build | 1,244 | 0 | no | B | build time |
| cbc | 0.2.1 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 368 | 0 | yes | C |  |
| cc | 1.10.0 | MIT OR Apache-2.0 | via libfuzzer-sys, ring | build | 8,675 | 30 | no | B | build time: ring's build script (and libfuzzer-sys) |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | via chacha20, crc32fast, curve25519-dalek, getrandom 0.2.17 +6 | Larsal | 143 | 0 | support | C | needed unchanged by the crypto copies |
| cfg_aliases | 0.2.2 | MIT | via borsh | lock only | 147 | 0 | no | X | lock only: an optional `borsh` feature, never on |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 | direct: larsal-crypto; via proptest, ssh-cipher | Larsal | 1,984 | 23 | yes | C |  |
| cipher | 0.5.2 | MIT OR Apache-2.0 | via aes, aes-gcm, blowfish, cbc +5 | Larsal | 1,852 | 0 | yes | C |  |
| clap | 4.6.7 | MIT OR Apache-2.0 | direct: larsal-cli; via uniffi | Larsal | 284 | 0 | no | R | own option parser in larsal-cli args.rs (about 180 lines): long and short options, `--name=value`, `-xvalue`, combined short flags, `--`, hidden aliases, ordered positionals with required, set/append/flag, `-h`/`--help`, and the five error kinds `problem()` maps (INT-10.2); stays a tool copy under uniffi's `cli` feature until our own bindgen main |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 | via clap | Larsal | 15,921 | 0 | no | G | gone with clap (Larsal) and the bindgen main (build) |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 | via clap | build | 3,931 | 0 | no | G | gone with the bindgen main |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 | via clap_builder | Larsal | 329 | 5 | no | G | gone with clap |
| cmov | 0.5.4 | Apache-2.0 OR MIT | via ctutils | Larsal | 1,309 | 21 | key | C | memory wiping and constant-time helpers |
| combine | 4.6.9 | MIT | via jni | other OS | 11,663 | 12 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| const-oid | 0.10.2 | Apache-2.0 OR MIT | via der, digest | Larsal | 6,428 | 1 | key | C | key encodings |
| core-foundation | 0.10.1 | MIT OR Apache-2.0 | via rustls-platform-verifier, security-framework | Larsal (net) | 2,850 | 164 | no | T | net only (trust evaluation under rustls-platform-verifier); keep trust, certificate, policy, base; cut keychain-item, authorization, secure-transport modules until a story needs them |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 | via core-foundation, rustls-platform-verifier, security-framework, security-framework-sys | Larsal (net) | 4,594 | 1 | no | T | net only (trust evaluation under rustls-platform-verifier); keep trust, certificate, policy, base; cut keychain-item, authorization, secure-transport modules until a story needs them |
| core_detect | 1.0.0 | MIT/Apache-2.0 | via proptest | test | 456 | 7 | no | B | tests only (proptest) |
| cpubits | 0.1.1 | MIT OR Apache-2.0 | via aes, crypto-bigint, polyval | Larsal | 236 | 0 | support | C | needed unchanged by the crypto copies |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 | via aes, argon2, chacha20, curve25519-dalek +4 | Larsal | 439 | 8 | support | C | needed unchanged by the crypto copies |
| crc32fast | 1.5.3 | MIT OR Apache-2.0 | via flate2, png | Larsal | 1,448 | 2 | no | T | copy whole (small, used by copies we do not edit) |
| crypto-bigint | 0.7.10 | Apache-2.0 OR MIT | via elliptic-curve, primefield, rfc6979 | Larsal | 35,069 | 14 | yes | C |  |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 | via aead, cipher, digest, elliptic-curve +2 | Larsal | 594 | 0 | yes | C |  |
| ctr | 0.10.1 | MIT OR Apache-2.0 | via aes-gcm | Larsal | 692 | 0 | yes | C |  |
| ctutils | 0.4.6 | Apache-2.0 OR MIT | via aes-gcm, crypto-bigint, digest, sec1 +4 | Larsal | 2,793 | 0 | key | C | memory wiping and constant-time helpers |
| curve25519-dalek | 5.0.0 | BSD-3-Clause | via ed25519-dalek | Larsal | 27,544 | 31 | yes | C | cut fiat backend files and its target table (fiat-crypto leaves), docs/, vendor/ (notes, Sage scripts) |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 | via curve25519-dalek | build | 421 | 2 | yes | C | build-time proc macro of the x86_64 AVX2 backend; keep unchanged |
| data-encoding | 2.11.1 | MIT | via x509-parser | lock only | 1,548 | 6 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| der | 0.8.2 | Apache-2.0 OR MIT | via ecdsa, sec1 | Larsal | 9,942 | 4 | key | C | key encodings |
| der-parser | 10.0.0 | MIT OR Apache-2.0 | via x509-parser | lock only | 2,728 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| deranged | 0.5.9 | MIT OR Apache-2.0 | via time | Larsal | 2,360 | 55 | no | B | tests only once time is replaced in zxcvbn (rcgen keeps time) |
| des | 0.9.0 | MIT OR Apache-2.0 | via ssh-cipher | lock only | 679 | 0 | yes | X | lock only: ssh-cipher's `tdes` feature, never on |
| digest | 0.11.3 | MIT OR Apache-2.0 | via blake2, curve25519-dalek, ecdsa, elliptic-curve +6 | Larsal | 2,152 | 0 | yes | C |  |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 | via asn1-rs, der-parser | lock only | 611 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| ecdsa | 0.17.0 | Apache-2.0 OR MIT | via p256 | Larsal | 2,459 | 0 | yes | C |  |
| ed25519 | 3.0.0 | Apache-2.0 OR MIT | via ed25519-dalek | Larsal | 477 | 0 | yes | C |  |
| ed25519-dalek | 3.0.0 | BSD-3-Clause | direct: larsal-crypto | Larsal | 1,742 | 0 | yes | C |  |
| either | 1.19.0 | MIT OR Apache-2.0 | via itertools | Larsal | 1,286 | 2 | no | G | gone with itertools |
| elliptic-curve | 0.14.2 | Apache-2.0 OR MIT | via ecdsa, p256, primeorder | Larsal | 3,748 | 4 | yes | C |  |
| equivalent | 1.0.3 | Apache-2.0 OR MIT | via indexmap | Larsal | 29 | 0 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim build time only |
| errno | 0.3.14 | MIT OR Apache-2.0 | via rustix | Larsal | 318 | 12 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim only bindgen and proptest use them |
| fancy-regex | 0.18.0 | MIT | via zxcvbn | Larsal | 9,886 | 0 | no | R | in our zxcvbn copy: the three back-reference patterns `(.+)\1+` (greedy, lazy, anchored) become an own repeat finder (about 60 lines); results must match the current strength tests |
| fastrand | 2.5.0 | Apache-2.0 OR MIT | via tempfile | Larsal | 615 | 0 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim only bindgen and proptest use them |
| fdeflate | 0.3.7 | MIT OR Apache-2.0 | via png | Larsal | 1,818 | 0 | no | T | copy whole (small, used by copies we do not edit) |
| ff | 0.14.0 | MIT/Apache-2.0 | via elliptic-curve, group, primefield, wnaf | Larsal | 342 | 0 | yes | C |  |
| fiat-crypto | 0.3.0 | MIT OR Apache-2.0 OR BSD-1-Clause | via curve25519-dalek | other OS | 92,961 | 0 | yes | X | never built: curve25519-dalek's opt-in fiat backend; cut its target table (crypto cut of an unused part) |
| find-msvc-tools | 0.1.15 | MIT OR Apache-2.0 | via cc | build | 2,169 | 40 | no | B | build time: ring's build script (and libfuzzer-sys) |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | direct: larsal-core, larsal-format, larsal-fuzz; via png | Larsal | 4,694 | 26 | no | T | keep `rust_backend`; cut the zlib, zlib-ng and zlib-rs backends and their features (zlib-rs leaves the lock); png needs flate2 too, so a gzip replacement saves nothing |
| fnv | 1.0.7 | Apache-2.0 / MIT | via rusty-fork | test | 301 | 0 | no | B | tests only (proptest) |
| fs-err | 3.3.2 | MIT OR Apache-2.0 | via uniffi_bindgen, uniffi_macros | build | 1,671 | 0 | no | B | build time |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | via ring | Larsal (net) | 989 | 43 | yes | C | ring's RNG for TLS handshakes only (deny.toml skip); cut non-Apple backends and target tables (wasi leaves) |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | direct: larsal-crypto; via jobserver, rand, tempfile | Larsal | 1,726 | 87 | yes | R | larsal-crypto random.rs calls `getentropy` through libc in 256-byte chunks, as getrandom 0.4 does on macOS, behind a `rand_core::TryCryptoRng` type (about 30 lines); needs a line in LD-221 because rule 3 names random numbers; stays a test copy for rand, tempfile, jobserver |
| ghash | 0.6.0 | Apache-2.0 OR MIT | via aes-gcm | Larsal | 91 | 0 | yes | C |  |
| glob | 0.3.4 | MIT OR Apache-2.0 | via askama_derive, uniffi_bindgen | build | 1,042 | 0 | no | B | build time |
| goblin | 0.8.2 | MIT | via uniffi_bindgen | build | 14,924 | 6 | no | B | build time |
| group | 0.14.0 | MIT/Apache-2.0 | via elliptic-curve, wnaf | Larsal | 746 | 0 | yes | C |  |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | via indexmap | Larsal | 11,319 | 321 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim build time only |
| heck | 0.5.0 | MIT OR Apache-2.0 | via clap_derive, uniffi_bindgen, uniffi_pipeline | Larsal | 510 | 0 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim build time only |
| hkdf | 0.13.0 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 166 | 0 | yes | C |  |
| hmac | 0.13.0 | MIT OR Apache-2.0 | direct: larsal-crypto; via hkdf, rfc6979 | Larsal | 359 | 0 | yes | C |  |
| http | 1.5.0 | MIT OR Apache-2.0 | via ureq-proto | Larsal (net) | 7,567 | 51 | no | T | net (ureq-proto types); cut tests |
| httparse | 1.10.1 | MIT OR Apache-2.0 | via ureq-proto | Larsal (net) | 3,097 | 50 | no | T | net; copy whole |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 | via block-buffer, crypto-bigint, crypto-common, elliptic-curve +3 | Larsal | 2,496 | 29 | support | C | needed unchanged by the crypto copies |
| ico | 0.6.0 | MIT | direct: larsal-core | Larsal | 1,213 | 0 | no | R | own ICO directory reader and BMP decoder in larsal-core icons.rs (about 170 lines: 1/4/8/24/32-bit, AND mask; icons.rs already checks the directory itself) plus a 60-line test encoder for mod06.rs and fuzz_seeds.rs |
| indexmap | 2.14.2 | Apache-2.0 OR MIT | via uniffi_bindgen, uniffi_internal_macros, uniffi_pipeline | Larsal | 8,928 | 12 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim build time only |
| inout | 0.2.5 | MIT OR Apache-2.0 | via aead, cipher | Larsal | 626 | 27 | yes | C |  |
| itertools | 0.14.0 | MIT OR Apache-2.0 | via zxcvbn | Larsal | 8,508 | 9 | no | R | in our zxcvbn copy: `join` twice, `unique` once (about 15 lines of std) |
| itoa | 1.0.18 | MIT OR Apache-2.0 | via askama, http, serde_json | Larsal | 317 | 12 | no | T | copy whole (small, used by copies we do not edit) |
| jni | 0.22.4 | MIT OR Apache-2.0 | via rustls-platform-verifier | other OS | 9,066 | 233 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| jni-macros | 0.22.4 | MIT OR Apache-2.0 | via jni | other OS | 6,448 | 27 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| jni-sys | 0.4.1 | MIT OR Apache-2.0 | via jni | other OS | 1,209 | 9 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| jni-sys-macros | 0.4.1 | MIT OR Apache-2.0 | via jni-sys | other OS | 170 | 0 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| jobserver | 0.1.35 | MIT OR Apache-2.0 | via cc | fuzz | 1,117 | 20 | no | B | fuzz workspace only; libfuzzer-sys bundles LLVM libFuzzer C++ source (NCSA) |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 | via zxcvbn | Larsal | 193 | 1 | no | R | in our zxcvbn copy: `std::sync::LazyLock` (no new code) |
| libc | 0.2.191 | MIT OR Apache-2.0 | direct: larsal-platform; via cc, core-foundation, cpufeatures, errno +8 | Larsal | 116,213 | 159 | no | T | cut every non-Apple module (linux_like, windows, fuchsia, vxworks, wasi, ...: about 3 MB of 4.5 MB); keep src/unix/bsd/apple and shared files |
| libfuzzer-sys | 0.4.13 | (MIT OR Apache-2.0) AND NCSA | direct: larsal-fuzz | fuzz | 269 | 1 | no | B | fuzz workspace only; libfuzzer-sys bundles LLVM libFuzzer C++ source (NCSA) |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | via rustix | other OS | 479,316 | 4541 | no | X | other OS: cut with rustix's Linux backend |
| log | 0.4.34 | MIT OR Apache-2.0 | via goblin, jni, rustls-platform-verifier, ureq +1 | Larsal (net) | 3,491 | 3 | no | R | own no-op facade named `log` under [patch] (about 40 lines: `error!`..`trace!`, `log_enabled!` consume their arguments and print nothing); rustls-platform-verifier, ureq, ureq-proto and goblin keep compiling; dependencies never log (rule 4) |
| memchr | 2.8.3 | Unlicense OR MIT | via aho-corasick, askama_derive, combine, nom +5 | Larsal | 9,057 | 113 | no | T | quick-xml; cut src/arch/wasm32 |
| minimal-lexical | 0.2.1 | MIT/Apache-2.0 | via nom | build | 3,634 | 31 | no | B | build time; larsal-ffi has no .udl file: candidate cut from our uniffi_bindgen copy |
| miniz_oxide | 0.8.9 | MIT OR Zlib OR Apache-2.0 | via png | Larsal | 4,992 | 0 | no | T | png's; drop when our png copy moves to 0.9 (LD-115) |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 | via flate2 | Larsal | 5,187 | 0 | no | T | flate2's deflate/inflate; copy whole |
| nom | 7.1.3 | MIT | via weedle2 | build | 10,781 | 6 | no | B | build time; larsal-ffi has no .udl file: candidate cut from our uniffi_bindgen copy |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 | via der-parser | lock only | 7,894 | 8 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| num-conv | 0.2.2 | MIT OR Apache-2.0 | via time | Larsal | 198 | 0 | no | B | tests only once time is replaced in zxcvbn (rcgen keeps time) |
| num-integer | 0.1.47 | MIT OR Apache-2.0 | via num-bigint | lock only | 1,169 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| num-traits | 0.2.19 | MIT OR Apache-2.0 | via crypto-bigint, proptest | Larsal | 3,849 | 1 | support | C | crypto-bigint needs it; also proptest |
| objc2 | 0.6.5 | MIT | direct: larsal-cli, larsal-platform; via objc2-app-kit, objc2-foundation | Larsal | 15,440 | 534 | no | T | copy whole (core runtime) |
| objc2-app-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT | direct: larsal-cli, larsal-platform | Larsal | 84,506 | 87 | no | T | generated bindings: cut every generated file of a feature we do not turn on (most of 12 MB) |
| objc2-core-foundation | 0.3.2 | Zlib OR Apache-2.0 OR MIT | direct: larsal-hwkey; via objc2-io-kit | Larsal (hwkey) | 31,343 | 2054 | no | T | generated bindings: cut every generated file of a feature we do not turn on (most of 12 MB) |
| objc2-encode | 4.1.0 | MIT | via objc2 | Larsal | 1,856 | 2 | no | T | copy whole (small, used by copies we do not edit) |
| objc2-foundation | 0.3.2 | MIT | direct: larsal-cli, larsal-platform; via objc2-app-kit | Larsal | 56,329 | 385 | no | T | generated bindings: cut every generated file of a feature we do not turn on (most of 12 MB) |
| objc2-io-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT | direct: larsal-hwkey | Larsal (hwkey) | 37,180 | 1442 | no | T | generated bindings: cut every generated file of a feature we do not turn on (most of 12 MB) |
| oid-registry | 0.8.1 | MIT OR Apache-2.0 | via x509-parser | lock only | 200 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | via rustls, rustls-platform-verifier, tempfile, uniffi_bindgen +2 | Larsal | 1,131 | 33 | support | C | rustls and rustls-platform-verifier need it unchanged; uniffi_core too |
| openssl-probe | 0.2.2 | MIT OR Apache-2.0 | via rustls-native-certs | other OS | 150 | 3 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| p256 | 0.14.0 | Apache-2.0 OR MIT | direct: larsal-crypto | Larsal | 2,564 | 0 | yes | C |  |
| pbkdf2 | 0.13.0 | MIT OR Apache-2.0 | direct: larsal-crypto; via bcrypt-pbkdf | Larsal | 671 | 0 | yes | C |  |
| pem-rfc7468 | 1.0.0 | Apache-2.0 OR MIT | via ssh-encoding | Larsal | 590 | 1 | key | C | key encodings |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | via ureq | Larsal (net) | 451 | 4 | no | R | in our ureq copy: cut query helpers and the lossy charset body (unused by the breach check), or std (`str::from_utf8`) |
| plain | 0.2.3 | MIT/Apache-2.0 | via goblin | build | 287 | 7 | no | B | build time |
| png | 0.18.1 | MIT OR Apache-2.0 | direct: larsal-core, larsal-fuzz; via ico | Larsal | 9,030 | 0 | no | T | cut tests, benches, fuzz; candidate: one miniz_oxide (0.9) |
| poly1305 | 0.9.1 | Apache-2.0 OR MIT | via ssh-cipher | Larsal | 1,467 | 33 | yes | C |  |
| polyval | 0.7.3 | Apache-2.0 OR MIT | via ghash | Larsal | 954 | 4 | yes | C |  |
| powerfmt | 0.2.1 | MIT OR Apache-2.0 | via time | Larsal | 850 | 5 | no | B | tests only once time is replaced in zxcvbn (rcgen keeps time) |
| primefield | 0.14.0 | Apache-2.0 OR MIT | via p256, primeorder, wnaf | Larsal | 1,810 | 0 | yes | C |  |
| primeorder | 0.14.0 | Apache-2.0 OR MIT | via p256 | Larsal | 2,213 | 0 | yes | C |  |
| proc-macro-crate | 3.5.0 | MIT OR Apache-2.0 | via borsh-derive | lock only | 450 | 0 | no | X | lock only: an optional `borsh` feature, never on |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | via askama_derive, clap_derive, curve25519-dalek-derive, jni-macros +8 | build | 4,669 | 3 | no | B | build time |
| proptest | 1.12.0 | MIT OR Apache-2.0 | direct: larsal-core, larsal-crypto, larsal-format, larsal-sshagent | test | 15,495 | 5 | no | B | tests only (proptest) |
| qrcode | 0.14.1 | MIT OR Apache-2.0 | direct: larsal-ffi | Larsal | 4,190 | 0 | no | T | keep bits, ec, canvas, types; cut render/ (svg, pic, unicode, string, image) |
| quick-error | 1.2.3 | MIT/Apache-2.0 | via rusty-fork | test | 886 | 0 | no | B | tests only (proptest) |
| quick-xml | 0.42.0 | MIT | direct: larsal-format, larsal-sshagent | Larsal | 20,733 | 0 | no | T | reader only: cut serde (de/, se/), async-tokio, encoding, and the writer if still unused |
| quote | 1.0.47 | MIT OR Apache-2.0 | via askama_derive, clap_derive, curve25519-dalek-derive, jni-macros +8 | build | 1,547 | 0 | no | B | build time |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | via getrandom 0.4.3 | other OS | 6,771 | 3 | no | X | other OS (UEFI): cut with getrandom 0.4's table |
| rand | 0.10.3 | MIT OR Apache-2.0 | via proptest | test | 6,360 | 15 | no | B | tests only (proptest) |
| rand_core | 0.10.1 | MIT OR Apache-2.0 | direct: larsal-crypto; via chacha20, crypto-bigint, crypto-common, elliptic-curve +8 | Larsal | 403 | 0 | yes | C | trait crate every RNG user shares |
| rand_xorshift | 0.5.0 | MIT OR Apache-2.0 | via proptest | test | 99 | 0 | no | B | tests only (proptest) |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | direct: larsal-platform | test | 3,872 | 0 | no | B | tests only (E6-S7 certificates); option: fixed demo certificates instead |
| regex | 1.13.1 | MIT OR Apache-2.0 | via zxcvbn | Larsal | 3,427 | 0 | no | R | in our zxcvbn copy: its three patterns run on regex-automata `meta::Regex`, which Larsal already ships |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 | direct: larsal-core; via fancy-regex, regex | Larsal | 30,671 | 35 | no | T | cut engines and features we do not turn on (dense/sparse DFA build and search, literal prefilters) |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 | direct: larsal-autotype, larsal-core; via fancy-regex, proptest, regex, regex-automata | Larsal | 50,759 | 0 | no | T | cut Unicode tables we do not turn on (age, bool, gencat, script, script-extension, segment) |
| rfc6979 | 0.6.0 | Apache-2.0 OR MIT | via ecdsa | Larsal | 308 | 0 | yes | C |  |
| ring | 0.17.14 | Apache-2.0 AND ISC | via rcgen, rustls, rustls-webpki | Larsal (net) | 16,748 | 180 | yes | C | TLS only (net); cut pregenerated asm/perlasm for non-Apple targets and tests/ (about 3.3 MB of 7.6 MB) |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT | via askama_derive, askama_parser | build | 403 | 0 | no | B | build time |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 | via curve25519-dalek, jni-macros, simd_cesu8 | build | 274 | 0 | no | B | build time |
| rusticata-macros | 4.1.0 | MIT/Apache-2.0 | via asn1-rs, der-parser, x509-parser | lock only | 484 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | via tempfile | Larsal | 49,436 | 1045 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim build and test only; cut the linux_raw backend |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT | direct: larsal-platform; via rustls-platform-verifier | Larsal (net) | 36,102 | 0 | yes | C | TLS key schedule and certificate path checks: no code edits (LD-221 (4) lists rustls as copy-trim; research advises rule (3) treatment); cut benches/, examples/ |
| rustls-native-certs | 0.8.5 | Apache-2.0 OR ISC OR MIT | via rustls-platform-verifier | other OS | 498 | 0 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 | via rcgen, rustls, rustls-native-certs, rustls-webpki +1 | Larsal (net) | 2,678 | 1 | key | C | certificate and key types |
| rustls-platform-verifier | 0.7.1 | MIT OR Apache-2.0 | direct: larsal-platform | Larsal (net) | 2,089 | 18 | key | C | trust decision through Security.framework; cut Android, Windows and other-Unix modules and target tables (the jni family, rustls-native-certs, webpki-root-certs leave the lock) |
| rustls-platform-verifier-android | 0.2.0 | MIT OR Apache-2.0 | via rustls-platform-verifier | other OS | 0 | 0 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| rustls-webpki | 0.103.16 | ISC | via rustls, rustls-platform-verifier | Larsal (net) | 7,081 | 0 | yes | C | TLS key schedule and certificate path checks: no code edits (LD-221 (4) lists rustls as copy-trim; research advises rule (3) treatment); cut benches/, examples/ |
| rusty-fork | 0.3.1 | MIT/Apache-2.0 | via proptest | test | 687 | 0 | no | B | tests only (proptest) |
| salsa20 | 0.11.0 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 253 | 0 | yes | C |  |
| same-file | 1.0.6 | Unlicense/MIT | via walkdir | other OS | 487 | 3 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| schannel | 0.1.30 | MIT | via rustls-native-certs | other OS | 3,836 | 73 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| scroll | 0.12.0 | MIT | via goblin | build | 1,464 | 9 | no | B | build time |
| scroll_derive | 0.12.1 | MIT | via scroll | build | 561 | 0 | no | B | build time |
| sec1 | 0.8.1 | Apache-2.0 OR MIT | via elliptic-curve, ssh-key | Larsal | 897 | 0 | key | C | key encodings |
| security-framework | 3.7.0 | MIT OR Apache-2.0 | via rustls-native-certs, rustls-platform-verifier | Larsal (net) | 7,703 | 366 | no | T | net only (trust evaluation under rustls-platform-verifier); keep trust, certificate, policy, base; cut keychain-item, authorization, secure-transport modules until a story needs them |
| security-framework-sys | 2.17.0 | MIT OR Apache-2.0 | via rustls-platform-verifier, security-framework | Larsal (net) | 1,854 | 1 | no | T | net only (trust evaluation under rustls-platform-verifier); keep trust, certificate, policy, base; cut keychain-item, authorization, secure-transport modules until a story needs them |
| semver | 1.0.28 | MIT OR Apache-2.0 | via cargo_metadata, rustc_version | build | 1,313 | 39 | no | B | build time |
| serde | 1.0.229 | MIT OR Apache-2.0 | direct: larsal-ffi; via askama_derive, askama_parser, basic-toml, cargo-platform +6 | Larsal | 11,575 | 2 | no | R | the one `Serialize`/`Deserialize` derive (larsal-ffi larsal_settings.rs) becomes a hand mapping over the JSON value; stays a tool copy for the bindings generator |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | via camino, cargo-platform, indexmap, semver +5 | Larsal | 7,291 | 2 | no | B | build time once serde_json is replaced (cargo_metadata, toml, askama) |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 | via askama_derive, askama_parser, serde, serde_core | build | 7,477 | 0 | no | B | build time once serde_json is replaced (cargo_metadata, toml, askama) |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | direct: larsal-core, larsal-ffi, larsal-format; via cargo_metadata | Larsal | 12,621 | 12 | no | R | Larsal's own RFC 8259 reader and writer (about 250 to 300 lines with tests): a value type with an ordered map, `from_str`/`from_slice`, `to_vec`, pretty output, test builders for `json!`; above the 200-line guide, but it takes serde_json, serde, serde_core, zmij out of Larsal (about 32,000 lines) |
| serde_spanned | 1.1.2 | MIT OR Apache-2.0 | via toml | build | 257 | 0 | no | B | build time |
| sha1 | 0.11.0 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 806 | 5 | yes | C | cut other-arch backend files (riscv, loongarch, wasm) |
| sha2 | 0.11.1 | MIT OR Apache-2.0 | direct: larsal-crypto; via bcrypt-pbkdf, ed25519-dalek, p256, ssh-key | Larsal | 2,466 | 39 | yes | C | cut other-arch backend files (riscv, loongarch, wasm) |
| shlex | 2.0.1 | MIT OR Apache-2.0 | via cc | build | 528 | 4 | no | B | build time: ring's build script (and libfuzzer-sys) |
| signature | 3.0.0 | Apache-2.0 OR MIT | via ecdsa, ed25519, ssh-key | Larsal | 353 | 0 | yes | C |  |
| simd-adler32 | 0.3.10 | MIT | via fdeflate, miniz_oxide 0.8.9, miniz_oxide 0.9.1 | Larsal | 1,458 | 8 | no | T | copy whole (small, used by copies we do not edit) |
| simd_cesu8 | 1.2.0 | Apache-2.0 OR MIT | via jni, jni-macros | other OS | 561 | 30 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| simdutf8 | 0.1.5 | MIT OR Apache-2.0 | via simd_cesu8 | other OS | 1,953 | 4 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| siphasher | 1.0.4 | MIT OR Apache-2.0 | via uniffi_meta | build | 1,375 | 11 | no | B | build time |
| smawk | 0.3.3 | MIT | via textwrap | build | 673 | 0 | no | B | build time |
| ssh-cipher | 0.3.0 | Apache-2.0 OR MIT | via ssh-key | Larsal | 913 | 0 | key | C | cut the `tdes` feature (des leaves the lock) |
| ssh-encoding | 0.3.0 | Apache-2.0 OR MIT | via ssh-cipher, ssh-key | Larsal | 1,013 | 0 | key | C |  |
| ssh-key | 0.7.0-rc.11 | Apache-2.0 OR MIT | direct: larsal-crypto | Larsal | 7,843 | 0 | key | C | already Larsal's patched copy (vendor/ssh-key, LD-209); a [patch] path copy, so cargo audit no longer sees it (proven, see Advisories) |
| static_assertions | 1.1.0 | MIT OR Apache-2.0 | via uniffi_core | Larsal | 243 | 1 | no | R | in our uniffi_core copy: a 5-line `const_assert!` (std `const _: () = assert!(..)`) at the same path generated code uses |
| strsim | 0.11.1 | MIT | via clap_builder | build | 967 | 0 | no | G | gone with clap |
| subtle | 2.6.1 | BSD-3-Clause | direct: larsal-crypto; via crypto-bigint, ctutils, curve25519-dalek, ed25519-dalek +7 | Larsal | 456 | 2 | key | C | memory wiping and constant-time helpers |
| syn | 2.0.119 | MIT OR Apache-2.0 | via curve25519-dalek-derive, jni-macros, jni-sys-macros, scroll_derive +2 | build | 41,973 | 31 | no | B | build time |
| syn | 3.0.9 | MIT OR Apache-2.0 | via askama_derive, clap_derive, serde_derive, thiserror-impl | build | 43,305 | 32 | no | B | build time |
| synstructure | 0.13.2 | MIT | via asn1-rs-derive | lock only | 1,027 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | via proptest, rusty-fork, uniffi_bindgen, uniffi_pipeline | Larsal | 1,289 | 3 | no | B | compiled into larsal-ffi today through uniffi_pipeline (not linked); after the uniffi trim only bindgen and proptest use them |
| textwrap | 0.16.4 | MIT | via uniffi_bindgen, uniffi_udl | build | 2,403 | 0 | no | B | build time |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | direct: larsal-autotype, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-hwkey, larsal-platform, larsal-sshagent; via cargo_metadata, jni | Larsal | 324 | 0 | no | R | hand-written `Display` and `std::error::Error` impls for our 18 error enums (144 `#[error]` messages; or one `macro_rules!`, about 40 lines); stays a tool copy for cargo_metadata until the bindgen trim |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 | via thiserror | build | 2,258 | 0 | no | B | build time |
| time | 0.3.55 | MIT OR Apache-2.0 | via rcgen, yasna, zxcvbn | Larsal | 24,632 | 251 | no | R | in our zxcvbn copy: the current year from `SystemTime` (days-to-civil, about 15 lines, 3 call sites); stays a test copy for rcgen |
| time-core | 0.1.9 | MIT OR Apache-2.0 | via time | Larsal | 376 | 0 | no | B | tests only once time is replaced in zxcvbn (rcgen keeps time) |
| time-macros | 0.2.32 | MIT OR Apache-2.0 | via time | lock only | 3,905 | 7 | no | X | lock only: time's `macros` feature, never on |
| toml | 1.1.8+spec-1.1.0 | MIT OR Apache-2.0 | via uniffi_bindgen, uniffi_macros | build | 7,161 | 0 | no | B | build time |
| toml_datetime | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | via toml | build | 1,051 | 0 | no | B | build time |
| toml_edit | 0.25.17+spec-1.1.0 | MIT OR Apache-2.0 | via proc-macro-crate | lock only | 7,424 | 0 | no | X | lock only: an optional `borsh` feature, never on |
| toml_parser | 1.1.5+spec-1.1.0 | MIT OR Apache-2.0 | via toml | build | 6,405 | 42 | no | B | build time |
| toml_writer | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | via toml | build | 867 | 0 | no | B | build time |
| twofish | 0.8.0 | MIT OR Apache-2.0 | direct: larsal-crypto | Larsal | 376 | 0 | yes | C |  |
| typenum | 1.20.1 | MIT OR Apache-2.0 | via hybrid-array | Larsal | 16,345 | 0 | support | C | needed unchanged by the crypto copies |
| unarray | 0.1.4 | MIT OR Apache-2.0 | via proptest | test | 335 | 8 | no | B | tests only (proptest) |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 | via askama_parser, proc-macro2, syn 2.0.119, syn 3.0.9 | build | 703 | 2 | no | B | build time |
| unicode-width | 0.2.2 | MIT OR Apache-2.0 | via textwrap | lock only | 22,680 | 0 | no | X | lock only: textwrap's optional feature, never on |
| uniffi | 0.32.2 | MPL-2.0 | direct: larsal-ffi, uniffi-bindgen | Larsal | 280 | 0 | no | T | MPL-2.0; manifest trim: drop the always-on uniffi_pipeline dependency (the runtime never uses it; 9 packages leave the app compile); cut bindgen-tests |
| uniffi_bindgen | 0.32.2 | MPL-2.0 | via uniffi | build | 16,630 | 0 | no | B | build time (crates/uniffi-bindgen); cut the Kotlin, Python and Ruby generators and templates; keep Swift |
| uniffi_core | 0.32.2 | MPL-2.0 | via uniffi | Larsal | 2,783 | 36 | no | T | MPL-2.0 runtime; static_assertions becomes std (edited files stay MPL-2.0) |
| uniffi_internal_macros | 0.32.2 | MPL-2.0 | via uniffi_bindgen, uniffi_meta, uniffi_pipeline | build | 821 | 0 | no | B | build time |
| uniffi_macros | 0.32.2 | MPL-2.0 | via uniffi | build | 4,785 | 11 | no | B | build time |
| uniffi_meta | 0.32.2 | MPL-2.0 | via uniffi_bindgen, uniffi_macros, uniffi_udl | build | 1,533 | 0 | no | B | build time |
| uniffi_pipeline | 0.32.2 | MPL-2.0 | via uniffi, uniffi_bindgen, uniffi_meta | Larsal | 562 | 0 | no | B | build time |
| uniffi_udl | 0.32.2 | MPL-2.0 | via uniffi_bindgen | build | 2,523 | 0 | no | B | build time; larsal-ffi has no .udl file: candidate cut from our uniffi_bindgen copy |
| universal-hash | 0.6.1 | MIT OR Apache-2.0 | via poly1305, polyval | Larsal | 104 | 0 | yes | C |  |
| untrusted | 0.9.0 | ISC | via ring, rustls-webpki | Larsal (net) | 191 | 0 | yes | C | ring's input reader |
| ureq | 3.5.0 | MIT OR Apache-2.0 | direct: larsal-platform | Larsal (net) | 12,482 | 0 | no | T | net; keep HTTP/1.1 over rustls with the platform verifier; cut proxy and SOCKS, cookies, json, charset, gzip/brotli, basic auth, query helpers |
| ureq-proto | 0.6.5 | MIT OR Apache-2.0 | via ureq | Larsal (net) | 7,402 | 0 | no | T | net; cut basic auth and proxy (base64) |
| utf8-zero | 0.8.1 | MIT OR Apache-2.0 | via ureq | Larsal (net) | 360 | 3 | no | R | in our ureq copy: cut query helpers and the lossy charset body (unused by the breach check), or std (`str::from_utf8`) |
| wait-timeout | 0.2.1 | MIT/Apache-2.0 | via rusty-fork | test | 242 | 6 | no | B | tests only (proptest) |
| walkdir | 2.5.0 | Unlicense/MIT | via jni | other OS | 1,947 | 0 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | via getrandom 0.2.17 | other OS | 1,527 | 16 | no | X | other OS: cut with getrandom 0.2's WASI table |
| webpki-root-certs | 1.0.11 | CDLA-Permissive-2.0 | via rustls-platform-verifier | other OS | 131 | 0 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| weedle2 | 5.0.0 | MIT | via uniffi_udl | build | 2,603 | 0 | no | B | build time; larsal-ffi has no .udl file: candidate cut from our uniffi_bindgen copy |
| winapi-util | 0.1.11 | Unlicense OR MIT | via same-file, walkdir | other OS | 600 | 20 | no | X | other OS (Android, Linux, Windows): cut with the target tables of rustls-platform-verifier |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | via jni, windows-sys 0.61.2 | other OS | 33 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 | via ring | other OS | 384,499 | 0 | no | X | other OS: cut with ring's Windows target table |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | via errno, rustix, rustls-platform-verifier, schannel +2 | other OS | 334,264 | 8925 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 | via windows-sys 0.52.0 | other OS | 46 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 | via windows-targets | other OS | 8 | 0 | no | X | other OS: cut with the Windows target tables of errno, rustix, tempfile, rustls-platform-verifier, schannel, winapi-util |
| winnow | 1.0.4 | MIT | via askama_parser, toml, toml_parser | build | 27,900 | 24 | no | B | build time |
| wnaf | 0.14.1 | Apache-2.0 OR MIT | via primeorder | Larsal | 440 | 0 | yes | C |  |
| x509-parser | 0.18.1 | MIT OR Apache-2.0 | via rcgen | lock only | 4,894 | 0 | no | X | lock only: rcgen's `x509-parser` feature, never on; cut it in our rcgen copy (data-encoding: also drop the unused workspace pin) |
| yasna | 0.6.0 | MIT OR Apache-2.0 | via rcgen | test | 5,050 | 0 | no | B | tests only (E6-S7 certificates); option: fixed demo certificates instead |
| zeroize | 1.9.1 | Apache-2.0 OR MIT | direct: larsal-crypto; via aes, aes-gcm, argon2, bcrypt-pbkdf +21 | Larsal | 495 | 15 | key | C | memory wiping and constant-time helpers |
| zlib-rs | 0.6.8 | Zlib | via flate2 | lock only | 13,094 | 354 | no | X | lock only: flate2's `zlib-rs` backend, never on |
| zmij | 1.0.23 | MIT | via serde_json | Larsal | 1,652 | 59 | no | G | gone with serde_json |
| zxcvbn | 3.1.1 | MIT | direct: larsal-core | Larsal | 4,927 | 0 | no | T | already Larsal's patched copy (vendor/zxcvbn, LD-136); the edits above take 13 packages out of Larsal; a [patch] path copy, so cargo audit no longer sees it |

## 8. Build order

Each step is its own change, with its proof, after E14-S4 has landed. Mutation and break-on-purpose checks run in a private copy of the tree (rule 11).

### Step 1: the mechanical vendor (no code edits)

1. From the tree root: `cargo vendor --offline --locked --versioned-dirs -s fuzz/Cargo.toml vendor/crates-io`. Every `.crate` file is in the local cache (F3). Do not point it at `vendor/` (F1).
2. `.cargo/config.toml`:

   ```toml
   [source.crates-io]
   replace-with = "vendored"

   [source.vendored]
   directory = "vendor/crates-io"

   [net]
   offline = true
   ```

3. Keep `[patch.crates-io]` in `Cargo.toml` and `fuzz/Cargo.toml` exactly as they are (zxcvbn, ssh-key). `cargo vendor` does not copy path sources, so `vendor/zxcvbn` and `vendor/ssh-key` stay the only copies of those two.
4. `Cargo.lock` and `fuzz/Cargo.lock` must not change: source replacement keeps the crates.io source and checksum of each entry. Proof: both files byte-identical before and after.
5. `deny.toml` `[sources]`: the rule stays (crates.io the only registry, no git), because the lock still names crates.io; add a comment that the bytes come from `vendor/crates-io`.
6. A new step in `scripts/check.sh` (gate G1), for example `scripts/check-vendor.sh`, about 40 lines:
   - a. `CARGO_HOME=$(mktemp -d) cargo metadata --offline --locked --format-version 1` for the root and for `fuzz/` passes, and every `manifest_path` is inside the tree. An empty cargo home means no registry cache to fall back on.
   - b. Every registry entry of both lockfiles has `vendor/crates-io/<name>-<version>/`, and that folder holds nothing else.
   - c. Each copy's `.cargo-checksum.json` `package` value equals its `Cargo.lock` checksum: the copy is that crates.io release. Cargo itself checks every listed file at build time.
   - d. Path copies: a list `vendor/PATCHED` (name and upstream version, today zxcvbn 3.1.1 and ssh-key 0.7.0-rc.11). The step writes a temporary lockfile that gives them their crates.io source and runs `cargo audit --no-fetch -f` on it (closes F2).
   - e. Each copy has a license file, or its text is in `scripts/licenses/` (F5, LD-222 (3)).
7. Proof for the E0-S7 check: `cargo build --workspace --offline --locked`, every test, and `scripts/check.sh` with an empty `CARGO_HOME` and no network. The toolchain sits in rustup's own folder and the cargo-deny and cargo-audit programs are found on `PATH`, so an empty `CARGO_HOME` leaves them working.

### Step 2: cut what is never built (X, 53 packages, 1.42 million lines)

1. Edit only the manifests of the parent copies:
   - optional features nobody turns on: rcgen `x509-parser` (asn1-rs, asn1-rs-derive, asn1-rs-impl, der-parser, oid-registry, rusticata-macros, x509-parser, displaydoc, num-bigint, num-integer, synstructure, data-encoding), the optional `borsh` support (borsh, borsh-derive, cfg_aliases, proc-macro-crate, toml_edit, bit-vec 0.9.1), ssh-cipher `tdes` (des), time `macros` (time-macros), textwrap (unicode-width), flate2 `zlib-rs` (zlib-rs);
   - target tables of other systems: rustls-platform-verifier (the jni family, combine, simd_cesu8, simdutf8, walkdir, same-file, winapi-util, rustls-native-certs, openssl-probe, schannel, webpki-root-certs, rustls-platform-verifier-android), the Windows tables of ring, errno, rustix and tempfile (windows-sys 0.52 and 0.61, windows-link, windows-targets and the 8 windows_* crates), rustix's Linux backend (linux-raw-sys), getrandom 0.2 WASI (wasi), getrandom 0.4 UEFI (r-efi), curve25519-dalek's fiat backend (fiat-crypto).
   In crypto copies (ring, getrandom, ssh-cipher, curve25519-dalek, rustls-platform-verifier) this is a cut of unused parts, which rule 3 allows; no code line changes.
2. Let cargo rewrite the lockfiles once (`cargo metadata --offline` without `--locked`). The diff must be removals only. Then delete the removed folders from `vendor/crates-io`.
3. Each edited copy gets a rewritten `.cargo-checksum.json` for its new contents (Chromium style); the original is kept beside it as `.cargo-checksum.upstream.json`. The diff proof: every file that is still there and listed upstream has the upstream hash; the report lists removed files and the changed `Cargo.toml`.
4. Where a parent cannot be edited, an empty placeholder crate with the same name and feature names under `[patch.crates-io]` (Firefox `build/rust/r-efi`, Chromium placeholders).

### Step 3: replacements, smallest risk first

Each removes its rows from `vendor/crates-io` (and the G rows it takes along) and comes with tests.

| Order | Package | Where | Proof |
|---|---|---|---|
| R1 | lazy_static | zxcvbn copy | strength tests unchanged (FEA strength cases), plus a run comparing old and new zxcvbn scores on its test passwords and 100,000 generated ones |
| R2 | itertools (either goes) | zxcvbn copy | same comparison |
| R3 | time (time-core, deranged, powerfmt, num-conv leave Larsal) | zxcvbn copy | same comparison; a test for the year around 1 January |
| R4 | thiserror | all our crates | every message test (M-codes) unchanged |
| R5 | base64 | larsal-crypto wrapper over base64ct; callers in larsal-core, larsal-format, larsal-sshagent | round-trip property test; padded, unpadded, URL-safe and bad-input cases; demo vault known answers (AT-B01) |
| R6 | log | own facade under `[patch]` | `cargo test -p larsal-platform --features net` |
| R7 | regex (aho-corasick goes) | zxcvbn copy | the score comparison |
| R8 | getrandom 0.4 | dropped (LD-258 (1)): LD-221 (7) keeps getrandom a crypto copy, trimmed in step 4 item 5 | none |
| R9 | clap | larsal-cli `args.rs` | INT-10.2 and INT-10.3 tests, M10-02 texts unchanged |
| R10 | ico | larsal-core `icons.rs`; test encoder in tests | mod06 tests; the icon_decode fuzz target and its corpus |
| R11 | fancy-regex (bit-set 0.8, bit-vec 0.8 go) | zxcvbn copy | the score comparison |
| R12 | serde_json and serde (serde_core, zmij leave Larsal) | larsal-core import, larsal-ffi settings and edit | import tests, settings round trip, a new fuzz target for the JSON reader |

R13 (percent-encoding, utf8-zero) and R14 (static_assertions) land with the ureq and uniffi trims in step 4.

### Step 4: trims

Cut-only copies stay in `vendor/crates-io` with a rewritten checksum file (step 2.3). A copy whose code changes moves to `vendor/<name>/` as a `[patch]` path copy and joins `vendor/PATCHED`. Largest cut first:

1. libc: every non-Apple module (about 3 MB of 4.5 MB).
2. objc2-foundation, objc2-app-kit, objc2-core-foundation, objc2-io-kit: the generated files of features we do not turn on.
3. regex-syntax Unicode tables we do not turn on; regex-automata engines we do not turn on.
4. ring: pregenerated assembly and perlasm for other targets (keep `*-ios64.S` for arm64 and `*-macosx.S` for x86_64), `tests/`. Crypto: files only; TLS tests and known answers rerun.
5. The other crypto copies: `tests/`, `benches/`, other-architecture backend files (sha2, sha1, curve25519-dalek, getrandom, cpufeatures), with the diff proof of step 2.3.
6. uniffi (drop the uniffi_pipeline dependency, F6) and uniffi_core (R14): path copies; edited MPL-2.0 files stay MPL-2.0. 9 packages leave Larsal's build.
7. ureq and ureq-proto: cut proxy, SOCKS, cookies, JSON, charset, compression, basic auth and query helpers (R13: percent-encoding and utf8-zero go; base64 leaves the net code).
8. flate2: the non-Rust backends. png onto one miniz_oxide (0.9) through a small re-export crate as Firefox does, or in our png copy: miniz_oxide 0.8.9 and the LD-115 skip go.
9. qrcode render/, quick-xml serde, async and encoding parts, memchr wasm32, bytes, security-framework modules nobody calls.

### Step 5: tools (lowest priority)

1. Our own bindgen main without uniffi's `cli` feature: clap, clap_builder, clap_derive, clap_lex, anstyle and strsim leave the tree entirely.
2. uniffi_bindgen: cut the Kotlin, Python and Ruby generators; with no `.udl` file in larsal-ffi, also UDL (uniffi_udl, weedle2, nom, minimal-lexical).
3. rcgen: optionally fixed demo certificates instead of certificates made at test time.
4. rustix: cut the linux_raw backend.

### Updating a copy later

- An update is one reviewed change: fetch one `.crate` (the only online step), unpack it into `vendor/crates-io/<name>-<version>/`, re-apply the recorded cuts, diff it against the old copy, review the diff (AT-J03: every `unsafe` block, build script and proc macro), run the checks.
- Take a version at least 14 days after its release unless it fixes an advisory (Chromium).
- `cargo audit` keeps covering plain copies by name and version; `vendor/PATCHED` covers path copies (step 1.6d).

## 9. Open issues

1. **F2 is live today**: `vendor/zxcvbn` and `vendor/ssh-key` are not checked by `cargo audit`. Until step 1.6d lands, check them by hand against RustSec.
2. **F7**: rustls and rustls-webpki as crypto copies (rule 3) rather than trims (LD-221 (4)): the lead rules.
3. **F8**: the getrandom replacement needs a line in LD-221 next to rule 3: the lead rules.
4. **serde_json**: the replacement is above the 200-line guide (about 300 lines); the lead confirms, or it stays a copy-trim.
5. `cargo audit` and `cargo deny` still fetch the advisory database (as today); vendoring does not change that.
6. Outside Cargo: `scripts/install-swiftlint.sh` downloads SwiftLint (a tool, not linked into Larsal); the Swift package has no outside dependency; the Rust toolchain is not a package (E14-S4 pins it).
7. Line counts of replacements are estimates from our call sites; nothing was built for this research.

## 10. Step 1 done (2026-10-30)

Built by the E0-S7 step 1 Builder with the lead's rulings of LD-247. Checker next.

What changed in the tree:

- `vendor/crates-io/`: `cargo vendor --offline --locked --versioned-dirs -s fuzz/Cargo.toml vendor/crates-io` for the workspace and the fuzz workspace, from the local cargo cache (no network). 235 packages: 196 copied, 1 copied with one file cut, 38 stubs. `.cargo/config.toml` replaces crates.io with it (`vendored-sources`) and sets `net.offline`. The two `[patch]` copies stay in `vendor/zxcvbn` and `vendor/ssh-key` (LD-221 (9)).
- `Cargo.lock`: 22 packages left it, nothing was added, and no remaining entry changed its version or checksum. `fuzz/Cargo.lock`: 2 left (itertools, either).
- Size: `vendor/` is 102 MB in 8,432 files (`vendor/crates-io` 101 MB, 8,379 files, 1.95 million lines of Rust).

Per package:

- **Copied whole (196)**: every file byte-for-byte the published `.crate` whose SHA-256 is the `Cargo.lock` checksum (8,068 files compared). `cargo vendor` leaves out only the 65 `.gitignore` and 5 `.gitattributes` files of the packages. adler2 2.0.1, aead 0.6.1, aes 0.9.3, aes-gcm 0.11.1, aho-corasick 1.1.5, anstyle 1.0.14, anyhow 1.0.104, arbitrary 1.5.0, argon2 0.6.0, askama 0.16.1, askama_derive 0.16.1, askama_macros 0.16.1, askama_parser 0.16.1, autocfg 1.5.1, base16ct 1.0.0, base64 0.23.1, base64ct 1.8.3, basic-toml 0.1.10, bcrypt-pbkdf 0.11.0, bit-set 0.11.1, bit-set 0.8.0, bit-vec 0.10.1, bit-vec 0.8.0, bitflags 2.13.2, blake2 0.11.0, block-buffer 0.12.1, blowfish 0.10.0, byteorder 1.5.0, bytes 1.12.1, camino 1.2.6, cargo-platform 0.3.3, cargo_metadata 0.23.1, cbc 0.2.1, cc 1.10.0, cfg-if 1.0.5, chacha20 0.10.2, cipher 0.5.2, clap 4.6.7, clap_builder 4.6.7, clap_derive 4.6.7, clap_lex 1.1.1, cmov 0.5.4, const-oid 0.10.2, core_detect 1.0.0, cpubits 0.1.1, cpufeatures 0.3.1, crc32fast 1.5.3, crypto-bigint 0.7.10, crypto-common 0.2.2, ctr 0.10.1, ctutils 0.4.6, curve25519-dalek 5.0.0, curve25519-dalek-derive 0.1.1, der 0.8.2, deranged 0.5.9, digest 0.11.3, ecdsa 0.17.0, ed25519 3.0.0, ed25519-dalek 3.0.0, elliptic-curve 0.14.2, equivalent 1.0.3, errno 0.3.14, fancy-regex 0.18.0, fastrand 2.5.0, fdeflate 0.3.7, ff 0.14.0, find-msvc-tools 0.1.15, flate2 1.1.10, fnv 1.0.7, fs-err 3.3.2, getrandom 0.2.17, getrandom 0.4.3, ghash 0.6.0, glob 0.3.4, goblin 0.8.2, group 0.14.0, hashbrown 0.17.1, heck 0.5.0, hkdf 0.13.0, hmac 0.13.0, http 1.5.0, httparse 1.10.1, hybrid-array 0.4.15, ico 0.6.0, indexmap 2.14.2, inout 0.2.5, itoa 1.0.18, jobserver 0.1.35, lazy_static 1.5.1, libc 0.2.191, libfuzzer-sys 0.4.13, log 0.4.34, memchr 2.8.3, minimal-lexical 0.2.1, miniz_oxide 0.8.9, miniz_oxide 0.9.1, nom 7.1.3, num-conv 0.2.2, num-traits 0.2.19, objc2 0.6.5, objc2-app-kit 0.3.2, objc2-core-foundation 0.3.2, objc2-encode 4.1.0, objc2-foundation 0.3.2, objc2-io-kit 0.3.2, once_cell 1.21.4, p256 0.14.0, pbkdf2 0.13.0, pem-rfc7468 1.0.0, percent-encoding 2.3.2, plain 0.2.3, png 0.18.1, poly1305 0.9.1, polyval 0.7.3, powerfmt 0.2.1, primefield 0.14.0, primeorder 0.14.0, proc-macro2 1.0.107, proptest 1.12.0, qrcode 0.14.1, quick-error 1.2.3, quick-xml 0.42.0, quote 1.0.47, rand 0.10.3, rand_core 0.10.1, rand_xorshift 0.5.0, rcgen 0.14.10, regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11, rfc6979 0.6.0, rustc-hash 2.1.3, rustc_version 0.4.1, rustix 1.1.5, rustls 0.23.46, rustls-pki-types 1.15.1, rustls-webpki 0.103.16, rusty-fork 0.3.1, salsa20 0.11.0, scroll 0.12.0, scroll_derive 0.12.1, sec1 0.8.1, semver 1.0.28, serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229, serde_json 1.0.154, serde_spanned 1.1.2, sha1 0.11.0, sha2 0.11.1, shlex 2.0.1, signature 3.0.0, simd-adler32 0.3.10, siphasher 1.0.4, smawk 0.3.3, ssh-cipher 0.3.0, ssh-encoding 0.3.0, static_assertions 1.1.0, strsim 0.11.1, subtle 2.6.1, syn 2.0.119, syn 3.0.9, tempfile 3.27.0, textwrap 0.16.4, thiserror 2.0.21, thiserror-impl 2.0.21, time 0.3.55, time-core 0.1.9, toml 1.1.8+spec-1.1.0, toml_datetime 1.1.2+spec-1.1.0, toml_parser 1.1.5+spec-1.1.0, toml_writer 1.1.3+spec-1.1.0, twofish 0.8.0, typenum 1.20.1, unarray 0.1.4, unicode-ident 1.0.27, uniffi 0.32.2, uniffi_bindgen 0.32.2, uniffi_core 0.32.2, uniffi_internal_macros 0.32.2, uniffi_macros 0.32.2, uniffi_meta 0.32.2, uniffi_pipeline 0.32.2, uniffi_udl 0.32.2, universal-hash 0.6.1, untrusted 0.9.0, ureq 3.5.0, ureq-proto 0.6.5, utf8-zero 0.8.1, wait-timeout 0.2.1, weedle2 5.0.0, winnow 1.0.4, wnaf 0.14.1, yasna 0.6.0, zeroize 1.9.1, zmij 1.0.23.
- **Copied, one file cut (1)**: ring 0.17.14 without `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (LD-247 (4)); its `.cargo-checksum.json` lists every other file with its upstream hash and keeps the package checksum. The crates.io package builds from `pregenerated/`, never from the `.pl` generators (`build.rs`: `.git` absent, so `generated_dir` is `pregenerated`; the `.pl` path only names the output file); an offline `x86_64-apple-darwin` build ran ring's build script and made `aesni-x86_64-macosx.o` from `pregenerated/aesni-x86_64-macosx.S`.
- **Stub (38)**: never built on a Mac (LD-247 (3)): in `Cargo.lock` but in no `cargo tree` for aarch64-apple-darwin or x86_64-apple-darwin (every feature of our crates; normal, build and dev edges; both workspaces). 16 are for other systems (`--target all` only), 22 are optional features nobody turns on. Each keeps its `Cargo.toml`, an empty `src/lib.rs` and a `.cargo-checksum.json` with the package checksum and an empty files list. asn1-rs 0.7.2, asn1-rs-derive 0.6.0, asn1-rs-impl 0.2.0, bit-vec 0.9.1, borsh 1.8.1, borsh-derive 1.8.1, cfg_aliases 0.2.2, data-encoding 2.11.1, der-parser 10.0.0, des 0.9.0, displaydoc 0.2.7, fiat-crypto 0.3.0, linux-raw-sys 0.12.1, num-bigint 0.4.8, num-integer 0.1.47, oid-registry 0.8.1, proc-macro-crate 3.5.0, r-efi 6.0.0, rusticata-macros 4.1.0, synstructure 0.13.2, time-macros 0.2.32, toml_edit 0.25.17+spec-1.1.0, unicode-width 0.2.2, wasi 0.11.1+wasi-snapshot-preview1, windows-link 0.2.1, windows-sys 0.52.0, windows-sys 0.61.2, windows-targets 0.52.6, windows_aarch64_gnullvm 0.52.6, windows_aarch64_msvc 0.52.6, windows_i686_gnu 0.52.6, windows_i686_gnullvm 0.52.6, windows_i686_msvc 0.52.6, windows_x86_64_gnu 0.52.6, windows_x86_64_gnullvm 0.52.6, windows_x86_64_msvc 0.52.6, x509-parser 0.18.1, zlib-rs 0.6.8.
- **Replaced (2)**: rustls-platform-verifier 0.7.1 by Larsal's own verifier in larsal-platform (`net.rs` `Verifier`, `macos/trust.rs`; LD-247 (2)); itertools 0.14.0 by standard-library code in `vendor/zxcvbn` (LD-136 change 6, LD-247 (5)).
- **Gone with a replacement (20)**: with rustls-platform-verifier: combine 4.6.9, core-foundation 0.10.1, core-foundation-sys 0.8.7, jni 0.22.4, jni-macros 0.22.4, jni-sys 0.4.1, jni-sys-macros 0.4.1, openssl-probe 0.2.2, rustls-native-certs 0.8.5, rustls-platform-verifier-android 0.2.0, same-file 1.0.6, schannel 0.1.30, security-framework 3.7.0, security-framework-sys 2.17.0, simd_cesu8 1.2.0, simdutf8 0.1.5, walkdir 2.5.0, webpki-root-certs 1.0.11, winapi-util 0.1.11; with itertools: either 1.19.0.
- **Patched path copies (2)**: zxcvbn 3.1.1 (`vendor/zxcvbn`, one new change: 6), ssh-key 0.7.0-rc.11 (`vendor/ssh-key`, unchanged).

Banned names (LD-247): the name guard scans `vendor/` like every folder and passes on the whole shared tree (11,619 files on 2026-10-30; the count grows with the tree). Full copies of the six packages LD-247 names make it fail on exactly their files (10 hits: itertools' `src/duplicates_impl.rs`, ring's `aesni-x86_64.pl`, rustls-platform-verifier's license, README and one test, schannel's `src/schannel_cred.rs`, four windows-sys 0.61 files); as vendored they are replaced, cut or stubs.

Checks added (scripts/check.sh):

- G1 `vendor` (`scripts/check-vendor.sh`): `cargo metadata --offline --locked` with an empty cargo home, workspace and fuzz, fails on any package that is not a path in the tree or a crates.io package read from `vendor/crates-io`; `cargo tree` for both Mac targets fails if it names a stub; any symbolic link in `vendor/`, `crates/` or `fuzz/` (build output in `fuzz/target` aside) fails, so no copy can be a link to a folder or file outside the tree (Checker 1 finding 2).
- Verifier handshake signatures (Checker 1 finding 1): `net::tests::ld247_handshake_signed_with_another_key_refused` serves the good 127.0.0.1 leaf signed with another key, in TLS 1.3 and TLS 1.2; both are refused ("the server did not prove it holds the certificate's key") before any request is sent. It fails when either `verify_tls13_signature` or `verify_tls12_signature` returns valid without checking.
- `audit-copies` (F-113): a lockfile written from `vendor/*/Cargo.toml` (each path copy's upstream name and version as a crates.io package) goes through `cargo audit -n -f`. `audit-fuzz` (F-114): `cargo audit -n -f fuzz/Cargo.lock`.
- `deny-fuzz` (F-114): `cargo deny --manifest-path fuzz/Cargo.toml` with `deny.toml` minus its `larsal-platform/net` feature line; `deny.toml` gains the named exception for libfuzzer-sys 0.4.13 (NCSA, fuzz only). cargo deny already sees the two path copies for licenses, bans and sources; their advisories go through `audit-copies`.
- Every cargo build in check.sh, check-vendor.sh, repro-build.sh, build-core.sh, make-sbom.sh and interop.sh runs `--offline --locked` (`cargo fmt`, `cargo deny --locked check` and the plain `cargo audit` still fetch the advisory database, section 9 item 5) (cargo-fuzz takes no `--locked`; the config's `net.offline` holds it).

Not done in step 1 (steps 2 to 5): cutting the stubs' parents' features and target tables, the other replacements (R1, R3 to R14), the trims, and the uniffi cut. The crate's own `#[cfg(test)]` modules in `vendor/zxcvbn` still do not build (they need quickcheck and were written for integer guesses before LD-136); the same 61 compile errors before and after change 6, so a run of 100,035 passwords through the old and the new copy (scores, guesses, every match with its l33t substitutions, feedback text) is the proof that change 6 changes nothing: both outputs have the same SHA-256.

## 11. Step 2 done (2026-10-30)

Built by the E0-S7 step 2 Builder, as section 8 step 2 says. Checker 1 passed it on 2026-10-30, after four fixes. Checker 2 passed the crypto copies the same day (proof section 20). A Verify agent signed step 2 the same day: every check of the story passed again in a private copy (proof section 21). Proof: [security/parity/E0-S7-step2.md](../../security/parity/E0-S7-step2.md).

What changed in the tree:

- **Manifest cuts (14 copies, step 2.1)**: only `Cargo.toml` changed; no code file. Optional features nobody turns on: rcgen `x509-parser`, yasna `bit-vec`, bit-vec 0.10.1 `borsh`, ssh-cipher `tdes`, time `macros`, textwrap `unicode-width`, flate2 `zlib-rs` (each with the weak `name?/feature` entries that named the dependency). Target tables of other systems: the Windows tables of ring, errno, rustix and tempfile; rustix's two Linux tables of linux-raw-sys (and the `linux-raw-sys/...` entries in 7 of its features, whose names stay); getrandom 0.2.17 WASI; getrandom 0.4.3 UEFI; curve25519-dalek's fiat backend. rustls-platform-verifier's rows were skipped (gone since step 1). The workspace `Cargo.toml` lost the unused `data-encoding` pin (F9).
- **Lockfiles (step 2.2)**: one offline rewrite by cargo, removals only. `Cargo.lock` 245 entries to 207 (registry 232 to 194). `fuzz/Cargo.lock` 125 to 121 (registry 115 to 111). The 38 packages that left are the 38 stubs of step 1. They are now out of `vendor/crates-io`, which holds 197 packages: 183 plain copies and 14 cut copies.
- **Checksums (step 2.3)**: each cut copy has a new `.cargo-checksum.json` for its files, with the same `package` checksum. Beside it, `.cargo-checksum.upstream.json` is the list cargo vendor wrote. For ring it was rebuilt from the published `.crate`, by a method that reproduces the list of all 197 copies byte for byte. Against its `.crate`, each copy differs only in `Cargo.toml`, plus files cargo vendor never copies and ring's step 1 cut.
- **Placeholders (step 2.4)**: none needed. Every parent could be edited.
- **Check**: `scripts/check-vendor.sh` gains rule 4. It names the 14 cut copies: each must keep its upstream list, and no other copy may have one (LD-254 (1)). A cut copy's new list must name the same package as its upstream list, and every file in the new list but `Cargo.toml` and the upstream list must have its upstream hash. In every copy that is not a stub, cut or plain, every file on disk, in any folder, must be in its list (Checker 1: cargo hashes only the files a list names and builds a `build.rs` it finds when the manifest names none, so a file not in the list could be compiled through a changed `Cargo.toml`, or with nothing else changed). Rule 1 also fails on a target (library, build script, binary, test) of any package whose source file is not a `.rs` file in that package's folder or has `/../` in its path (Checker 1), so a changed `Cargo.toml` cannot point cargo at a file elsewhere in the tree or outside it, nor make itself (valid TOML can be valid Rust too) a crate root or a build script. So no code line can hide behind a rewritten list (rule 3). It fails on its 14 mutants (M1 to M4, X1 to X4, Y1, Y2, Z1, Z2, W1, W2), and the 6 earlier mutants still fail. Its scope (LD-254 (2)): a tripwire against drift and simple edits in `vendor/`. A copy whose list and manifest are rewritten together is caught by the review of 'Updating a copy later' (section 8) and the `.crate` diff, not by the script.
- **Size**: `vendor/` 8,432 files (86,423,315 bytes) before, 8,332 files (86,450,876 bytes) after; 102 MB both. The Rust lines (1,946,975 by `wc -l`) do not change: the 1.42 million lines of the cut packages left in step 1, when they became stubs.

Checks: the offline locked workspace build passes with an empty cargo home, and so do the 2,437 workspace tests, the net tests (44 plus 1), the AT-B01 known answers in release (163) and a check of the fuzz workspace. cargo deny and the three audit steps pass offline, with the same warnings as before. The bill of materials is byte-identical (151 components). The name guard passes on the shared tree (11,523 files).

Not done in step 2: the replacements (step 3), the trims (step 4), the tools (step 5). Notes for the lead are in the proof file: the approved-crates row naming data-encoding, a possible pedigree note for cut copies in the bill of materials, and vendor/ssh-key's `tdes` feature.

## 12. Step 3a done (2026-10-30)

Built by the E0-S7 step 3a Builder: batch 3a of LD-255 (3) (R1, R2, R3, R7, R11, all in `vendor/zxcvbn`) and P1 of LD-255 (1). Checker 1 and Checker 2 passed it on 2026-10-30 (proof sections 8 and 9). A Verify agent signed step 3a the same day: every check of the story passed again in a private copy, and the published zxcvbn 3.1.1 and the new copy find the same repeats, recent years and dates in 300,000 passwords (proof section 10). Proof: [security/parity/E0-S7-step3a.md](../../security/parity/E0-S7-step3a.md).

What changed in the tree:

- **vendor/zxcvbn** (LD-136 changes 7 to 10, listed in its Cargo.toml and lib.rs): R1, its 15 statics are `std::sync::LazyLock` (`rust-version` 1.80); R2, nothing to do, itertools left in step 1 (change 6), and it is in no lockfile and not in `vendor/crates-io`; R3, the reference year is `utc_year(SystemTime::now())`, Larsal's own days-to-civil code (year only); R7 and R11, the recent-year pattern, the two maybe-date patterns and the three repeat patterns are hand-written matchers (`find_repeat`, `shortest_unit`, `split_date` and a loop); P1, `build = false`. The copy has no outside dependency left (the optional `derive_builder` and `serde` are never turned on). Its MIT license file is unchanged.
- **Test**: `crates/larsal-core/tests/zxcvbn_copy.rs` (2 tests: the year around 1 January and 1 March for 1601 to 2400 against larsal-model's calendar; 36 passwords whose matches were read from the copy before the change). Each of 12 mutants of the new code fails it.
- **Lockfiles**: `Cargo.lock` 207 entries to 202 (registry 194 to 189): lazy_static 1.5.1, regex 1.13.1, fancy-regex 0.18.0, bit-set 0.8.0 and bit-vec 0.8.0 left; cargo also writes 3 dependency names without a version now that one version is left. `fuzz/Cargo.lock` 121 to 111 (registry 111 to 101): those 5 plus time, time-core, deranged, powerfmt and num-conv. Nothing added, no path package added; every remaining entry keeps its version, source and checksum.
- **vendor/crates-io**: 197 to 192 copies; the 5 folders removed, no other file changed.
- **Stay**: time 0.3.55, time-core, deranged, powerfmt and num-conv, for rcgen and yasna (larsal-platform's `net` test certificates); they are no longer compiled into Larsal. aho-corasick 1.1.5 stays in both lockfiles and in `vendor/crates-io` because regex-automata names it in a weak feature (`aho-corasick?/std`), which Cargo's lockfile keeps; nothing compiles it now. It can leave with the regex-automata trim (step 4.3). `cut_copies` in check-vendor.sh is unchanged (no cut copy left).
- **Bill of materials**: 151 to 140 components. The 11 that left are lazy_static, regex, aho-corasick, fancy-regex, bit-set 0.8.0, bit-vec 0.8.0, time, time-core, deranged, powerfmt and num-conv (the research's 13 for zxcvbn less itertools and either, which left in step 1); nothing added or changed.
- **plan/architecture.md**: the rows "Strength estimate" and "Patterns".
- **Side effect**: with `regex` gone, regex-automata and regex-syntax are built with only the features Larsal names in `Cargo.toml` (no literal prefilters, no full DFA, no Unicode category or script tables), as LD-122 and LD-123 describe; every test, the release timed tests among them, passes.

Proof that nothing else changed: one run of the copy before against the new copy on the copy's own test strings (239, with and without user inputs) and 100,000 generated passwords (fixed seed), comparing the score, guesses, guesses_log10, crack times, feedback, the whole match sequence and Larsal's own `omnimatch` and `estimate_guesses` path: both outputs 693,012,250 bytes with one SHA-256. A second run, every Unicode character as a date separator and as a repeat plus every short string over two small alphabets (2,589,573 passwords), also gave one SHA-256 for both.

Checks: the offline locked workspace build with an empty cargo home; 2,439 workspace tests (2,437 before plus the 2 new); the net tests (44 plus 1); larsal-ffi with `net` (297); the release timed tests; AT-B01 in release (163); fmt, the three clippy steps and the fuzz check; cargo deny and the three audit steps offline, with the same warnings as before; check-vendor (and its 20 earlier mutants still fail); the name guard. On the shared tree after the apply: the offline locked build, check-vendor and the name guard pass.

Not done in step 3a: batches 3b (R4, R5, R6, R8) and 3c (R9, R10, R12), the trims (step 4), the tools (step 5).

## 13. Step 3b done (2026-10-31)

Built by the E0-S7 step 3b Builder: batch 3b of LD-255 (3), as far as the rules let it go. R4 and R6 are built. R5 and R8 are not: each stops at a rule, and the lead decides (proof section 6). Checker next. Proof: [security/parity/E0-S7-step3b.md](../../security/parity/E0-S7-step3b.md).

What changed in the tree:

- **R4 thiserror**: the 13 error enums of our crates (144 messages: larsal-crypto 1, larsal-format 3, larsal-core 3, larsal-autotype 1, larsal-hwkey 1, larsal-sshagent 1, larsal-platform `net` 1, larsal-ffi 2) have hand-written `Display` and `std::error::Error` impls; each `#[error]` text is now one `match` arm, word for word. No variant used `#[from]`, `#[source]`, `transparent` or a field named `source`, so `source()` stays `None` for all, as before. `thiserror` left the 8 crates' manifests, the `net` feature and the workspace pins; two tests that listed larsal-crypto's dependencies no longer skip it. A harness printed `Display`, `Debug` and `source()` of all 144 variants before and after: the same bytes.
- **R6 log**: `crates/log` is Larsal's own facade (version 0.4.999, no published version; in place of log 0.4.34 by `[patch.crates-io]`): `trace!`, `debug!`, `warn!`, `log_enabled!` and `Level::{Debug, Trace}`, the only API that ureq, ureq-proto and goblin call. The format arguments are type-checked and never run, and `log_enabled!` is false: what the published crate did here, since nothing in the tree installs a logger. One unit test. It is a workspace member, so it gets fmt, clippy, the unsafe count and the tests of our own crates.
- **Lockfiles**: `Cargo.lock` 202 entries, as before (registry 189 to 188): log 0.4.34 from crates.io became the path package log 0.4.999 (its `source` and `checksum` lines gone, its version line changed); 8 dependency names `thiserror` gone from our crates. `fuzz/Cargo.lock` 111 to 109 (registry 101 to 99): thiserror 2.0.21 and thiserror-impl 2.0.21 gone, with 5 dependency names. The one path package added: `log` 0.4.999 (`crates/log`).
- **vendor/crates-io**: 192 to 191 copies; `log-0.4.34` removed, no other file changed. `cut_copies` in check-vendor.sh unchanged.
- **Stay, and who needs them**: thiserror 2.0.21 and thiserror-impl 2.0.21, for cargo_metadata 0.23.1 in the bindings generator (uniffi, uniffi_bindgen); no longer compiled into Larsal. base64 0.23.1 (R5 not built; ureq and ureq-proto need it until the ureq trim, step 4.7). getrandom 0.4.3 (R8 not built; tempfile, rand and jobserver need it too).
- **Bill of materials**: 140 to 138 components: thiserror 2.0.21, thiserror-impl 2.0.21 and log 0.4.34 gone; log 0.4.999 added as one of Larsal's own crates (no license row, no notice, like the app crates). Nothing else changed.
- **plan/architecture.md**: the approved-crates rows "Errors, data" and "HTTPS for opt-in features".

Not done in step 3b: R5 base64 (base64ct is not in the approved-crates table) and R8 getrandom 0.4 (LD-221 (7), Rust rule 2); batch 3c (R9, R10, R12), the trims (step 4), the tools (step 5).

## 14. Step 3c done (2026-10-31)

Built by the E0-S7 step 3c Builder: batch 3c of LD-255 (3) (R9, R10, R12). Signed 2026-10-31 (Checker 1, Checker 2, Verify; LD-260). Proof: [security/parity/E0-S7-step3c.md](../../security/parity/E0-S7-step3c.md).

What changed in the tree:

- **R9 clap**: larsal-cli `args.rs` parses the options itself: `--name value`, `--name=value`, `-xvalue`, `-x=value`, combined short flags, `--`, the hidden aliases, `-h` and `--help`, with the problems the old parser reported, in its order. The INT-10.2 and INT-10.3 tests and the M10-02 texts are unchanged; one new test. 280,840 command lines (every command, the shell with and without an open vault) give the same result or problem, byte for byte, through the old and the new parser.
- **R10 ico**: larsal-core `icons.rs` reads ICO itself: at most 256 images (`MAX_ICO_IMAGES`), each entry with a zero reserved byte and its data inside the file, all data no larger than the file; each image's size from its own header; the largest within the pixel limit; a PNG through `check` and `decode_png`, a BMP of 1, 4, 8, 16, 24 or 32 bits with its mask through `decode_bmp` (checked slices only; F-043's short colour table refused). The test encoder `tests/common/ico.rs` writes the bytes the old crate wrote (12,000 files compared); two new tests. Old against new on 13,263 files: the same, but the 2 ICOs of more than 256 images, now refused.
- **R12 serde_json and serde**: larsal-model `json.rs` is Larsal's own reader and writer: strict RFC 8259, at most 16 MiB and 127 levels (the old crate's depth), members in key order, a repeated key keeps the last value or is refused (`from_slice_unique`), numbers kept as written, the compact and the two-space pretty form. Used for the settings files, the saved searches, the site access and last use items, the instance line (no longer serde's derive) and the tests that read JSON. The import keeps its own reader (`import/json.rs`, Larsal's code since E4-S13, unchanged; it never used serde_json). Old against new on 37,832 inputs: the same values but in 310 documents a long number, now correctly rounded (55 of them the old crate refused); the written forms of the 15,399 with whole numbers byte-identical; of 7,180 instance lines, 3 JSON arrays are now refused.
- **Lockfiles**: `Cargo.lock` 202 entries to 201 (registry 188 to 187): ico 0.6.0 gone, and the dependency names `clap`, `ico`, `serde` and `serde_json` of our crates; removals only. `fuzz/Cargo.lock` 109 to 101 (registry 99 to 91): ico, itoa, serde, serde_core, serde_derive, serde_json, syn 3.0.9 and zmij gone; one name now without its version (`syn`). No path package added: the JSON code is a module of larsal-model.
- **vendor/crates-io**: 191 to 190 copies; `ico-0.6.0` removed, no other file changed. `cut_copies` in check-vendor.sh unchanged.
- **Stay, and who needs them**: clap 4.6.7, clap_builder, clap_derive, clap_lex, anstyle and strsim, for uniffi's `cli` feature in the bindings generator (`crates/uniffi-bindgen`) until step 5 item 1; serde, serde_core and serde_derive, for uniffi_macros (uniffi's proc macro, which runs on the host in every larsal-ffi build, so they are compiled in Larsal's build, also by `scripts/build-core.sh`; serde_core also through its toml, serde_spanned and toml_datetime) and for cargo_metadata (uniffi, uniffi_bindgen), askama and basic-toml in the bindings generator; serde_json and zmij, for cargo_metadata in the bindings generator only (not in Larsal's build). None of them is linked into Larsal or the `larsal` tool any more (`cargo tree -e normal,no-proc-macro`, both Mac targets: larsal-ffi with `net` 128 packages to 123, larsal-cli 100 to 91; `-e normal -i serde`: serde ← uniffi_macros (proc-macro) ← uniffi ← larsal-ffi). itoa stays in Larsal through http (`net`). byteorder 1.5.0 stays for blowfish (bcrypt-pbkdf, `vendor/ssh-key`) and is now built with no features, where before it had `default, std`: Cargo's feature unification once ico left, no file changed, and blowfish computes the same bytes (step3c.md section 16 note 1).
- **Bill of materials**: 138 to 128 components: anstyle, clap, clap_builder, clap_lex, ico, serde, serde_core, serde_derive, serde_json and zmij gone; itoa now ships in Larsal.app only. Nothing added; every other component identical.
- **Fuzzing**: new target `json_reader` (18 seeds in `fuzz/corpus/json_reader`, written by `write_json_reader_seeds`): its seeds, then 300 seconds (10,012,754 runs), no crash. `icon_decode` on its whole corpus (13,263 files: seeds, the grown corpus, the smoke units, generated files and F-043's 135), then 300 seconds (502,648 runs), no crash.
- **plan/architecture.md**: the approved-crates rows "Icon images", "Errors, data" and "Command line".

Not done in step 3c: batch 3d (R5 base64, LD-258 (2)), the trims (step 4), the tools (step 5: clap leaves the tree with the bindings generator's own main).

## 15. Step 3d done (2026-10-31)

Built by the E0-S7 step 3d Builder: batch 3d of LD-255 (3), R5 base64 (LD-258 (2), LD-259 (2), LD-260 (4)), the last batch of step 3. Built and proven first beside 3c in a private copy, then rebased onto the tree 3c left and proven again. Signed 2026-10-31 (Checker 1, Checker 2, Verify; LD-261); with it E0-S7 is Done. Proof: [security/parity/E0-S7-step3d.md](../../security/parity/E0-S7-step3d.md).

What changed in the tree:

- **R5 base64**: larsal-crypto `base64.rs` over base64ct 1.8.3 (approved for larsal-crypto only, LD-258 (2)): `Form::Padded` (standard alphabet with `=`; on read exact padding, unused low bits ignored, RFC 4648 section 3.5, for key files FMT-18.12), `Form::PaddingOptional` (standard alphabet; read with full, partial or no padding, never more `=` than the encoding writes, unused bits zero) and `Form::Url` (URL-safe, written without padding, read as `PaddingOptional`); `encode`, `encode_secret`, `decode` and `decode_secret`, the secret ones only into wiping buffers and under the stack wipe `secret::scrubbed`, as every crypto call of larsal-crypto (Checker 2); a new `Error::Base64` with no data. Every call our crates made to the `base64` crate goes through it: the Bitwarden and other imports, the HTML export icon, the key file reader, the known_hosts name of the ssh-agent, an larsal-ffi unit test, the tests and the `opvault_import` fuzz target. `base64ct` is in `CRYPTO_CRATES` of larsal-cli `main.rs` and larsal-ffi `cli.rs`, so `--debug-info` and F09 name it. Old against new: 6,416,989 texts (5,216,989 of them exhaustive) and 265,793 encodes through every old engine and the new forms: all equal. 10 new tests; 24 mutants of the module and of each caller's form, each fails a test.
- **Lockfiles**: `Cargo.lock` 201 entries, as before (registry 187): the dependency name `base64` gone from larsal-core, larsal-ffi, larsal-format and larsal-sshagent, `base64ct` added under larsal-crypto. `fuzz/Cargo.lock` 101 to 100 (registry 91 to 90): base64 0.23.1 gone with its names in larsal-core, larsal-format, larsal-fuzz and larsal-sshagent, `base64ct` added under larsal-crypto. No package entry added, no other entry changed.
- **vendor/crates-io**: 190 copies, no file changed. `base64ct-1.8.3` is a plain copy, byte-for-byte its `.crate`.
- **Stays, and who needs it**: base64 0.23.1 and its copy, for ureq 3.5.0 and ureq-proto 0.6.5 (the `net` feature, Larsal.app only), until the ureq trim (step 4 item 7). No crate of Larsal names it any more; the `larsal` tool and the fuzz workspace no longer build it (`cargo tree -e normal,no-proc-macro`, both Mac targets: larsal-cli 91 to 90 packages, larsal-ffi without `net` 109 to 108, with `net` 123 as before). Its features changed: it is now built with `alloc` and `std` only (it was `alloc`, `default`, `simd-unsafe` and `std`). That is Cargo's feature unification once our crates left it: we took its defaults, and ureq and ureq-proto take it with `default-features = false, features = ["std"]`. So its SIMD engines and their unsafe code leave Larsal.app; ureq and ureq-proto call `BASE64_STANDARD`, the general-purpose engine, which both sets have. No other package's features changed.
- **Bill of materials**: 128 components, as before; none gone, none added. base64 0.23.1 now ships in Larsal.app only (`larsal:ships-in` was "Larsal.app, app"), because the `larsal` tool no longer links it; base64ct was already a component. In the graph, larsal-core, larsal-format and larsal-sshagent lose their edge to base64, and larsal-crypto gains one to base64ct. The notices change only in base64's product column.
- **check-vendor.sh**: rule 1's `cargo metadata` now runs with `--all-features` (Checker 1). Without it, rule 1 listed only the packages of the default features, so the 8 that only `net` reaches (base64 0.23.1 since R5, and http, httparse, rustls, rustls-webpki, ureq, ureq-proto and utf8-zero) were not checked, and base64 or rustls read from a copy in /tmp passed. Now PASS with 201 packages, 187 from vendor/crates-io (every Cargo.lock entry; fuzz 100 and 90 as before). Its mutants still fail, and four new ones do too: B1 and B2 for base64ct, B3 and B4 (base64 and rustls from /tmp, the lock rewritten).
- **plan/architecture.md**: the approved-crates row "Base64, Base32, hex".

Not done in step 3d: the trims (step 4, base64 itself leaves with ureq's, item 7) and the tools (step 5). With 3d, every batch of step 3 is built; E0-S7 is Done when its Verify signs (LD-259 (1)).

## 16. Step 4a done (2026-10-31)

Built by the E0-S7 step 4a Builder: batch 4a of the follow-up (LD-259 (1), LD-261 (1)), section 8 step 4 items 1 to 3, non-crypto copies, whole files cut only. Checker next. Proof: [security/parity/E0-S7-step4a.md](../../security/parity/E0-S7-step4a.md).

What changed in the tree:

- **Item 1, libc 0.2.191**: the 390 `.rs` files for other systems (Linux, Windows, WASI, the BSDs, Fuchsia and the rest) are cut; the Apple modules (both Mac targets, plus 32-bit Apple), the shared files and `build.rs` stay. 453 files to 64, 133,739 Rust lines to 13,920.
- **Item 2, objc2-foundation, objc2-app-kit, objc2-core-foundation, objc2-io-kit 0.3.2**: the generated files of every feature no build turns on are cut (161, 291, 34 and 12 files); the generated files of the features our crates and copies turn on stay (Foundation 9, AppKit 2, Core Foundation 11, IOKit `hid`). 289,138 Rust lines to 77,455 together.
- **Item 3, regex-automata 0.4.18**: the full-DFA engine (`dfa-build`, `dfa-search`: 10 files of `src/dfa/`) and its own `perl_word` table (built only when `syntax` or `unicode-perl` is off) are cut, and its `Cargo.toml` lost the optional `aho-corasick` dependency (the multi-literal prefilter, never on) with the feature that turns it on and its 3 weak entries: 10 lines removed. **regex-syntax 0.8.11 is not cut**: every test build takes all its Unicode tables, because proptest names it with its default features, so no table is free to go (only `benches/bench.rs`, 1,234 bytes, is never compiled).
- **How "never compiled" is proven**: the dep-info of six aarch64 builds (debug and release, all and default features, larsal-ffi with `net`, larsal-cli, larsal-hwkey, fuzz); for x86_64, whose standard library is not installed, a module probe (`rustc --emit=dep-info` against placeholder `core` and `std` crates) that gives exactly the real aarch64 set on aarch64 and differs on x86_64 only by 3 Apple files of libc, all kept; and every cut module's gate read from the source: one feature that is off, or a `target_os`, `target_env` or `target_vendor` branch, the same on both Mac targets. `cargo tree -e features` for both Mac targets in 9 forms (workspace all and default features, larsal-ffi with and without `net`, larsal-cli, larsal-hwkey, larsal-core, larsal-platform `net`, fuzz): all 18 outputs byte-identical before and after.
- **Each copy**: stays a plain copy in `vendor/crates-io` with a new `.cargo-checksum.json` and cargo vendor's list kept as `.cargo-checksum.upstream.json`; against its published `.crate` it lacks only its cut files, and only regex-automata's `Cargo.toml` differs. `cut_copies` in `scripts/check-vendor.sh` has 20 names now (the 14 of step 2 and these 6); its rules are unchanged, and two new mutants for file cuts (F1 a cut file put back changed and listed, F2 one put back unlisted) fail, as do the 25 earlier ones (28 runs in all).
- **Lockfiles**: removals only. `Cargo.lock` 201 entries to 200 (registry 187 to 186), `fuzz/Cargo.lock` 100 to 99 (registry 90 to 89): aho-corasick 1.1.5 gone with its name in regex-automata's entry. No path package added, no other entry changed. `vendor/crates-io` 190 copies to 189.
- **Same bytes**: `larsal`, `liblarsal_ffi.a` (`net`) and `liblarsal_hwkey.rlib` built in release from the tree before and from the cut tree at one path have the same SHA-256.
- **Bill of materials**: 128 components, byte-identical (`sbom.cdx.json`, the notices and the standard library's notice): no component changed, because the cut copies keep their version, licenses and Cargo.lock checksum, and aho-corasick shipped in nothing since step 3a.
- **Size**: `vendor/` 8,130 files, 84,126,480 bytes, 2,406,837 lines (1,920,953 of Rust) before; 7,189 files, 70,324,248 bytes, 2,038,237 lines (1,553,824 of Rust) after; 99 MB to 84 MB. Removed: 941 files, 13,802,232 bytes, 368,600 lines (367,129 of Rust).
- **plan/architecture.md**: the approved-crates rows "Patterns", "macOS APIs", "Hardware keys over USB" and "macOS system calls".

Checks: the offline locked build of every target with an empty cargo home; 2,460 workspace tests (per binary in the proof); the net tests (44 plus 1); larsal-ffi with `net` (297); the release timed tests (250); AT-B01 in release (171); fmt, the three clippy steps, the fuzz check and the nightly fuzz build of the 23 targets; cargo deny and the three audit steps offline, with the same warnings as before; check-vendor and its 28 mutant runs; the name guard.

Not done in step 4a: the regex-syntax tables (above); the pedigree note for cut copies in the bill of materials (LD-254 (3)); batches 4b to 4d and step 5.

## 17. Step 4b done (2026-10-31)

Built by the E0-S7 step 4b Builder: batch 4b of the follow-up (LD-259 (1), LD-261 (1)), section 8 step 4 items 4 and 5, the crypto copies, whole files cut only (AGENTS.md rule 3). Checker next (Checker 2 too: crypto copies). Proof: [security/parity/E0-S7-step4b.md](../../security/parity/E0-S7-step4b.md).

What changed in the tree:

- **Item 4, ring 0.17.14**: the pregenerated assembly for other targets (`*-elf.S`, `*-linux32.S`, `*-linux64.S`, `*-win64.S`, the NASM and win32n `.asm` and `.o` files, `prefix_symbols_nasm.inc`: 81 files), the perlasm scripts for 32-bit ARM and x86 (15) and `tests/` (25) are cut. Kept: the 11 `*-ios64.S` (arm64), the 12 `*-macosx.S` (x86_64), the two prefix headers and the armv8 and x86_64 perlasm. Its build script reads the same 47 files on aarch64 and 54 on x86_64 as before (clang `-MD`), and makes the same objects. 392 files to 271, 7,790,261 bytes to 4,609,007.
- **Item 5, the other crypto copies**: `tests/` and `benches/` of 54 copies; the LoongArch, RISC-V and WebAssembly backends of sha2 and sha1 and cpufeatures' LoongArch file; curve25519-dalek's 32-bit (`u32`) and `fiat` backends; p256's 32-bit field and scalar files and polyval's 32-bit multiply; getrandom 0.4.3's backends and helpers for other systems (all but `getentropy.rs` and `utils/get_errno.rs`) and getrandom 0.2.17's 17 backends for other systems (LD-221 (7)). 448 files in 55 copies in all; the per-copy table is in the proof.
- **Skipped**: cfg-if, ecdsa, ghash and rustls stay plain (their `tests/` and `benches/` hold under 1.4 KB each, less than the upstream list a cut copy keeps); 10 crypto copies have nothing of these kinds. Files behind features that are off, the portable backends, ring's other-system Rust files and hand-written 32-bit ARM code, and the `examples/` of once_cell and rustls are kept: items 4 and 5 do not name them.
- **How "never compiled" is proven**: the dep-info of seven aarch64 builds and the nightly fuzz build; for x86_64, the module probe of step 4a over all 68 crypto copies that are not proc macros (every feature set, debug assertions on and off, both panic modes, the cfgs their build scripts set), which gives exactly the real aarch64 set on aarch64; ring's file reads traced by clang on both Mac targets. 0 cut files in any of these sets, and the probe of the cut copies finds every module. `cargo tree -e features` for both Mac targets in 10 forms: all 20 outputs byte-identical.
- **Each copy**: stays a plain copy in `vendor/crates-io` with a new `.cargo-checksum.json` and cargo vendor's list kept as `.cargo-checksum.upstream.json` (50 new; the 5 copies cut before keep theirs); against its published `.crate` it lacks only its cut files, and no file in it differs. `cut_copies` in `scripts/check-vendor.sh` has 70 names now; its rules are unchanged, and nine new mutants (C1 to C4 for the new kinds of cut, A4 to A6, A4b and A6b for a crypto copy from outside the tree) fail, as do the earlier ones (48 runs in all, with two controls that pass).
- **Lockfiles**: unchanged (`e23c677e…`, `d2758a2f…`). No package left; `vendor/crates-io` keeps its 189 copies.
- **Same bytes**: `larsal`, `liblarsal_ffi.a` (`net`) and `liblarsal_hwkey.rlib` built in release from the tree before and from the cut tree at one path have the same SHA-256.
- **Bill of materials**: 128 components, byte-identical: no component changed, because the cut copies keep their version, licenses, top-level license files and Cargo.lock checksum.
- **Size**: `vendor/` 7,189 files, 70,324,248 bytes, 2,038,237 lines (1,553,824 of Rust) before; 6,791 files, 64,608,188 bytes, 1,850,630 lines (1,488,215 of Rust) after; 84 MB to 78 MB. Removed: 398 files, 5,716,060 bytes, 187,607 lines (65,609 of Rust).
- **plan/architecture.md**: the approved-crates intro and the rows "SHA-2, SHA-1", "OS random source", "ECDSA P-256", "Ed25519", "SSH keys" and "HTTPS for opt-in features".

Checks: the offline locked build of every target with an empty cargo home; 2,460 workspace tests (per binary in the proof); the TLS tests (`net`: 44 plus 1); larsal-ffi with `net` (297); the release timed tests (250); AT-B01 in release (171); fmt, the three clippy steps, the fuzz check and the nightly fuzz build of the 23 targets; cargo deny and the three audit steps offline, with the same warnings as before; check-vendor and its 48 mutant runs; the name guard.

Not done in step 4b: the kept files above; the pedigree note for cut copies in the bill of materials (LD-254 (3)); batches 4c and 4d and step 5.

## 18. Step 4c done (2026-10-31)

Built by the E0-S7 step 4c Builder: batch 4c of the follow-up (LD-259 (1), LD-261 (1)), section 8 step 4 item 6, uniffi (F6) and uniffi_core (R14). Not crypto. Checker next. Proof: [security/parity/E0-S7-step4c.md](../../security/parity/E0-S7-step4c.md).

What changed in the tree:

- **vendor/uniffi** (uniffi 0.32.2, MPL-2.0): a `[patch.crates-io]` path copy; `uniffi_pipeline` is optional and only the `cli` feature (the bindings generator) turns it on, since only `src/cli/uniffi_bindgen.rs` uses it. No source file changed; the manifest lists its changes at its top. The copy leaves out README.md, tests/ and the packaging files, with their manifest entries, as `vendor/ssh-key` does.
- **vendor/uniffi_core** (uniffi_core 0.32.2, MPL-2.0): a path copy without the `static_assertions` dependency. In `src/lib.rs` (MPL-2.0 notice kept, each place marked `Larsal change (E0-S7 R14)`), `deps::static_assertions` is a module with the two macros the generated scaffolding calls there, `const_assert!` (`const _: () = assert!(..)`) and `assert_impl_all!` (a function with the trait bounds), 2 lines removed and 32 added. The research named only `const_assert!`; uniffi_macros also calls `assert_impl_all!` 9 times. Old and new accept and refuse the same 7 cases with the same error codes, and the scaffolding's version check still fails on another version.
- **No `publish = false`** in the two copies: deny.toml's `[licenses.private] ignore = true` makes cargo deny skip the license of any crate marked so, and these MPL-2.0 copies must stay checked. The same gap for vendor/zxcvbn and vendor/ssh-key is F-137 (Low).
- **Packages that leave Larsal's build**: larsal-ffi's library no longer compiles uniffi_pipeline, tempfile, fastrand, rustix, errno, heck, indexmap, hashbrown and equivalent (the 9 of F6 and item 6, with uniffi_pipeline in place of getrandom 0.4, which stays as Larsal's random source, LD-221 (7)) nor static_assertions: `cargo build --target aarch64-apple-darwin -p larsal-ffi --features net` compiles 121 target units before and 111 after, the host units the same 47; `cargo tree -e normal,no-proc-macro`, both Mac targets: larsal-ffi with `net` 123 packages to 113, without 108 to 98, larsal-cli unchanged. The 9 still run on the build machine inside the uniffi_macros proc macro (uniffi_meta names uniffi_pipeline) and in the bindings generator, so build-core.sh, which builds for the host, loses only static_assertions; none of the 9 was ever linked, and the release `liblarsal_ffi.a` loses only the static_assertions member.
- **Lockfiles**: `Cargo.lock` 200 entries to 199 (registry 186 to 183): static_assertions 1.1.0 gone, uniffi and uniffi_core now the two path packages (their `source` and `checksum` lines gone), uniffi_core without the name `static_assertions`; removals only. `fuzz/Cargo.lock` unchanged (no uniffi there).
- **vendor/crates-io**: 189 copies to 186 (uniffi-0.32.2, uniffi_core-0.32.2, static_assertions-1.1.0 removed). `cut_copies` in check-vendor.sh unchanged (70); the audit list of path copies takes the two new ones by itself (4 now).
- **Bill of materials**: 128 components to 117: equivalent, errno, fastrand, hashbrown, heck, indexmap, rustix, static_assertions, tempfile, uniffi_pipeline and uniffi_internal_macros gone (uniffi_internal_macros, a proc macro, was reached only through uniffi_pipeline); uniffi and uniffi_core now carry `pedigree` (patched copies) in place of their crates.io checksum. 103 license texts to 94, 12 crates without a license file to 10.
- **Size**: `vendor/` 6,791 files, 64,608,188 bytes, 1,850,630 lines (1,488,215 of Rust) before; 6,756 files, 64,484,061 bytes, 1,847,168 lines (1,487,030 of Rust) after. Removed: 35 files, 124,127 bytes, 3,462 lines (1,185 of Rust).
- **Same output**: the Swift bindings (`LarsalCore.swift`, `LarsalFFI.h`, `module.modulemap`) are byte-identical, and the library exports the same 506 C functions; `larsal` and `liblarsal_hwkey.rlib` in release are byte-identical. No feature of any other package changed (`cargo tree -e features`, 10 forms, both Mac targets).
- **deny.toml** (comments only), **.cargo/config.toml** (one comment) and **plan/architecture.md** (the `vendor/` line, the approved-crates intro, the row "Swift bindings").

Checks: the offline locked build of every target with an empty cargo home; 2,460 workspace tests (per binary in the proof); the TLS tests (`net`: 44 plus 1); larsal-ffi with `net` (297); the release timed tests (250); AT-B01 in release (171); fmt, the three clippy steps, the fuzz check and the nightly fuzz build of the 23 targets; build-core.sh and xcodebuild build-for-testing (TEST BUILD SUCCEEDED, only the local package); cargo deny and the three audit steps offline, with the same warnings as before; check-vendor and its 54 mutant runs (6 new for the path copies); the name guard.

Not done in step 4c: the 9 packages still compile for the uniffi_macros proc macro (a uniffi_meta copy would take them out; optional, step 5); the pedigree note for cut copies in the bill of materials (LD-254 (3)); batch 4d and step 5.

## 19. Step 4d done (2026-10-31)

Built by the E0-S7 step 4d Builder: batch 4d of the follow-up (LD-259 (1), LD-261 (1)), section 8 step 4 items 7, 8 and 9. Not crypto: no crypto copy changed. Checker next. Proof: [security/parity/E0-S7-step4d.md](../../security/parity/E0-S7-step4d.md).

What changed in the tree:

- **vendor/ureq** (ureq 3.5.0, MIT OR Apache-2.0, item 7 and R13): a `[patch.crates-io]` path copy without proxies (HTTP CONNECT, SOCKS, the Windows system proxy, the proxy environment variables), cookies, JSON, charset decoding and the lossy UTF-8 reader, gzip and brotli, the query and form helpers and ureq's own tests; changes 1 to 9 at the top of its `Cargo.toml`. 12 source files cut, 21 changed (3,477 lines out, 35 in). With the features Larsal had off, ureq already passed compressed replies through, decoded no charset and kept no cookies; Larsal's net.rs set `.proxy(None)`, which is gone with the proxy setting.
- **vendor/ureq-proto** (ureq-proto 0.6.5, item 7): a path copy that makes no Basic authorization header from a user name and password in the URI (Larsal's net.rs refuses such a URL, LD-64), its only use of base64; 4 source files changed (108 lines out, 6 in).
- **Request bytes**: the 23 request heads of the net tests, the breach check's among them, are byte-identical before and after, also with the proxy variables set.
- **flate2** (item 8, a cut copy since step 2): the C and zlib-rs backends (`src/ffi/c.rs`, `src/ffi/zlib_rs.rs`) and the 7 features and 2 optional dependency tables that named them are cut.
- **png** (item 8): a new cut copy whose manifest drops its own `miniz_oxide` 0.8 dependency; its code never called it (it works through fdeflate and flate2). So miniz_oxide 0.8.9 and the LD-115 skip in deny.toml are gone, with no re-export crate and no path copy.
- **quick-xml** (item 9): a new cut copy without its serde reader and writer (`src/de/`, `src/se/`, `serde_helpers.rs`) and its tokio reader and writer (17 files, 17,060 lines), built only under features Larsal never turns on; the manifest is the published one.
- **memchr** (item 9): a new cut copy without `src/arch/wasm32/` (5 files), built only for WebAssembly.
- **Skipped** (item 9): qrcode `render/` (rustc reads all five files through their `mod` lines: a code change and a path copy for about 16 KB); qrcode's other unused files (about 13 KB, against a 3 KB list; its `[[bin]]` and `[[example]]` paths are inferred, so they cannot be cut); quick-xml `encoding.rs` (always compiled); bytes `serde.rs` (2.6 KB, less than its 3.7 KB list; `loom.rs` is compiled); security-framework (in no lockfile since step 1; its pin waits for E6-S3 and E16-S6).
- **Packages**: base64 0.23.1, utf8-zero 0.8.1 and miniz_oxide 0.8.9 leave the tree; percent-encoding 2.3.2 leaves Larsal's build and stays in the tree only for askama in the bindings generator (step 5). Linked sets, both Mac targets: larsal-ffi with `net` 113 to 109, without 98 to 97, larsal-cli 90 to 89. No feature of any other package changed (`cargo tree -e features`, 10 forms).
- **Lockfiles**: `Cargo.lock` 199 entries to 196 (registry 183 to 178), `fuzz/Cargo.lock` 99 to 98 (registry 89 to 88): removals, the two path packages, and flate2's `miniz_oxide 0.9.1` written as `miniz_oxide` now that one version is left.
- **vendor/crates-io**: 186 copies to 181 (base64-0.23.1, utf8-zero-0.8.1, miniz_oxide-0.8.9, ureq-3.5.0, ureq-proto-0.6.5 removed). `cut_copies` in check-vendor.sh 70 to 73 (memchr, png, quick-xml); the audit list of path copies takes ureq and ureq-proto by itself (6 now). 9 new check-vendor mutants (D1 to D8 and D2a), one per new kind of cut: they fail, and the 54 earlier runs still behave as recorded.
- **Bill of materials**: 117 components to 113 (base64, miniz_oxide 0.8.9, percent-encoding and utf8-zero gone); ureq and ureq-proto carry `pedigree` in place of their crates.io checksum. 94 license texts to 92.
- **Size**: `vendor/` 6,756 files, 64,484,289 bytes, 1,847,168 lines (1,487,030 of Rust) before; 6,621 files, 62,635,967 bytes, 1,794,510 lines (1,441,089 of Rust) after. Removed: 135 files, 1,848,322 bytes, 52,658 lines (45,941 of Rust).
- **Same output**: the Swift bindings are byte-identical and the library exports the same 506 C functions; `liblarsal_hwkey.rlib` in release is byte-identical. `larsal` in release is not: png's crate hash changed, so the LTO code order moved (`__text` 64 bytes larger, the same file size and strings).
- **deny.toml** (the miniz_oxide skip and its comment), **.cargo/config.toml** (one comment), **crates/larsal-platform/src/net.rs** (`.proxy(None)` gone) and **plan/architecture.md** (the `vendor/` line, the approved-crates intro and the rows XML, Gzip, Base64, Icon images and HTTPS).

Checks: the offline locked build of every target with an empty cargo home; 2,463 workspace tests, the same per binary as before (per binary in the proof); the TLS tests (`net`: 44 plus 1); larsal-ffi with `net` (297); the release timed tests (250); AT-B01 in release (171); fmt, the three clippy steps, the fuzz check and the nightly fuzz build of the 23 targets; the fuzz smoke of icon_decode, document, vault_open and inner_header; build-core.sh and xcodebuild build-for-testing (TEST BUILD SUCCEEDED, only the local package); cargo deny and the three audit steps offline, with the same warnings as before; check-vendor and its 63 mutant runs; the name guard.

Not done in step 4d: the item 9 skips above; percent-encoding and askama (step 5); step 5.

## 20. Step 5 done (2026-10-31)

Built by the E0-S7 step 5 Builder: section 8 step 5 (LD-257 (3), LD-259 (1), LD-261 (4)). Not crypto: no crypto copy changed. New unsafe code in larsal-platform's test tools, so Checker 2 too (Rust rule 2). Checker 1, Checker 2 and Verify signed 2026-10-31; the probe's second unsafe review is open (LD-275 (1)). Proof: [security/parity/E0-S7-step5.md](../../security/parity/E0-S7-step5.md).

What changed in the tree:

- **Item 1, the bindings generator**: `crates/uniffi-bindgen` has its own small main over uniffi's `bindgen` feature: it reads the options `scripts/build-core.sh` passes and refuses anything else (two new tests). vendor/uniffi loses the `cli` feature with `src/cli/`, its two binaries and its `clap`, `camino` and `uniffi_pipeline` dependencies, and the `bindgen-tests` feature. clap, clap_builder, clap_derive, clap_lex, anstyle and strsim leave the tree.
- **Item 2, vendor/uniffi_bindgen** (uniffi_bindgen 0.32.2, MPL-2.0): a new `[patch.crates-io]` path copy with only the Swift generator (the Kotlin, Python and Ruby generators and templates and the test helpers cut: 140 files) and no UDL parser (a private `parse_udl` that fails with a clear message; larsal-ffi has no `.udl` file). 7 source files changed (45 lines out, 17 in); changes 1 to 3 at the top of its `Cargo.toml`. uniffi_udl, weedle2, nom and minimal-lexical leave the tree. `src/scaffolding/` stays (it brings no package).
- **Item 3, rcgen: skipped.** The net tests make their certificates each run, valid one year either side, because Apple's verifier refuses a server certificate valid for more than 825 days; fixed certificates would expire within about two years or need a clock seam in Larsal's TLS verifier. rcgen is test-only, and plan/architecture.md plans it for larsal-server, so it would come back.
- **Item 4, rustix**: `src/backend/linux_raw/` cut (94 files). Its build script picks the libc backend whenever the system is not Linux; the build-script output and the 159 compiled files are the same before and after.
- **Item 5, LD-257 (3)**: check.sh's unsafe gate runs `cargo clean --profile dev` when `Cargo.lock` is newer than `target/debug/.lock-clean`, then makes that file. Its mutant (the old gate after this step's lock change) fails on uniffi_udl's stale dep-info; the new gate cleans once and passes, then passes without a clean. The next check.sh run on the shared tree cleans once.
- **Item 6, LD-261 (4)**: `crates/larsal-cli/tests/stack_scrub.rs`, one test over larsal-platform's new probe `zero_stack_words_after` (feature `test-memory`): base64's `encode_secret` and `decode_secret` and the 27 cipher calls each leave about 2,048 zero words (the floor is 1,024); a control without the wipe leaves 0. Taking any of the two base64 calls or the seven `Encryptor` and `Decryptor` calls out of `scrubbed`, or the wipe out of `scrubbed`, fails it. Taking only the outer `scrubbed` of `encrypt` or `decrypt` passes: their work runs in the `Encryptor` and `Decryptor` calls, each still wiped, and no word of the key is left on the stack. larsal-platform's unsafe count 314 to 322.
- **Item 7, LD-261 (4)**: `deny.toml` bans `base64ct` except through larsal-crypto and the argon2, pem-rfc7468 and ssh-encoding copies that already use it. `cargo deny --offline check` passes with the same warnings; larsal-core naming base64ct fails it (`explicitly banned`).
- **Lockfiles**: `Cargo.lock` 196 entries to 186 (registry 178 to 167): removals only, uniffi_bindgen now a path package. `fuzz/Cargo.lock` unchanged.
- **vendor/crates-io**: 181 copies to 170 (the ten packages and uniffi_bindgen-0.32.2 removed, each first checked equal to its `.crate`). `cut_copies` unchanged (73); the audit list of path copies takes vendor/uniffi_bindgen by itself (7). 8 new check-vendor mutants (E1 to E7, E2b) fail; the earlier ones behave as recorded.
- **Packages in Larsal**: none changed. Linked sets, both Mac targets: larsal-ffi with `net` 109, without 97, larsal-cli 89, as before; the ten packages ran only in the bindings generator. No feature of any other package changed (`cargo tree`, 10 forms).
- **Bill of materials**: 113 components, as before. uniffi_bindgen carries `pedigree` in place of its crates.io checksum, and uniffi's note follows its new comment; no other component changed.
- **Size**: `vendor/` 6,621 files, 62,635,967 bytes, 1,794,510 lines (1,441,089 of Rust) before; 5,957 files, 58,617,600 bytes, 1,671,462 lines (1,339,493 of Rust) after. Removed: 664 files, 4,018,367 bytes, 123,048 lines (101,596 of Rust).
- **Same output**: the Swift bindings byte-identical, the same 506 exported C functions; `larsal` and `liblarsal_hwkey.rlib` in release byte-identical.
- **Root Cargo.toml** (the uniffi_bindgen patch line and comments), **.cargo/config.toml** (one comment), **deny.toml** (the ban, the uniffi_udl exception gone, comments) and **plan/architecture.md** (the `vendor/` line, the approved-crates intro and the rows 'Base64, Base32, hex', 'Swift bindings' and 'Command line').

Checks: the offline locked build of every target with an empty cargo home; 2,466 workspace tests (2,463 per binary as before, plus 2 for the generator's command line and the stack test; per binary in the proof); the TLS tests (`net`: 44 plus 1); larsal-ffi with `net` (297); the release timed tests (250); AT-B01 in release (171); fmt, the three clippy steps, the fuzz check and the nightly fuzz build; build-core.sh and xcodebuild build-for-testing (TEST BUILD SUCCEEDED); cargo deny and the three audit steps offline; check-vendor and its 71 mutant runs; the name guard.

Not done in step 5: item 3 (above); uniffi_bindgen's `src/scaffolding/`; the pedigree note for cut copies in the bill of materials (LD-254 (3)).


## E22-S2 / E23-S2 file-format copies (LD-379)

Record of 2026-11-05, on Main since commit ccdaf96. Ten exact registry archives were acquired under the owner's itemized approval and independently checked. Their complete 193 regular members and every license/notice are retained unchanged in vendor/crates-io; these are uncut copies, not patched crypto. Each .cargo-checksum.json lists every raw member and the original publisher archive SHA-256. No new stub, build script, proc macro, installed tool or online Cargo source is added. The seven direct dependencies and exact features are in architecture; dbl/tinyvec/macros stay transitive. Declared transitive defaults are not mislabelled graph-wide defaults-off. tinyvec and unicode-normalization each carry a .gitignore that hides their Cargo.lock; both files are force-added (LD-418).

| Package | Archive SHA-256 | Raw files | Notices retained |
|---|---|---:|---|
| scrypt 0.12.0 | `d87af57419b594aa23fa95f09f0e06d80d84ba01c26148c43844cad6ff4485f0` | 21 | `LICENSE-APACHE`, `LICENSE-MIT` |
| chacha20poly1305 0.11.0 | `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb` | 15 | `LICENSE-APACHE`, `LICENSE-MIT` |
| bech32 0.11.1 | `32637268377fc7b10a8c6d51de3e7fba1ce5dd371a96e342b34e6078db558e7f` | 31 | `LICENSE-MIT` |
| aes-siv 0.8.0 | `4f60ec3717e40f849d065676ef76a0fbd76ed6c300b18cc70a9a3bde80d7c8e8` | 16 | `LICENSE-APACHE`, `LICENSE-MIT` |
| aes-kw 0.3.1 | `41ac571010bd60765c56085a4f1d412012a9be2663b1a2f2b19b49318653fd0d` | 16 | `LICENSE-APACHE`, `LICENSE-MIT` |
| cmac 0.8.0 | `ac78aa94ce13e432b332a4d1bf2eff167d3a2520188ee05b337180a42fd2e62e` | 26 | `LICENSE-APACHE`, `LICENSE-MIT` |
| dbl 0.5.0 | `f0d7a944e61df464668c5f51f56cc667396a8821434273112948ea0b66e405d7` | 9 | `LICENSE-APACHE`, `LICENSE-MIT` |
| unicode-normalization 0.1.25 | `5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8` | 25 | `COPYRIGHT`, `LICENSE-APACHE`, `LICENSE-MIT` |
| tinyvec 1.10.0 | `bfa5fdc3bce6191a1dbc8c02d5c8bffcf557bafa17c124c5264a458f1b0613fa` | 26 | `LICENSE-APACHE.md`, `LICENSE-MIT.md`, `LICENSE-ZLIB.md` |
| tinyvec_macros 0.1.1 | `1f3ccbac311fea05f86f61904b462b55fb3df8837a366dfc601a0161d0532f20` | 8 | `LICENSE-APACHE.md`, `LICENSE-MIT.md`, `LICENSE-ZLIB.md` |

Existing license alternatives and copyrights keep their own terms. The approved metadata/source choice does not establish signed release authenticity, whole-process erasure, Unicode18 interoperability or file-format/runtime success. No age peer program is extracted or executed by this vendoring step. S2's checks passed and Verify V1, V3 and V4 signed on 2026-11-06, dependency scope only (LD-379, security/parity/E22-S2-E23-S2-crates.md).
