# E13-S2 attack group AT-J: supply chain and build

Story: E13-S2, attack campaign (plan/epics.md). Rows AT-J01 to AT-J06 of plan/attacks-and-checks.md, "Attack catalog", group AT-J. Severities per its "Findings" section.
Agent: Red team, group AT-J. Date: 2026-10-29, tree read and checks run 20:34 to 21:19.
Clean room: no reference source opened and REF_CLI not run (no row of this group needs them). Demo data only: `testdata/`, `crates/*/tests/data`, `fuzz/corpus`, and probe files under `/tmp/e13s2-AT-J`.
Edits: this file only. No product code changed, no scripts/check.sh, no fuzzing. Network: only the advisory database fetch of `cargo audit` and `cargo deny` (the accepted exception). Shared build dir `CARGO_TARGET_DIR=/tmp/e13s2-target` (one `cargo build --release -p larsal-cli`; its first try printed 2 compile errors while another agent was editing, and the re-run a minute later built cleanly).
Earlier proof (history only): the AT-J03 rows in spec/decisions.md (LD-109, LD-115, LD-138, LD-145, LD-157, LD-182, LD-188, LD-197, LD-198, LD-201, LD-209), [E13-S5-two-person-review.md](E13-S5-two-person-review.md).

Tools: cargo-audit 0.22.2, cargo-deny 0.20.2, toolchain 1.99.1 (rust-toolchain.toml). Advisory database: RustSec commit `ee1a49a` of 2026-10-29 15:05, 1,386 advisories, the same commit in both tools' copies.
Inputs (SHA-256, first 16 hex): `Cargo.lock` f670b8279205dafa, `Cargo.toml` 9153ed420b48c5cd, `deny.toml` 6960d17779152f95, `fuzz/Cargo.lock` fcfa92288a48b48c.

## Results

| Row | Result | One line |
|---|---|---|
| AT-J01 | passed | `cargo audit`: 0 vulnerabilities in 267 crates (1 allowed "unmaintained" warning). Fuzz lock: 0 in 127. The two vendored copies are never checked (F-J1). |
| AT-J02 | passed | `cargo deny check`: advisories, bans, licenses, sources ok, exit 0. Same with `--all-features`. No OpenSSL or native TLS. crates.io only. No duplicate crypto crate except the named getrandom skip. The fuzz workspace is outside the gate, and its licence check fails (F-J2). |
| AT-J03 | passed | All 44 direct third-party dependencies have a table line and a written AT-J03 review. All 22 build scripts and all transitive crates trace to a review. Reviewed versions match the lock. The vendored diffs hold only marked changes. The records still need signature fixes (F-J5). |
| AT-J04 | waits_for_story | E14-S4 has no proof file yet (`security/parity/E14-S4-reproducible-build.md` absent at 21:19). |
| AT-J05 | waits_for_story | Waits for D7 (E14-S3). Today's state is recorded below. |
| AT-J06 | passed | Name guard self-test PASS, scan PASS (3,127 files). The secret scan found no real key, token or password. Encoded content was unpacked and is clean too. Guard gaps: F-J3, F-J4. Hygiene: F-J6. |

## AT-J01 Known vulnerabilities

Method (row): `cargo audit`; passes when zero.

Commands:

```
cargo audit                                   # root workspace, Cargo.lock
cargo audit -f fuzz/Cargo.lock                # the fuzz workspace (its own lock)
git -C ~/.cargo/advisory-db log -1 --format='%H %cd'
```

Output excerpt:

```
Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
  Loaded 1386 security advisories
Scanning Cargo.lock for vulnerabilities (267 crate dependencies)
Crate:     basic-toml   Version: 0.1.10   Warning: unmaintained   ID: RUSTSEC-2026-0374
warning: 1 allowed warning found
audit exit 0
Scanning fuzz/Cargo.lock for vulnerabilities (127 crate dependencies)
fuzz audit exit 0
ee1a49a2769a24a596afc1c20cb33748d2769586 Thu Oct 29 15:05:38 2026 +0100
```

The one warning is "unmaintained", not a vulnerability. It is the RUSTSEC-2026-0374 ignore in deny.toml (LD-157 condition 3). Its condition still holds: `cargo tree -p larsal-ffi -e normal --target aarch64-apple-darwin -i basic-toml` says "did not match any packages", so the crate is build time only and only in the bindings generator. Re-run at 21:19: same result.

Coverage probe (red team): are the two patched copies in `vendor/` checked? `Cargo.lock` lists `zxcvbn` 3.1.1 and `ssh-key` 0.7.0-rc.11 with no `source` line, because they are path packages. Two stub lock files in `/tmp/e13s2-AT-J/pathprobe` name `crypto-bigint` 0.7.5, which RUSTSEC-2026-0387 (patched >= 0.7.6) covers:

```
reg  (source = crates.io): cargo audit --no-fetch -f reg/Cargo.lock  -> exit 1, RUSTSEC-2026-0387, "1 vulnerability found!"
path (no source line):     cargo audit --no-fetch -f path/Cargo.lock -> exit 0, nothing found
```

A tiny `/tmp` crate that depends on a path crate named `crypto-bigint` 0.7.5 gives the same from `cargo deny --offline check advisories`: "advisories ok", exit 0. The control in the same crate (registry `basic-toml` 0.1.10) gives `error[unmaintained] RUSTSEC-2026-0374`, exit 1, so the database was loaded. Neither tool matches a path package against the database. An advisory against ssh-key rc.11 or zxcvbn 3.1.1 would therefore pass AT-J01, AT-J02 and the check.sh gates without a sound. Filed as F-J1.

Result: **passed** (zero vulnerabilities), with F-J1.

## AT-J02 Policy

Method (row): `cargo deny check`. Passes when licences are on the allowlist, sources are crates.io only, there are no duplicate crypto crates and there is no OpenSSL.

Commands and output excerpt:

```
cargo deny check                     -> warning[duplicate] syn 2.0.119 / 3.0.9 (not crypto; multiple-versions = "warn")
                                        advisories ok, bans ok, licenses ok, sources ok; exit 0 (re-run 21:19: same)
cargo deny --offline --all-features check -> advisories ok, bans ok, licenses ok, sources ok; exit 0
cargo tree --workspace --all-features --target all -i openssl-sys   -> did not match any packages
cargo tree --workspace --all-features --target all -i native-tls    -> did not match any packages
grep '^source' Cargo.lock | sort | uniq -c -> 254 registry+https://github.com/rust-lang/crates.io-index
grep -c '^checksum' Cargo.lock             -> 254 (of 254 registry packages)
cargo metadata --locked --offline (root and fuzz) -> exit 0 (both locks current)
```

- Licences: the allowlist is exactly E0-S4's 7 (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0). The only exceptions are the 8 named MPL-2.0 exact-version exceptions for the UniFFI 0.32.2 family (LD-157), which follow architecture.md's rule for named exceptions.
- Sources: 254 crates.io packages, each with a checksum. The 13 path packages are our 11 crates plus the 2 approved patched copies (`vendor/zxcvbn` LD-136, `vendor/ssh-key` LD-209), through `[patch.crates-io]` in both workspaces. There is no git source.
- Duplicate crypto crates: the macOS build graph (`cargo tree -d`, net on, all edges) has only one crypto duplicate, `getrandom` 0.2.17 next to 0.4.3. That is the named deny.toml skip (E6-S7, LD-194; ring for TLS handshake randomness only). The other duplicates are `bit-set`, `bit-vec`, `miniz_oxide` (named skip, LD-115) and `syn`.
- OpenSSL: none. `openssl-probe` is in Cargo.lock only (rustls-native-certs on non-Apple Unix) and is not built for macOS.
- With `--all-features` the macOS crate set is the same as with `larsal-platform/net`: `comm` of the two `cargo tree` name lists is empty, so no feature-gated crate escapes the graph deny.toml checks.

Coverage probe (red team): the fuzz workspace (`fuzz/Cargo.toml`, own `fuzz/Cargo.lock`) is outside both gates. scripts/check.sh runs `cargo audit` and `cargo deny check` on the root only. The root config cannot be used for it, because `cargo deny --manifest-path fuzz/Cargo.toml check` stops with "the package 'larsal-fuzz' does not contain this feature: larsal-platform/net". With a `/tmp` copy of deny.toml minus that one line:

```
cargo deny --manifest-path fuzz/Cargo.toml --config /tmp/e13s2-AT-J/deny-fuzz.toml check
error[rejected]: failed to satisfy license requirements
  libfuzzer-sys-0.4.13/Cargo.toml: license = "(MIT OR Apache-2.0) AND NCSA"   rejected: license is not explicitly allowed
advisories ok, bans ok, licenses FAILED, sources ok   (exit 4)
```

Compared with the root lock, the fuzz lock adds only `larsal-fuzz`, `arbitrary` 1.5.0, `libfuzzer-sys` 0.4.13 and `jobserver` 0.1.35. Every other entry is the same name and version. Fuzz binaries are never shipped. Filed as F-J2 (Low).

Result: **passed**, with F-J2.

## AT-J03 New dependency review

Method (row): maintainers, `unsafe` count, build scripts, download count, last release. Passes when the lead and a Checker approve in writing. As briefed: every dependency added since E0 has its written approval in spec/decisions.md or plan/architecture.md.

Commands (summarised):

```
cargo metadata --no-deps | jq '…dependencies[] | select(.path == null)'     # direct third-party deps of every crate
cargo tree --workspace --target aarch64-apple-darwin -e normal,build,dev --features larsal-platform/net --prefix none
                                                                             # the crates built on macOS
grep -F <crate> plan/architecture.md spec/decisions.md                      # each name against the approvals
cargo tree … -i <crate> --depth 1                                            # who brings each unnamed crate
cargo metadata … | jq 'targets[].kind | index("custom-build")'              # build scripts
diff -r ~/.cargo/registry/src/…/<crate> vendor/<crate>                      # the patched copies
shasum -a 256 ~/.cargo/registry/cache/…/<crate>.crate vs the index "cksum"
grep -rl '<crate>::' crates                                                  # who imports the reviewed crates
cargo tree -e features -i <crate>                                            # features of the reviewed crates
```

Findings of the check:

- **Direct dependencies:** 44 third-party crates, all pinned exactly (`=`). Every one has a line in architecture.md's approved table. Those added after E0 each have an AT-J03 row: png, ico (LD-109, LD-115); regex-automata, regex-syntax (LD-115); zxcvbn (LD-136, LD-138); pbkdf2, hkdf (LD-145, Checker 1 and lead); uniffi, libc (LD-157); ssh-key, bcrypt-pbkdf (LD-182, LD-209); objc2-io-kit, objc2-core-foundation (LD-188); ureq, rustls, rustls-platform-verifier, rcgen (LD-197); qrcode (LD-198); p256, ed25519-dalek (LD-201). The rest were in the E0 table and are pinned in `[workspace.dependencies]` (the RustCrypto set, quick-xml, flate2, base64, thiserror, serde, serde_json, clap, objc2, objc2-foundation, objc2-app-kit, proptest). There is no outside Swift package: `macos/Larsal.xcodeproj` has only `XCLocalSwiftPackageReference "LarsalCore"` and no Package.resolved. The fuzz workspace adds only libfuzzer-sys and arbitrary (table: "Tests, fuzzing").
- **Transitive crates:** 209 crate names are built on macOS. 46 of them are not named in either file. Each traces to an approved parent and is covered by that parent's review, either by count ("23 through larsal-ffi and 28 more", LD-157) or as part of an E0 crate: clap_builder, clap_lex, anstyle and strsim (clap); serde_core, serde_derive and zmij (serde, serde_json); typenum, hybrid-array, crypto-common, block-buffer, inout, cpufeatures, cmov, cpubits, base64ct and const-oid (RustCrypto, der); cargo_metadata, semver, toml_*, winnow, askama_parser, textwrap, smawk, siphasher, indexmap, hashbrown, rustc-hash, minimal-lexical and uniffi_udl (UniFFI generator, LD-157); tempfile, rustix, errno, rusty-fork, wait-timeout, quick-error, fnv, rand_xorshift, unarray and core_detect (proptest, tests only); objc2-encode (objc2); adler2 (miniz_oxide). Crates that are in Cargo.lock but not built for macOS (x509-parser, asn1-rs, borsh, jni, the windows-* crates and others) are optional or other-platform. They are still scanned by `cargo audit`.
- **Build scripts:** 22 third-party crates in the graph have one. Each is either named with its build script in a review (anyhow, camino, fs-err, libc: LD-157; curve25519-dalek: LD-201; num-traits: LD-201; ring, rustls, httparse: LD-197; crc32fast: LD-109) or belongs to an E0 crate (getrandom, objc2, proc-macro2, quote, serde, serde_core, serde_json, thiserror, zmij, rustix). Proc macros: every one is build time only and covered (LD-157 lists uniffi_macros, uniffi_internal_macros, askama_macros, clap_derive and scroll_derive).
- **Versions:** comparing every "crate x.y.z" in the AT-J03 rows with Cargo.lock gives only explained differences: LD-151 (superseded), and LD-201's recorded bump of crypto-bigint 0.7.7 to 0.7.10 and ctutils 0.4.5 to 0.4.6. No crate has moved past its reviewed version unseen.
- **Patched copies (rule-11 safe, read only):** the registry `.crate` files match the crates.io index checksums: `zxcvbn-3.1.1.crate` f9eaee90…7365e0, `ssh-key-0.7.0-rc.11.crate` f9a32fae…c15ce3. `vendor/ssh-key` src diff: 2 hunks, both marked `Larsal change (LD-209)` (the short-scalar fix and the README doc line). The Cargo.toml diff only drops tests, dev-dependencies and the README and adds `publish = false`. `vendor/zxcvbn` src diff: 39 hunks with 61 added lines marked `Larsal change`. The added lines bring no `unsafe`, `std::process`, `std::net`, `std::fs`, `env` or `extern "C"`. The 3 upstream wasm `unsafe` blocks are removed, and `#![forbid(unsafe_code)]` is added.
- **Conditions of the signed reviews, spot-checked today:** ureq has no features (LD-197 (1)). rustls has only `ring`, `std` and `tls12`. The platform verifier has only `default` (empty, so no `ffi-testing`, `dbg` or `cert-logging`). ureq, rustls and the verifier are imported only in `larsal-platform/src/net.rs` and its tests; ring appears only as `rustls::crypto::ring::default_provider()`, and rcgen only in `net/tests.rs` (LD-197 (2)). uniffi has no features in larsal-ffi (LD-157 (2)). qrcode has no features and is imported only in `larsal-ffi/src/edit.rs` (LD-198). p256, ed25519-dalek and ssh-key are imported only in `larsal-crypto/src/ssh.rs` (LD-201, LD-182). pbkdf2 and hkdf only in `larsal-crypto/src/kdf.rs` (LD-145). objc2-io-kit and objc2-core-foundation only in `larsal-hwkey/src/usb/` (LD-188). libc only in `larsal-platform/src/macos/` (LD-157). zxcvbn only in `larsal-core/src/health.rs` and its test (LD-133).
- **Unsafe spot-check** (`grep -w unsafe` in registry `src`): uniffi_core 130, httparse 78, ring 230 and qrcode 0, the same as LD-157, LD-197 and LD-198. ureq's 1 hit is a doc comment, and the crate has `#![forbid(unsafe_code)]`.
- **Download counts and last release:** not fetched again (no network beyond the advisory database). They are cited from the reviews.
- **Signatures:** a Checker signed every review. Lead co-sign is written in LD-145, LD-182, LD-188, LD-197, LD-198, LD-201 and LD-209. LD-157 still says "lead co-sign pending", although plan/epics.md E5-S1 says "UniFFI and libc AT-J03 co-signed (LD-157)". LD-115 and LD-138 carry only "Signed by the Checker". The lead's approval there rests on the LD row itself (epics.md E4-S11: "Rulings … LD-138 (crate review signed)"). architecture.md's qrcode and HTTPS cells still say "lead co-sign open" (stale, already routed to E13-S6 by LD-220). Filed as F-J5 (Low).

Result: **passed**. Every dependency has a written Checker approval and a lead approval, explicit or by the lead's own LD row. The records still need F-J5.

## AT-J04 Reproducible build

Method (row): two clean builds; the same binary hash, or every difference explained. This is E14-S4, which another agent is building now.

Command: `ls security/parity/ | grep -i E14`, run at 20:34 and again at 21:19: no output. `security/parity/E14-S4-reproducible-build.md` does not exist.

Result: **waits_for_story** (E14-S4).

## AT-J05 Signing

Method (row): Gatekeeper check of the release (`codesign -d --entitlements -`, `codesign -dv`, `spctl -a -vv`, `stapler validate`). This waits for D7 (Developer ID, E14-S3). All of these are read-only checks on the existing builds; no app was launched.

Output excerpt (today's state, for history):

```
target/xcode/Build/Products/Release/Larsal.app  (binary of 2026-10-27 19:26)
  Identifier=app.larsal.desktop  flags=0x10002(adhoc,runtime)  Signature=adhoc  TeamIdentifier=not set
  codesign -d --entitlements -  -> no entitlements (so no get-task-allow)
  spctl -a -vv   -> rejected
  stapler validate -> does not have a ticket stapled to it
target/xcode/Build/Products/Debug/Larsal.app
  Identifier=app.larsal.desktop.debug  flags=0x10002(adhoc,runtime)  get-task-allow = true (debug only, expected)
```

The hardened runtime flag is already on in both builds, and the Release build has no `get-task-allow`. A Developer ID signature, notarization and stapling wait for D7.

Result: **waits_for_story** (D7, E14-S3).

## AT-J06 Names and secrets

Method (row): the name guard, plus a secret scan of the whole folder; passes when both are clean.

### Name guard

```
scripts/check-names.sh --self-test   -> self-test: PASS (exit 0)
scripts/check-names.sh               -> names: PASS (3127 files scanned, 15 vault files name-only)  exit 0, 31.8 s
```

Red team additions:

1. **Encoded content the guard reads raw.** `/tmp/e13s2-AT-J/tools/unpack.py` decoded every base64 run of 40 or more characters in the text files (1,518 runs, data URIs included) and brotli-unpacked the table data of all 14 WOFF2 fonts into `/tmp/e13s2-AT-J/unpacked`. Then `scripts/check-names.sh /tmp/e13s2-AT-J/unpacked` gave `names: PASS (1534 files scanned)`. Today's tree is clean there too.
2. **Probes of the guard** (in `/tmp/e13s2-AT-J/guardprobe`, one file per root, each banned word written only at run time from the guard's own hex list). The control (plain text) gives FAIL (1 hit), and a percent-encoded URL gives FAIL (1 hit). Three probes PASS silently: a base64 `data:` URI in an `.html` file, a 2.4 KB brotli stream (as inside WOFF2) and a 2.4 KB zstd stream. None of these three is in the guard's "Known limits" list. The header says "Anything it cannot read or unpack fails the guard". Filed as F-J3 (Low). A word split across two string literals also passes; that is deliberate splitting, not a slip, and needs no fix.
3. **Inside the demo vaults.** By design the guard does not read past the vault signature. Our release `larsal export` (`HOME=/tmp/e13s2-AT-J/home`, passwords from testdata/README.md) of all 15 `testdata/*.larsalvault` into `/tmp/e13s2-AT-J/decrypted` gave exit 0 for all. A masked count (`/tmp/e13s2-AT-J/tools/inner_names.py`; words never printed) found these banned words outside the document's root element. In the 12 vaults REF_CLI made, the `Generator` field holds the reference app's name. All 15 hold custom-data key names that contain a banned word, as the format needs (a random-slug key; the browser-connection keys in option-a-personal, 10 times). The option-a vaults' Generator is Larsal's own. testdata/README.md already removes the creator field from the JSON exports. After publication anyone can read these names with the documented demo passwords. Filed as F-J4 (Low).

### Secret scan

No secret scanner is installed, and installing one needs the network. So `/tmp/e13s2-AT-J/tools/secrets.py` ran a fixed set of rules over every file, skipping only `target/`, `fuzz/target/` and `.git/` as the guard does. It has 23 content rules: PEM, OpenSSH and PGP private keys; PuTTY keys; AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, npm, PyPI, SendGrid and Twilio tokens; JWTs; Apple app-specific passwords; credentials in URLs; assigned password, secret and token values; notarization or team settings; and private keys in JSON. It also checks file names (`.env`, `.netrc`, `id_*`, `*.p12`, `*.pfx`, `*.pem`, `*.key`, `*.keychain`, `*.mobileprovision` and other key-store names). The run took 3 min 7 s and gave 211 hits:

| Rule | Hits | Verdict |
|---|---|---|
| Cloud and API tokens, JWT, app-specific password, notarization or team, secret-named files | 0 | clean |
| PEM or OpenSSH private-key header | 41 | 19 headers are parser constants or doc text. 22 have a key body, and all are demo keys. The OpenSSH bodies decode to comments `demo@app`, `demo2@app`, `short@app`, `dsa@app`, `ecdsa@app`, `p384@app`, `p521@app` and `rsa@app`, or are the same demo key encrypted (the fuzz seeds k13des, k1big, k1chacha, k1e and k1gcm). seed-kp is an encrypted PEM demo key. seed-k8 is the P-256 PKCS#8 key that `larsal-sshagent/tests/common/mod.rs:202` makes with `ssh-keygen -m PKCS8`. The sk-* keys are test assets from the crate's helpers (INT-06 T17). `larsal-core/tests/fea08.rs` holds a 36-character fake made of repeated 0x11 bytes. The cards say these keys were made by `ssh-keygen` for INT-06. |
| PuTTY key | 2 | the fuzz seed and the test in larsal-sshagent: demo |
| Credentials in URL | 5 | `example`, `localhost` and `127.0.0.1` test and spec values |
| Assigned password or secret | 163 | 71 distinct values, all demo: `demo-pass-N`, the Option A mockup's fake entries (also in option_a.rs, which builds the demo vault), zxcvbn's test vectors, the standard TOTP demo secret, generator and Unicode test strings |

The owner's email does not appear. The owner's home path appears once (`security/parity/E5-S11-menus-voiceover.md:228`), and there are 3 `.DS_Store` files (`./`, `design/`, `security/`). Neither is a secret. Both are publication hygiene, filed as F-J6 (Low).

Limits: PNG and JPEG screenshots (645 PNG files) were not read for text by OCR. They come from demo vaults (rule 5), and the guard reads their chunks. High-entropy strings (hex test vectors) were not judged one by one: the rules above target real key and token formats.

Result: **passed**, with F-J3, F-J4 and F-J6.

## Findings

Severity per plan/attacks-and-checks.md "Findings". For the filer: none is Critical or High.

| ID | Severity | Area | Steps to reproduce (demo data) | Smallest fix |
|---|---|---|---|---|
| F-J1 | Medium | Supply chain: advisory scan of `vendor/` (AT-J01, AT-J02; scripts/check.sh `audit`, `deny`) | `Cargo.lock` lists `ssh-key` 0.7.0-rc.11 and `zxcvbn` 3.1.1 with no `source`, because they are path packages through `[patch.crates-io]`. In `/tmp`, write a lock with one `[[package]]` named `crypto-bigint` version `0.7.5` and the crates.io `source`. `cargo audit --no-fetch -f` it: RUSTSEC-2026-0387, exit 1. Remove the `source` line: exit 0, nothing found. The same with cargo deny: a path crate `crypto-bigint` 0.7.5 gives "advisories ok". So an advisory against the ssh-key release Larsal's SSH key parsing and decryption is built on, or against zxcvbn, never fails a gate (LD-197 (4) and LD-182 rely on these gates). | In scripts/check.sh `audit()`, also audit a stub lock made from `vendor/*/Cargo.toml`: write `version = 4`, then for each copy write `[[package]]`, its `name` and `version`, and `source = "registry+https://github.com/rust-lang/crates.io-index"`. Then run `cargo audit -n -f <stub>`. Ten lines, no new tool. |
| F-J2 | Low | Supply chain: the fuzz workspace (`fuzz/Cargo.lock`, 127 crates) | `cargo deny --manifest-path fuzz/Cargo.toml check` fails at once: "'larsal-fuzz' does not contain this feature: larsal-platform/net" (from the root deny.toml). With that line removed (a `/tmp` copy, passed as `--config`): `licenses FAILED`, because libfuzzer-sys 0.4.13 is "(MIT OR Apache-2.0) AND NCSA" and NCSA is not allowed. scripts/check.sh audits and denies the root workspace only. (`cargo audit -f fuzz/Cargo.lock` is clean today.) | Add `run audit-fuzz cargo audit -n -f fuzz/Cargo.lock` to `audit()`. Add `fuzz/deny.toml` (the root file without the `features` line, plus `{ crate = "libfuzzer-sys@0.4.13", allow = ["NCSA"] }`, reason: fuzz tool, never shipped). Run `cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check` in `deny()`. |
| F-J3 | Low | Name guard (scripts/check-names.sh, AT-J06, E0-S3) | Make a `/tmp` root with an empty AGENTS.md. Add a banned word (taken at run time from `WORDS_HEX`) in three forms: a base64 `data:text/plain;base64,…` URI in an `.html` file, a 2.4 KB brotli stream, or a 2.4 KB zstd stream. `scripts/check-names.sh <root>` gives PASS, exit 0, for each. The same word in plain text gives FAIL. None of the three is in the script's "Known limits", and the 14 WOFF2 fonts in `design/option-a/vendor` are brotli inside. Today's tree is clean: all 1,518 base64 runs and the 14 fonts, unpacked in /tmp, give PASS. | In check-names.sh, match the decoded bytes of `data:…;base64,` payloads and of base64 runs of 40 or more characters. Unpack WOFF2 ('wOF2') table data with the system's brotli, or fail closed on 'wOF2' and zstd (28 B5 2F FD) magic. Add a self-test case for each. Or name them under Known limits. |
| F-J4 | Low | Names inside encrypted demo data (testdata/, fuzz/corpus/vault_open; rule 1 and rule 5) | `printf 'demo-pass-1\n' \| larsal export -q testdata/password-only.larsalvault` (HOME under /tmp). The XML's `Generator` is the reference app's name. The same is true for all 12 vaults REF_CLI made. All 15 demo vaults also hold custom-data key names that contain banned words, which the format needs. The guard never sees this, because it does not read past the vault signature, by design. The demo passwords are published in testdata/README.md. | Before E14-S6, the lead records in spec/decisions.md that encrypted demo vaults may hold these names (they come from rule 5 and format compatibility) and adds one line to testdata/README.md. Otherwise, make-testdata.sh re-saves the REF_CLI vaults with Larsal's own generator name. |
| F-J5 | Low | AT-J03 records (spec/decisions.md, plan/architecture.md) | `grep -n "lead co-sign pending" spec/decisions.md` gives LD-157 (uniffi 0.32.2 family, libc), although plan/epics.md E5-S1 says it was co-signed. LD-115 and LD-138 say only "Signed by the Checker". architecture.md's qrcode and HTTPS rows say "lead co-sign open" while LD-197 and LD-198 say co-signed. G10 reads these records for "Lead and a Checker approve in writing". | The lead writes "Co-signed by the lead <date>" into LD-115, LD-138 and LD-157 (replacing "pending"). E13-S6 removes the two stale cells (LD-220 already routes them). |
| F-J6 | Low | Publication hygiene (AT-J06, E14-S6) | `find . -name .DS_Store -not -path './target/*'` gives 3 files. `grep -rn '/Users/[a-z]' security/parity` gives the owner's home path once, at E5-S11-menus-voiceover.md:228. | Delete the 3 `.DS_Store` files and ignore them in the repository's ignore file when git starts. Write `$HOME/.local/share/swiftlint/…` in that line. |

## Clean-up

The `/tmp/e13s2-AT-J` folders (probes, decrypted exports, unpacked blobs, logs, tools) are deleted at the end of this run. The shared `/tmp/e13s2-target` stays for the other red team agents.
