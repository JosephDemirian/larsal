# E0-S7 step 1: second review (2026-10-30)

Story E0-S7 step 1 (LD-221, LD-247). Crypto copies and `unsafe` code need two Checkers (plan/team.md). Checker 1's review is in the E0-S7 status line in plan/epics.md. This file holds the second review.

## Checker 2

Verdict: **passed**, with no findings. Two notes on doc comments, which do not block (see Notes).

Setup: a private copy of the tree (`rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots`), with its own target folder and an empty cargo home (`CARGO_HOME` was a new empty folder, `CARGO_NET_OFFLINE=true`, every cargo call `--offline --locked`). Before the review, `vendor/` and `crates/` in the copy were the same as in the shared tree (`diff -rq`). After each mutant, `cmp` against the shared tree showed the restored files were the same. No network, no keychain, no window, and the copy is deleted.

### (a) Crypto copies: byte-for-byte upstream

Scope: the 70 rows that section 7 of spec/research/dependencies.md marks C. 68 of them are plain copies in `vendor/crates-io/`. rustls-platform-verifier left the build (LD-247 (2)), and ssh-key is the patched path copy of LD-209.

Method, per package: (1) the `.crate` in the local cargo cache has a SHA-256 equal to its `Cargo.lock` checksum; (2) the `package` value in the copy's `.cargo-checksum.json` is the same checksum; (3) `diff -rq` of the unpacked `.crate` against the copy; (4) `diff -rq` of `~/.cargo/registry/src/<name>-<version>` against the copy; (5) each file in `.cargo-checksum.json` exists, has the listed SHA-256, and no file on disk is missing from the list.

Result for the 68 plain crypto copies: 2,185 archive files, 0 files differ, 0 extra files, checks (1), (2) and (5) pass for all 68. These are the only files removed, all whole files:

| Package | Removed file |
|---|---|
| ring 0.17.14 | `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (LD-247 (4)) |
| byteorder 1.5.0, cfg-if 1.0.5, ff 0.14.0, group 0.14.0, hybrid-array 0.4.15, num-traits 0.2.19, once_cell 1.21.4, rand_core 0.10.1, typenum 1.20.1, untrusted 0.9.0 | `.gitignore` (cargo vendor never copies it) |
| typenum 1.20.1, untrusted 0.9.0 | `.gitattributes` (cargo vendor never copies it) |

The 68 copies are aead 0.6.1, aes 0.9.3, aes-gcm 0.11.1, argon2 0.6.0, base16ct 1.0.0, base64ct 1.8.3, bcrypt-pbkdf 0.11.0, blake2 0.11.0, block-buffer 0.12.1, blowfish 0.10.0, byteorder 1.5.0, cbc 0.2.1, cfg-if 1.0.5, chacha20 0.10.2, cipher 0.5.2, cmov 0.5.4, const-oid 0.10.2, cpubits 0.1.1, cpufeatures 0.3.1, crypto-bigint 0.7.10, crypto-common 0.2.2, ctr 0.10.1, ctutils 0.4.6, curve25519-dalek 5.0.0, curve25519-dalek-derive 0.1.1, der 0.8.2, digest 0.11.3, ecdsa 0.17.0, ed25519 3.0.0, ed25519-dalek 3.0.0, elliptic-curve 0.14.2, ff 0.14.0, getrandom 0.2.17, ghash 0.6.0, group 0.14.0, hkdf 0.13.0, hmac 0.13.0, hybrid-array 0.4.15, inout 0.2.5, num-traits 0.2.19, once_cell 1.21.4, p256 0.14.0, pbkdf2 0.13.0, pem-rfc7468 1.0.0, poly1305 0.9.1, polyval 0.7.3, primefield 0.14.0, primeorder 0.14.0, rand_core 0.10.1, rfc6979 0.6.0, ring 0.17.14, rustls 0.23.46, rustls-pki-types 1.15.1, rustls-webpki 0.103.16, salsa20 0.11.0, sec1 0.8.1, sha1 0.11.0, sha2 0.11.1, signature 3.0.0, ssh-cipher 0.3.0, ssh-encoding 0.3.0, subtle 2.6.1, twofish 0.8.0, typenum 1.20.1, universal-hash 0.6.1, untrusted 0.9.0, wnaf 0.14.1, zeroize 1.9.1.

I also ran the same method on all 197 copies in `vendor/crates-io` that are not stubs (crypto and the others): 8,139 archive files, 0 differ. The only files missing are 65 `.gitignore`, 5 `.gitattributes` and ring's one cut file. Every `.crate` checksum and every `package` checksum equals `Cargo.lock`.

ssh-key (the path copy `vendor/ssh-key`), compared by `diff -r` with the registry `ssh-key-0.7.0-rc.11`: the only differences are the LD-209 changes. These are the manifest note, `publish = false`, and the removed tests, dev-dependencies and README entry; the lib.rs header and the removed README include (change 2); the length check in `private/ecdsa.rs` (change 1); and the wipe on drop in `private/opaque.rs` (change 3). Left out of the copy: `tests/`, README, CHANGELOG, `Cargo.toml.orig`, `Cargo.lock` and `.cargo_vcs_info.json`. Step 1 does not change it.

### (b) Unsafe review of crates/larsal-platform/src/macos/trust.rs

There are 14 `unsafe` blocks and 2 `unsafe extern` blocks, and each block has a `// SAFETY:` note. clippy (`-D warnings`, with `undocumented_unsafe_blocks` from macos/mod.rs) is clean with `--features net --all-targets`.

FFI declarations against the macOS 27.0 SDK headers: all 15 functions and the one static match. `Boolean` is `u8`. `OSStatus` is `i32`. `CFIndex` is `isize` (signed long). `CFStringEncoding` is `u32`, and `kCFStringEncodingUTF8` is 0x08000100. `SecTrustEvaluateWithError` returns C `bool`, which is Rust `bool`. `CFArrayCallBacks` has 5 fields in the same order, and Larsal only takes the address of `kCFTypeArrayCallBacks`. The 7 OSStatus codes in `refusal()` (net.rs) are the values in `SecBase.h`.

| Line | Call | Ownership and null | Result |
|---|---|---|---|
| 89 | `CFRelease` in `Drop for Cf` | `Cf` is made only from a Create or Copy result. It is a `NonNull`, so a null pointer never reaches CFRelease. It has no `Clone` or `Copy`, so it is released once. | OK |
| 130 | `CFDataCreate` | Create rule: +1, in `Cf`. Null gives `None`. The bytes are copied during the call, so their lifetime ends safely after it. | OK |
| 139 | `CFArrayCreate` with `kCFTypeArrayCallBacks` | Create rule: +1. The system callbacks retain each item, so the array stays valid after `items` is dropped. Each item keeps its own +1 until its `Cf` drops. With 0 items, nothing is read. | OK |
| 156 | `SecCertificateCreateWithData` | Create rule: +1. Null (not DER) gives `BadEncoding`. Certificates made before it are released when `certs` drops. | OK |
| 165 | `CFErrorCopyDescription` | Copy rule: +1, in `Cf`. Null gives empty text. | OK |
| 172 | `CFStringGetCString` | The buffer is 1,024 bytes and the size passed is 1,024. The buffer is read only when the call succeeds. | OK |
| 177 | `CStr::from_ptr` | On success, a NUL is inside the buffer. | OK |
| 198 | `CFStringCreateWithBytes` | Create rule: +1. The host is a `&str`, so it is UTF-8. `external` is 0, so the bytes are copied. | OK |
| 202 | `SecPolicyCreateSSL(1, name)` | Create rule: +1. `1` selects the server side. **The host name reaches the policy**: it is the rustls `ServerName` (`to_str()`, the trailing dot removed; an IP address arrives as text). | OK |
| 207 | `SecTrustCreateWithCertificates` | The out pointer is written once. A nonzero status returns `Err`. On success, the trust object is +1 in `Cf`, and a null object gives `Err`. | OK |
| 213 | `SecTrustSetAnchorCertificates` | Called only when anchors are given (tests only: `Client::with_anchors` is `#[cfg(test)]`, and `Client::new` passes none). The trust object retains the array. A nonzero status returns `Err`. | OK |
| 218 | `SecTrustSetOCSPResponse` | Called only when a stapled response was sent. It is retained. A nonzero status returns `Err`. | OK |
| 223 | `SecTrustEvaluateWithError` | **The result and the error are both read.** `true` is the only path to `Ok`. On `false`, the error (CF_RETURNS_RETAINED) goes into `Cf` and is released once. A null error still gives `Err`. | OK |
| 233 | `CFErrorGetCode` | It is called on a live error, and the code goes into `Refused::Os`. | OK |

**Nothing trusts on error:** in `evaluate_server`, each `?` and each `else` returns `Err`. `Ok(())` comes only after `SecTrustEvaluateWithError` returns `true`.

**Verifier in net.rs:** `verify_server_cert` returns `ServerCertVerified` only from `Ok(())`, and every `Refused` becomes `rustls::Error::InvalidCertificate`. `verify_tls12_signature` and `verify_tls13_signature` return the result of rustls's own `verify_tls12_signature` and `verify_tls13_signature`, with the provider's `signature_verification_algorithms`, and nothing else. `supported_verify_schemes` is the provider's list. The config allows TLS 1.3 and 1.2 only, with the ring provider. No path accepts a chain or a signature on error. macOS reads the clock itself (`now` is not passed). I agree with the Builder and Checker 1 on that.

Mutants that I ran in the private copy (`cargo test -p larsal-platform --features net --lib net::`). These are in addition to Checker 1's V1 to V7:

- M-A: `verify_server_cert` accepts when macOS refuses. sn03_bad_certificates_refused fails.
- M-C: `SecPolicyCreateSSL(0, ...)` (client side). 9 of the 12 net tests fail, among them sn03_good, sn03_bad, ld247_good_chain and ld247_handshake_signed_with_another_key_refused.
- M-D: a refusal with a null error object is trusted. All 12 net tests pass. This mutant changes the branch for a refusal without an error object, and macOS always gives an error object with a refusal, so no test can reach that branch. The code as shipped refuses there. No finding.

### Unsafe count (cargo geiger, offline)

`cargo geiger --offline --locked --manifest-path crates/larsal-platform/Cargo.toml --output-format Json --include-tests`, run with the default features and again with `--features net`: larsal-platform has 314 unsafe items (used 274: functions 3, expressions 263, impls 2, methods 6; unused 40), and `forbids_unsafe` is false. Rust rule 2 allows this for larsal-platform. The G1 `unsafe_count` step of scripts/check.sh, run on its own over every crate: larsal-autotype 0, larsal-core 0, larsal-crypto 0, larsal-format 0, larsal-model 0, larsal-cli 0, larsal-ffi 0, larsal-sshagent 0 and uniffi-bindgen 0, each with `forbids_unsafe` true; larsal-platform 314, larsal-hwkey 54; total 368 in 11 crates, exit 0. Crate roots: `#![forbid(unsafe_code)]` in larsal-autotype, larsal-cli, larsal-core, larsal-crypto, larsal-ffi, larsal-format, larsal-model, larsal-sshagent and uniffi-bindgen. `#![deny(unsafe_code)]` is only in larsal-platform and larsal-hwkey, and the only `allow(unsafe_code)` in larsal-platform is `macos/mod.rs`. vendor/zxcvbn still has `#![forbid(unsafe_code)]`.

### The open question: the net test count

`cargo test -p larsal-platform --features net -- --list` lists 51 tests in the library and 1 in `tests/net_start.rs`. I removed only `ld247_handshake_signed_with_another_key_refused` and its `WrongKey` helper to make the earlier version. That version lists 50 tests in the library and the same 1 in net_start, and every other name is the same. Runs: today the library gives 44 passed and 7 ignored, and net_start gives 1 passed. Without the new test, the library gives 43 passed and 7 ignored, and net_start gives 1 passed. The 7 ignored tests are the `*_child` helper processes. So the earlier "44" was 43 + 1 over two test binaries, and the fix report's "44" is the library binary alone (45 in all). **No test was lost.** This agrees with Checker 1's re-check.

### Other checks in the copy

`scripts/check-vendor.sh`: PASS. Cargo.toml has 238 packages, 225 from vendor/crates-io; fuzz has 125 packages, 115 from vendor/crates-io; 38 stubs, none built for a Mac. `cargo fmt --all -- --check`: clean. clippy-net (`-D warnings`): clean.

### Notes (not findings)

1. In net.rs, the doc comment of `Client::with_anchors` says "also trust `anchors`". `SecTrustSetAnchorCertificates` makes them the **only** trusted roots (SecTrust.h, and trust.rs line 212 says this). The code and tests are correct. Only the word "also" is wrong. Fix it the next time someone edits the file.
2. In trust.rs, the doc comment of `description()` says "at most 1,023 bytes". A longer text is not cut: `CFStringGetCString` fails, and the caller then uses "macOS refused it (error N)". This is safe. Only the comment is not exact.

## Verify (2026-10-30)

Verdict: **signed**. Every E0-S7 check that step 1 covers passed. A Verify agent ran them in a private copy. It did not build or check this step. One new Low finding is filed: F-134. It is a release-only timing test in larsal-crypto, and the same failure occurs when the code is built from the registry sources, so it does not come from the copies.

### Setup

- **Private copy.** `rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots` made `/tmp/e0s7-verify-copy` at 17:53. A second copy for mutants was `/tmp/e0s7-verify-mut`. Each copy had its own `CARGO_TARGET_DIR` under `/tmp/e0s7-verify-*`. Before the runs, `diff -rq` showed that `vendor/` and `crates/` were the same as in the shared tree. After the runs, every step 1 file in the copy was still the same as in the shared tree (`cmp`): `vendor/` (all of it), `.cargo/config.toml`, both `Cargo.toml` and `Cargo.lock` files, `deny.toml`, `scripts/check-vendor.sh`, `check.sh`, `make-sbom.sh`, `interop.sh`, `build-core.sh`, `repro-build.sh`, `check-names.sh`, and larsal-platform `net.rs`, `net/tests.rs`, `macos/trust.rs` and `Cargo.toml`.
- **Empty cargo home.** `CARGO_HOME` was a new empty folder. After the build and all the test runs, it held only `.package-cache`, `.package-cache-mutate`, `.global-cache` and `registry/CACHEDIR.TAG`. Cargo.lock and fuzz/Cargo.lock were byte-identical to the copies taken before the first run. `CARGO_NET_OFFLINE=true` and `--offline --locked` were on every cargo call.
- **No network.** The runs used `sandbox-exec` with `(allow default)`, `(deny network-outbound (remote ip))`, `(allow network-outbound (remote ip "localhost:*"))` and a deny on the resolver socket `/var/run/mDNSResponder`. I checked the profile without sending anything off the Mac. A socket bound to `lo0` that connects to 192.0.2.1:443 gets "Operation not permitted" inside the sandbox ("Network is unreachable" outside it). 127.0.0.1 is allowed. The resolver socket gets "Operation not permitted". HOME was a throwaway folder in /tmp. `SSH_AUTH_SOCK` was unset. The Swift runs had `TEST_RUNNER_HOME`, `TEST_RUNNER_LARSAL_TEST_INSTANCE_DIR` and `TEST_RUNNER_SSH_AUTH_SOCK` in /tmp. No window was shown, the pasteboard and keychain were not used, and nothing was fetched.

### 1. Build, offline and locked, with an empty cargo home

`cargo build --offline --locked --workspace --all-targets`, inside the sandbox: `Finished dev profile`, exit 0, in 1 m 37 s. Every package was compiled from `vendor/crates-io/` or the tree (`-v` shows `/tmp/e0s7-verify-copy/vendor/crates-io/<name>-<version>/src/lib.rs`). The log has no line with `registry/src`.

### 2. Every test, with no network and an empty cargo home

| Run | Result |
|---|---|
| `cargo test --offline --locked --workspace --no-fail-fast` (sandbox) | 101 test binaries: 2,435 passed, 2 failed, 62 ignored, in 3 m 44 s. Both failures come from the sandbox and pass when run alone (see below). |
| `fea06_29_offline_streams`, run alone without the sandbox | ok. It reads its own memory with `ps`, which is setuid, and `sandbox-exec` refuses setuid programs ("Operation not permitted" at fea06.rs:602). |
| `t53_t57_ssh_signs_in_through_apps_socket`, run alone without the sandbox | ok, and no sshd is left behind (`pgrep`). Inside a sandbox it fails even when the profile denies nothing (`(allow default)` only): macOS's `sshd-auth` calls `sandbox_init` itself. So the network rules are not the cause. |
| `-p larsal-platform --features net` (in check.sh, sandbox) | library 44 passed, 7 ignored (the `*_child` helpers); `net_start` 1 passed |
| Release tests: fea01, fea05, fea06, fea07, mod08, mod11 (`--no-fail-fast`, sandbox) | 249 passed and 1 failed (fea06_29, because of `ps`); fea06_29 alone without the sandbox: ok. So 250 in all. |
| `cargo test -p larsal-ffi --test app09` (sandbox; it starts Larsal.app hidden) | 18 passed. No Larsal process was left. |
| Swift: `xcodebuild … test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (without the sandbox: SwiftPM cannot start its own sandbox inside one) | 347 tests in 50 suites. 2 tests failed with 3 issues: "Parity editor-editor-advanced: Open hands a private copy…" and "F-086 MOD-05.13: an outside edit of an open attachment copy…". |
| The same 2 suites (ParityEditorFilesTests, DataSafetyTests), alone, with `test-without-building` | First try, at 18:19, while another agent's `larsal_ffi … edit::tests::f_065_clean_child` and `f_086 zz_verify_racer` were running (`ps`): more failures, all of them on opened attachment copies. When the Mac was quiet (no other `f_0…`, xctest or xcodebuild test process for 30 s): "Test run with 17 tests in 2 suites passed". The cause is F-133 (open): the clean clears the per-user temp folder `Larsal/open-attachments`, which every run on this Mac shares. Step 1 does not change that code. |

The net test count: `--list` of the built library binary gives 51 tests (44 run and 7 ignored), and `net_start` gives 1. All 51 `#[test]` functions in `crates/larsal-platform/src` are on the list, `ld247_handshake_signed_with_another_key_refused` among them. I agree with both Checkers: no test was lost. The earlier "44" was 43 in the library plus 1 in `net_start`.

### 3. A source outside the tree fails the check (scripts/check-vendor.sh)

I made each mutant in `/tmp/e0s7-verify-mut` and restored it before the next one. After each restore, `diff -rq` or `cmp` against the shared tree was clean.

| Mutant | Result |
|---|---|
| None | PASS, exit 0 (238 packages, 225 from vendor/crates-io; fuzz 125, 115; 38 stubs) |
| N1: a registry package that is not vendored (`cfg-if-1.0.5` moved out of vendor/crates-io) | exit 101: `no matching package named cfg-if found` |
| N2: a git source (`[patch.crates-io] subtle = { git = … }`) | exit 101: `can't checkout from '…': you are in the offline mode` (nothing was fetched) |
| N3: a path outside the tree (root `[patch]` zxcvbn pointing to a copy in /tmp) | FAIL, exit 1: `read from outside the tree: zxcvbn 3.1.1: path at /tmp/e0s7-verify-outside/zxcvbn/Cargo.toml`. Cargo.lock does not change, so only this check catches it. |
| N3b: the same for the fuzz workspace (ssh-key) | FAIL, exit 1, `fuzz/Cargo.toml: read from outside the tree: ssh-key 0.7.0-rc.11` |
| N3c: an outside path written with `..` (`vendor/../../e0s7-verify-outside/zxcvbn`) | FAIL, exit 1 (cargo normalizes the path, and the check compares it with the physical root) |
| N4: a link out of vendor/ (`subtle-2.6.1` replaced by a link to a copy in /tmp) | FAIL, exit 1: `symbolic links in the package folders: vendor/crates-io/subtle-2.6.1` |
| N5: a stub that is built (the checksum list of `subtle-2.6.1` emptied) | FAIL, exit 1: `stubs compiled: subtle-2.6.1`, for both Mac targets and both workspaces |
| N6: the cargo cache instead of vendor/ (the source replacement removed from .cargo/config.toml) | exit 101: `no matching package named regex-syntax found` |

### 4. The bill of materials

`scripts/make-sbom.sh` ran with an empty cargo home: `151 components, 116 license texts, 12 crates without a license file`. I ran it a second time on the same tree, but with the source replacement removed: there, cargo read every package from the local registry cache (`~/.cargo/registry`, offline) and not from `vendor/crates-io`. `sbom.cdx.json`, `THIRD-PARTY-NOTICES.md` and `rust-std-COPYRIGHT.html` were byte-identical in both runs. So the copies keep the same components, versions, licenses and checksums. For each component:

- 138 crates.io copies: each has a version and a license. The license is the `license` field of its `vendor/crates-io/<name>-<version>/Cargo.toml`. Its SHA-256 equals the Cargo.lock checksum and the SHA-256 of the published `.crate`.
- 2 patched copies (zxcvbn 3.1.1, ssh-key 0.7.0-rc.11): each has its license and a `pedigree` with the upstream purl.
- 10 of Larsal's own crates, and the Rust standard library (MIT OR Apache-2.0).
- None of the 38 stubs is listed. rustls-platform-verifier and itertools are not listed either.

### 5. Crypto copies against upstream (the diff proof)

- **Archive compare:** each copy in `vendor/crates-io/` was compared with its `.crate` in the local cargo cache. The `.crate` SHA-256, the Cargo.lock checksum and the `package` value of `.cargo-checksum.json` are equal for all 235. 197 are copies: 8,139 archive files, 0 differ, 0 extra, and every hash in `.cargo-checksum.json` is right. The 68 crypto rows of research section 7 that are copies have 2,185 files, and 0 differ. The other 2 C rows are not in vendor/crates-io: rustls-platform-verifier is replaced (LD-247 (2)), and ssh-key is the LD-209 path copy. Each of the 38 stubs holds only `Cargo.toml` (byte-identical to upstream's) and an empty `src/lib.rs`, and no crypto row is a stub.
- **`diff -rq` against `~/.cargo/registry/src/index.crates.io-*/<name>-<version>`, all 197:** 0 files differ. The only lines are cargo's own `.cargo-ok` and `.cargo-checksum.json` (197 each), 65 `.gitignore` and 5 `.gitattributes` (cargo vendor never copies them), and ring's one cut file `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (LD-247 (4)). Only whole files are missing.
- **ring for x86_64:** `cargo build --offline --locked --keep-going -p larsal-platform --features net --target x86_64-apple-darwin` ran ring's build script. It made `aesni-x86_64-macosx.o`, and its output does not name `aesni-x86_64.pl`. The vendored ring has no `.git`, so `build.rs` takes `pregenerated/`. The x86_64 standard library is not installed, so the library compiles then stop with E0463. That is not part of the vendoring.
- **zxcvbn change 6:** I compared it with the registry copy. The itertools calls are standard-library code, each marked `Larsal change (LD-136, LD-247) 6`. The two `join`s collect into a `Vec` and join it, and `unique()` keeps the first of each pair in order. Nothing else is new.

### 6. AT-B01 known answers on the copies

`cargo test --offline --locked --release --no-fail-fast -p larsal-crypto` ran with a new target folder. `-v` shows that sha2, aes, twofish, chacha20, salsa20, argon2, hmac and blake2 are compiled from `vendor/crates-io/<name>-<version>/src/lib.rs`. The result is 162 passed, 1 failed, 10 ignored:

- lib 47 (the RFC 9106 Argon2 vectors, the RFC 8032 and RFC 6979 signatures, the startup self-test)
- cipher 21 (SP 800-38A, RFC 8439, the Twofish tables)
- hash 6
- kdf 34
- mac 8 (RFC 4231, RFC 2202)
- random 7, secret 10, ssh_wipe 1
- stream 19 (RFC 8439, the Salsa20 eSTREAM vectors)
- doc-tests 2 and 7

The 1 failure is `damaged_speed_record_is_measured_again`. It is not a known answer: it is a speed test of the time question (F-134). The slow known-answer tests passed too: `--ignored` of hash, kdf and mac gave `streaming_one_gib_nist_long_message` ok, plus 3 kdf tests and 1 mac test, all ok. In the debug workspace run, every larsal-crypto test passed.

### 7. Name guard

- check.sh's `names` step in the copy: `names: PASS (11332 files scanned, 16 vault files name-only)`, and `names-self-test` PASS.
- `scripts/check-names.sh <copy>/vendor` alone: `names: PASS (8432 files scanned)`. That is every file in vendor/ (`find vendor -type f`: 8,432).
- Mutant: ring's upstream `aesni-x86_64.pl` put back into the mutant copy: `names: FAIL (1 hit)`, exit 1, on that one file. Then I removed it.
- The shared tree after my edits (this file, the F-113, F-114 and F-134 rows, the status line): `names: PASS (11622 files scanned, 16 vault files name-only)`, exit 0.

### 8. scripts/check.sh, once, in the private copy

`FUZZ_SECONDS=10` kept the run under 30 minutes. It ran in the sandbox, with a cargo home that held only copies of the local advisory databases (`advisory-db`, `advisory-dbs`). It started at 17:57:17 and took 12 m 06 s:

```
G1 static ......... FAIL (fmt)
G2 tests .......... FAIL (test test-release xcode-test)
deny .............. FAIL (deny deny-fuzz)
audit ............. FAIL (audit)
fuzz smoke ........ PASS (22 targets, 10s each)
Overall ........... FAIL (logs in target/check/)
```

None of these failures is a step 1 defect:

- **fmt:** one diff, in `crates/larsal-ffi/src/test_dir.rs:59`. That file belongs to E13-S6, and another agent was editing it when the copy was made. The shared file has changed since, and now `cargo fmt --all -- --check` and `fmt-fuzz` on the shared tree both exit 0. Every other G1 step passed:
  - fmt-fuzz, clippy, clippy-app09 and clippy-net
  - vendor (check-vendor PASS)
  - names-self-test and names
  - unsafe (larsal-platform 314, larsal-hwkey 54, the other 9 crates 0)
  - swift-format and swiftlint
- **test and test-release:** they stopped at `fea06_29_offline_streams` (setuid `ps` in the sandbox). Without `--no-fail-fast` the later binaries did not run. The full runs are in section 2.
- **xcode-test:** `Could not resolve package dependencies: sandbox-exec: sandbox_apply: Operation not permitted`. SwiftPM cannot start its own sandbox inside one. The run without the sandbox is in section 2. build-core passed; app09 did not start because of the `&&`, and it ran on its own (section 2).
- **deny, deny-fuzz and audit:** they failed only on the fetch: `Could not resolve host: github.com` and `couldn't fetch advisory database`. Nothing left the Mac. The steps with no fetch passed in the same run: `audit-fuzz` (125 crate dependencies) and `audit-copies` (ssh-key 0.7.0-rc.11 and zxcvbn 3.1.1). Offline, on the local databases (1,386 advisories), with the same tree:
  - `cargo audit -n`: exit 0 (245 crate dependencies, 1 allowed warning)
  - `cargo deny --offline --locked check`: `advisories ok, bans ok, licenses ok, sources ok`
  - deny-fuzz with `--offline`: `advisories ok, bans ok, licenses ok, sources ok`

### 9. F-113 and F-114 re-test

- **F-113.** `audit-copies` as shipped: the lock it writes lists ssh-key 0.7.0-rc.11 and zxcvbn 3.1.1, each with the crates.io source, and `cargo audit -n -f` on it exits 0. Mutant: a path copy `vendor/cb-test/Cargo.toml` of crypto-bigint 0.7.5 gives `RUSTSEC-2026-0387`, `error: 1 vulnerability found!`, exit 1. Then I removed the folder. So an advisory against a `[patch]` path copy now fails the gate.
- **F-114.** `audit-fuzz` (`cargo audit -n -f fuzz/Cargo.lock`) as shipped: exit 0 (125 crate dependencies). Mutant: fuzz/Cargo.lock names crypto-bigint 0.7.5, and the result is RUSTSEC-2026-0387, exit 1. `deny-fuzz` (deny.toml without its `larsal-platform/net` features line), offline: `advisories ok, bans ok, licenses ok, sources ok`, exit 0. Mutant: the libfuzzer-sys NCSA exception removed, and the result is `error[rejected]: failed to satisfy license requirements` at `vendor/crates-io/libfuzzer-sys-0.4.13/Cargo.toml`, exit 4.

### Clean-up

Every process I started was stopped. No Larsal and no sshd was left (`pgrep`). My `/tmp/e0s7-verify-*` folders are deleted.
