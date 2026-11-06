# E22-S2, E23-S2: the crates for file and folder encryption

Stories: E22-S2 (three crates), E23-S2 (seven crates).
Decisions: LD-379, LD-409, LD-414, LD-415, LD-418.
Date: 2026-11-06.
Result: verified, dependency scope only. Verify V1 (gates), V3 (these two stories) and V4 (adoption) each signed with limits.

## What was proven, and what was not

The ten crates are vendored byte for byte, pinned, reviewed under AT-J03, and allowed only in larsal-crypto. All four story checks hold: AT-J03, `cargo deny check`, gate G1 offline, check-vendor. They landed on Main in commit ccdaf96, in tree 1d5bfa9a33dc5a9bb76871ba2165b618c4cbcd67 at 0321146.

Nothing here calls these crates yet. This proof says the dependencies are the approved bytes and pass the gates. It says nothing about file or folder encryption working. E22-S3 and E23-S3 add the callers and carry their own proof.

Evidence under `/private/tmp` does not last, so this file copies what must survive. Verify reports and seals are kept outside the project in `~/Documents/Code/larsal-checkpoints/resume-2026-11-06/verify-first-merge/`.

## The crates and AT-J03

AT-J03 asks for five fields, and for the Lead and a Checker to approve in writing. The fields below are the independent Checker's reads on 2026-11-05. Download counts are observations, not a security score. Maintainers are the publisher owner accounts seen on crates.io.

| Crate | Version | Story | Last release | Downloads of this version | Maintainers | `unsafe` blocks/functions | Build script, links, proc macro | AT-J03 |
|---|---|---|---|---:|---|---:|---|---|
| scrypt | 0.12.0 | E22-S2 | 2026-04-22 | 6,943,257 | newpavlov, github:rustcrypto:kdfs | 10/0 | none | approved |
| chacha20poly1305 | 0.11.0 | E22-S2 | 2026-06-28 | 7,136,596 | newpavlov, github:rustcrypto:aeads | 0/0 | none | approved |
| bech32 | 0.11.1 | E22-S2 | 2025-12-02 | 16,686,909 | apoelstra, clarkmoody, TheBlueMatt | 0/0 | none | approved |
| aes-siv | 0.8.0 | E23-S2 | 2026-08-11 | 60,046 | tarcieri, github:rustcrypto:aeads | 0/0 | none | approved |
| aes-kw | 0.3.1 | E23-S2 | 2026-05-27 | 1,332,940 | tarcieri, newpavlov, github:rustcrypto:key-wraps | 0/0 | none | approved |
| cmac | 0.8.0 | E23-S2 | 2026-04-10 | 338,043 | newpavlov, github:rustcrypto:macs | 0/0 | none | approved |
| dbl | 0.5.0 | E23-S2 | 2025-09-03 | 631,575 | newpavlov, github:rustcrypto:utils | 0/0 | none | approved |
| unicode-normalization | 0.1.25 | E23-S2 | 2025-10-30 | 217,707,371 | huonw, SimonSapin, Manishearth, kwantam, sujayakar | 4/1 | none | approved |
| tinyvec | 1.10.0 | E23-S2 | 2025-08-18 | 138,879,011 | Lokathor, github:rust-bus:maintainers | 0/0 | none | approved |
| tinyvec_macros | 0.1.1 | E23-S2 | 2023-02-02 | 654,612,552 | Soveu | 0/0 | none | approved |

- V3 counted again on the vendored bytes: scrypt 10 (x86 and wasm paths only; on Mac arm64 it uses the soft route), unicode-normalization 5 (`normalize.rs:90,145,153,201,208`), others 0. These are source counts, not a safety, compiler or constant-time result.
- Nine manifests say `build = false`. tinyvec_macros has no build override and no build.rs. No new manifest declares build-dependencies, links or a proc macro. V3 found no net, process, file system or environment use in non-test source, by reading; that is not a runtime proof.
- Seven are direct dependencies of larsal-crypto, defaults off: scrypt, chacha20poly1305/zeroize, bech32, aes-siv/zeroize, aes-kw/zeroize, cmac/zeroize, unicode-normalization. dbl, tinyvec/alloc and tinyvec_macros are transitive.
- Newer releases existed on 2026-11-05 for bech32 (0.12.0), unicode-normalization (0.1.26) and tinyvec (1.13.3). The approved pins stay; nothing was upgraded silently.

## The bytes

Archive SHA-256 for each crate is in [spec/research/dependencies.md](../../spec/research/dependencies.md). V3's own script (`/private/tmp/larsal-verify-v3-LgIJVE3q/proof/q2_archives.py`, no failures): archive = publisher = Cargo.lock = `.cargo-checksum.json` package hash, for all ten. All 193 archive members are byte-equal to the vendored files. The only added file per crate is `.cargo-checksum.json`.

| Crate | Archive bytes | Archive members | Files in tree | Licenses kept |
|---|---:|---:|---:|---|
| scrypt 0.12.0 | 24,752 | 21 | 22 | MIT or Apache-2.0 |
| chacha20poly1305 0.11.0 | 71,012 | 15 | 16 | Apache-2.0 or MIT |
| bech32 0.11.1 | 66,591 | 31 | 32 | MIT |
| aes-siv 0.8.0 | 29,596 | 16 | 17 | Apache-2.0 or MIT |
| aes-kw 0.3.1 | 16,747 | 16 | 17 | MIT or Apache-2.0 |
| cmac 0.8.0 | 1,096,597 | 26 | 27 | MIT or Apache-2.0 |
| dbl 0.5.0 | 7,613 | 9 | 10 | MIT or Apache-2.0 |
| unicode-normalization 0.1.25 | 128,462 | 25 | 26 | MIT or Apache-2.0, plus COPYRIGHT |
| tinyvec 1.10.0 | 51,996 | 26 | 27 | Zlib, Apache-2.0 or MIT |
| tinyvec_macros 0.1.1 | 5,865 | 8 | 9 | MIT, Apache-2.0 or Zlib |

Tree total: 203 files, all tracked. Two of them, `vendor/crates-io/tinyvec-1.10.0/Cargo.lock` and `vendor/crates-io/unicode-normalization-0.1.25/Cargo.lock`, are hidden by the crate's own `.gitignore` and were force-added (LD-418, F-307).

## What the approval covers

- **Lead, in writing, 2026-11-05.** Approved the exact ten choices. `/private/tmp/larsal-lead/review-artifacts/files-acquisition-proposal/lead-at-j03/LEAD-DECISION.md`, SHA-256 `c81fb00c9bc8b3715e64c60746f4fa71bfd96a935812046dc924821bcb03aaaf`.
- **Independent Checker, in writing, 2026-11-05T08:08:54Z.** APPROVE for the dependency choice and the finite acquisition proposal. "It does not grant the owner's download yes, authorize execution, finish either S2 story, or approve production security." `/private/tmp/larsal-lead/review-artifacts/files-acquisition-proposal/checker-at-j03-4cklz94t/REPORT.md`, SHA-256 `536955fadb49260d4e7b898eefe48b6b736028b1b11b41a51364d133b69d8e22`.
- **Owner's yes.** The exact words recorded are "Approve these downloads", for the reviewed request: 161 objects, 28,928,322 publisher-reported stored bytes, request SHA-256 `fc7861cfe30d543f9e26a75601e7c07e28e903b9437f86ab0055f4f668c5ee44`. The words reach this record through the lead's receipt; no separate time of the owner's answer was supplied (`/private/tmp/larsal-e22-e23-approved-acquisition-20261105/approval-receipt.json`). The receipt's permission reads "Named public HTTPS GET retrieval and data-only integrity/inventory inspection only", with no installs and no peer execution. The request also names the reviewed S2 vendoring scope, and the story places vendoring after that yes (V3 limit 3).
- **What was taken.** Items C01 to C10 (the crates), T01.1 and T01.2 (one age arm64 archive and its proof), V001 to V148 (test vector files), N01 (one NIST ZIP). T02, T03 and T04 were excluded and are absent. Result: 12 of 12 publisher SHA-256 matches, 148 of 148 Git blob matches, no failed download; the NIST ZIP has no publisher hash, only a first-seen hash. Acquisition seal SHA-256 `c3de81b3b273272aec8bbc4b69cf750f531471228b3d3d9090136a341cfbbe76`.
- **What was used.** Only the ten crate archives. The other 151 objects are not in the tree and nothing here ran them. They sit in `/private/tmp/larsal-e22-e23-approved-acquisition-20261105`; E22-S3 and E23-S3 need them later. The publisher's signed-log proof for age is unverified.
- **What it does not cover.** No execution of any peer tool, no production security approval, no claim about the crate code beyond the table above.

## Reviews before the merge

On the private candidate (source manifest SHA-256 `af3a63116d4e0e6e021af30319de150888cf28f3c9662c7bbdb44df6b357b1c3`, 11,822 records), each scoped to the dependencies only, none a story approval:

- Checker 1: APPROVE, no required finding. `/private/tmp/larsal-s2-checker1-n7fU7iIz/REPORT.md`.
- Checker 2, sensitive and supply chain: APPROVE, no required finding, 17 policy controls. `/private/tmp/larsal-s2-checker2-review-h4P7JIzp/REPORT.md`.
- Fresh Verify: APPROVE for the private dependency scope. `/private/tmp/larsal-s2-freshverify-wlgHJRvi/REPORT.md`.

V4 compared hashes: manifests, locks, deny.toml and all 203 vendor files equal that candidate; `spec/decisions.md` differs by later rows (`/private/tmp/larsal-verify-v4-XYtjArXC/proof/q4-s2.txt`).

## Gates and their results

Bytes: Source59 and Source60b, which differ by two Swift test files. Main's tree equals the sealed candidate's tracked paths (V4 steps 1 to 5). Rust results extend from Source59 by byte compare, not by a rerun (V1 section 2).

| Check | Result | Proof |
|---|---|---|
| AT-J03 | Lead and independent Checker approved in writing, the five fields above | Above |
| `cargo deny check`, root and fuzz | exit 0, "advisories ok, bans ok, licenses ok, sources ok". V3 reran both under its own guard: exit 0 | `/private/tmp/larsal-source59-o9ZKb2bn/logs/deny.log`, `deny-fuzz.log`, `gates.jsonl` |
| deny controls | larsal-core naming scrypt: exit 2. GPL on bech32: exit 4. Wrapper rule removed: the same import passes, so the rule is what catches it. Package checksum changed: exit 101 | `/private/tmp/larsal-verify-v3-LgIJVE3q/proof` |
| G1 offline | Each part exit 0, by separate steps, not one command: fmt, fmt-fuzz, clippy three ways, vendor, server-blind, names self-test, names, unsafe (425 in 18 crates), swift format, SwiftLint | `/private/tmp/larsal-source59-o9ZKb2bn/logs/gates.jsonl`; Swift parts again in `/private/tmp/larsal-s60-ac2e4ccd/runs/G1` |
| SwiftLint form | The exact check.sh form was refused a cache save under the Source59 guard (exit 1, not a lint result). With `--no-cache`: 159 files, 0 violations. The exact form on Source60b in G1: exit 0 (LD-415) | Same |
| check-vendor | exit 0 on Source59, and on fresh clones of all five commits | `/private/tmp/larsal-source59-o9ZKb2bn/logs/vendor.log`; `/private/tmp/larsal-verify-v4-XYtjArXC/proof/q2-rehearse-r2.stdout` |
| Fresh clone builds the two forced locks | `cargo check --offline --locked -p tinyvec -p unicode-normalization` exit 0 on this tree; exit 101 with the locks left out | `/private/tmp/larsal-verify-v4-XYtjArXC/proof/lockcheck-good.log`, `lockcheck-missing.log` |
| Rule 3 | 0 call sites in our own Rust files; only `crates/larsal-crypto/Cargo.toml` names the seven | V3 report Q3; V4 `q4-s2.txt` |
| Notices | All ten rows in the generated third-party notices | `/private/tmp/larsal-verify-v3-LgIJVE3q/proof/q3_evidence.json` |
| Crypto list tests | `int10_3_crypto_list_matches_larsal_crypto`, `app09_4_crypto_list_matches_larsal_crypto_and_the_pins` pass after the list fix (F-308) | R2b workspace lane, B1 |

Definition of Done, line by line: code and tests, none by scope, this story adds no code but the list entries; `scripts/check.sh` passes, met by LD-414 below; Checkers, above; Verify, V1, V3, V4; parity rows, `plan/security.md` has no row naming these stories, so this file stands as their proof; no screens; name guard, below; no Critical or High open for them (F-269 belongs to E11-S6, F-299 to E16-S7a).

## What stands in for `scripts/check.sh` (LD-414)

That one command never ran on this source. Each step ran apart, in a named root. It stands because the plain route would reach the general clipboard and show the window server to tests, which the owner forbids (rule 10). The plain command stays the project's command for the owner's own use. Map from V1's report section 6, checked by V1 against the raw output; line numbers are `scripts/check.sh`. All steps pass.

| Step (line) | What ran | Bytes | Root | Status |
|---|---|---|---|---|
| fmt, fmt-fuzz, clippy three ways, vendor, server-blind, names self-test, unsafe (101-108, 110) | Same bodies, under guard | Source59 | `/private/tmp/larsal-source59-o9ZKb2bn/logs` | Covered |
| names (109) | Same | Source59, then this commit's tree (below) | Same | Covered |
| swift format, SwiftLint (111-112) | Exact forms | Source60b | `/private/tmp/larsal-s60-ac2e4ccd/runs/G1` | Covered |
| keychain-imports (172) | The six commands equal check.sh's, then the exact body on real programs: "keychain guard: 144 binaries, 0 forbidden imports", exit 0. Control on a system tool: exit 1, 102 imports | Source59 | `/private/tmp/larsal-verify-v1-WesKkJH8/proof/keychain`, `/private/tmp/larsal-verify-v4-XYtjArXC/proof/fresh-r2/keychain-imports.log` | Covered, not as one step |
| test, test-sync, test-net (173-175) | Captured programs run directly, with `--tests`, no fail-fast; three `--doc` lanes on another target (LD-416) | Source59 | `/private/tmp/larsal-s59-a4a8b6c5/state/replay`; doc logs in the Source59 root | Covered, split |
| test-release, test-release-browser (176-177) | Captured programs run directly | Source59 | Same | Covered |
| build-core (181) | Same | Source60b | `/private/tmp/larsal-s60-ac2e4ccd/runs/A1` | Covered |
| xcode-test (182) | build-for-testing plus test-without-building, with `-IDEPackageSupportDisableManifestSandbox=1`, `-packageAuthorizationProvider netrc`, `-disableAutomaticPackageResolution`, `-skipPackageUpdates`, `-collect-test-diagnostics never`, `-resultBundlePath`, `ENABLE_USER_SCRIPT_SANDBOXING=NO`, `-disable-sandbox` | Source60b | `/private/tmp/larsal-s60-ac2e4ccd/runs/A1`, `runs/B1` | Covered, different form |
| app09 (184) | Same | Source60b | `/private/tmp/larsal-s60-ac2e4ccd/lane-out/B1/app09.stdout` | Covered |
| deny, deny-fuzz (193-194) | Same, private home | Source59 | Source59 logs | Covered |
| audit three ways (214-216) | Same, one added metadata line in the guard (LD-415) | Source59 | Source59 logs, `-followup` and `-with-index` | Covered |
| fuzz list and 29 targets (238) | Same, one call each, four at a time, 30 s each | Source59 | Source59 logs, `fuzz-*.log` | Covered |

Counts, recounted by V1 from raw output:

| Lane | Programs | Passed | Failed | Ignored |
|---|---:|---:|---:|---:|
| workspace | 119 | 3,206 | 0 | 72 |
| sync | 15 | 477 | 0 | 8 |
| net | 2 | 67 | 0 | 7 |
| release | 6 | 275 | 0 | 0 |
| release-browser | 1 | 45 | 0 | 0 |
| Total | 143 | 4,070 | 0 | 87 |

Swift: 399 tests in 57 suites passed, 536 test case runs, 0 skips, 0 issues. APP09: 18 of 18. Documentation: workspace 9 passed, sync 0, net 0. Fuzz: 29 targets, 30 s each, 0 crashes. Test names against the last full check.sh: none lost, none newly ignored.

Other forms that differ from check.sh: logs outside the source, private CARGO_HOME with copied advisory data and index, CARGO_TARGET_DIR outside, CARGO_BUILD_JOBS=4. V1 judged that none changes what is checked.

**Limits of the map:** it is not one process. There is no `Overall PASS` line. The plain route with the new F-131 rules never ran. One on-purpose format test is red on Main and was before this work (F-306); no check.sh step runs it. Tests, the Swift build, swift format and SwiftLint did not run per commit, only on the final bytes (V4 section 2).

## Name guard on this commit's tree

Run on the private clone with this file and the other records in it, under a guard derived from the Source59 guard with only the root path changed (`/private/tmp/larsal-c6-WUYsaUdC/proof/guard.diff`). `scripts/check-names.sh --self-test`: "self-test: PASS", exit 0 (`/private/tmp/larsal-c6-WUYsaUdC/proof/names-self-test.log`). `scripts/check-names.sh`: "names: PASS (11809 files scanned, 19 vault files name-only)", exit 0 (`/private/tmp/larsal-c6-WUYsaUdC/proof/names.log`). The two counts add up to all 11,828 files in the tree.

## Limits: what this Done does not prove

- **No crypto code uses them.** 0 imports of the new crates in `crates/` or `fuzz/` (V4 `q4-s2.txt`). `--debug-info` and About name seven crates the program does not link (F-308). `cargo tree` and the notices list them as shipping, because the manifest names them; V3 found 0 of their symbols in the release `larsal`, `liblarsal_ffi.a` and native Larsal.
- **Release binary.** Not byte-identical to one built with Main's dependencies: 2103 functions each, 2091 equal once crate hash, padding and addresses are removed, 8 differ. V3 read 3 of those by eye, same instructions apart from padding; the other 5 it did not read one by one.
- **Wiping.** Not proven. scrypt has no zeroize feature. CMAC, SIV, KW state, normalization copies and tinyvec spills need site by site work. `chacha20poly1305/zeroize` alone does not enable Poly1305 wiping; that rests on the existing ssh-cipher route. Goes to E22-S3 and E23-S3.
- **Constant time.** Not proven. The AES-SIV publisher's warning stands: no crate audit and no thorough constant-time assessment.
- **Unicode newer than 17.** The pinned table says Unicode 17.0.0; the research cites 18. Peer and newer-character proof stays open.
- **x86_64 compile.** Not proven as the Checker's condition asks. Only the arm64 standard library is installed. V3 compiled the library once through an unstable flag (`-Zbuild-std`), library only, no link, no run. The pinned x86_64 standard library needs the owner's yes and belongs to E14.
- **Yanked status offline.** Unproven for aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive: warnings, exit 0 (LD-415, F-320). The Checker read the seven new crates as not yanked on 2026-11-05.
- **Advisory data.** The local copy is dated 2026-10-30, the Checker's scoped read 2026-11-05. Nothing later is seen. A fresh fetch waits for the owner's yes (rule 7). Rerun deny and audit on it before any release.
- **Signatures.** crates.io archives have none. Integrity is the published checksum, read before download, plus the computed match. This is not signed release authenticity.
- **Maintainer, download and yanked data** are the Checker's 2026-11-05 reads. V3 could not repeat them offline.
- **Feature changes in existing crates.** pbkdf2 gains default and hmac, chacha20 gains xchacha, aead gains default (LD-379). All additive and none is linked yet.
