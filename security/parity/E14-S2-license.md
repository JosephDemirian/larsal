# E14-S2 License (D2), third-party notices, word list license: proof

> Historical licensing evidence. LD-345 (2026-11-04) replaces the former GPL/AGPL requirements for current first-party versions. The commands and results below are preserved; they do not verify the new license. Updated checks and independent sign-off are pending.


Builder, 2026-10-31. Owner decision D2 and LD-262 (3). Built in a private copy (`/tmp/e14s2-builder-copy`, own `CARGO_TARGET_DIR`), then applied to the shared tree in one step. No reference source or app was opened (Builder, clean room). Web pages were only read; nothing was sent.

## 1. What was built

| # | Part | Files |
|---|---|---|
| 1 | Larsal's license: the exact GPL-3.0 text, the GNU "or later" notice, every crate's license field | `LICENSE`; README.md section "License"; `license = "GPL-3.0-or-later"` in `[workspace.package]` of `Cargo.toml` and in `fuzz/Cargo.toml`; `license.workspace = true` in all 12 `crates/*/Cargo.toml` |
| 2 | Notices shipped and shown | `scripts/build-core.sh` runs `scripts/make-sbom.sh` into `target/larsal-core/notices/`; the Xcode phase "License and Notices" (`macos/Larsal.xcodeproj`) copies `LICENSE`, `THIRD-PARTY-NOTICES.md`, `rust-std-COPYRIGHT.html` and `sbom.cdx.json` into `Larsal.app/Contents/Resources`; `macos/Larsal/Resources/Credits.rtf` is the text of the standard About window; `larsal --license` (`crates/larsal-cli/src/main.rs`, listed in `larsal` help); `scripts/repro-build.sh` puts `LICENSE` beside `larsal` in the release folder |
| 3 | Word list license | `ATTRIBUTION` in `crates/larsal-core/src/generator/wordlist.rs` (CC BY 4.0), word for word in Credits.rtf, `larsal --license` and a "Built-in word list" section of `THIRD-PARTY-NOTICES.md` (make-sbom reads it from the source) |
| 4 | Contributor agreements, individual and entity | `legal/CONTRIBUTOR-AGREEMENT.md` (Harmony, Option Five) |
| 5 | Paid license of the team features | `legal/TEAMS-LICENSE.md` (from the PolyForm Free Trial and Internal Use 1.0.0 texts) |
| 6 | Plain-words page | `legal/README.md` |
| 7 | Bill of materials | `sbom.cdx.json` now gives Larsal's own crates and Larsal itself `GPL-3.0-or-later` |
| 8 | Test | `crates/larsal-cli/tests/license.rs`: `e14_2_license_is_the_exact_gpl_3_0_text`, `e14_2_every_crate_of_app_says_gpl_3_0_or_later`, `e14_2_the_license_and_word_list_notices_are_shown` |

## 2. The GPL-3.0 text

- Read with `curl -sS -o gpl-3.0.txt https://www.gnu.org/licenses/gpl-3.0.txt` on 2026-10-31, into an empty folder in /tmp, then copied to `LICENSE` unchanged.
- 35,149 bytes, 674 lines, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.
- The test hashes `LICENSE` with `larsal_crypto::hash::sha256` (rule 3: no hash crate outside larsal-crypto) and compares with that value.

## 3. Tests and checks (private copy)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check`; same for `fuzz/Cargo.toml` | pass |
| `cargo test --offline --locked --workspace` | exit 0 in 4 min 59 s: 106 test binaries, 2,463 passed, 0 failed, 63 ignored; the three `e14_2_*` tests pass |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | exit 0 |
| `scripts/build-core.sh` | exit 0; `make-sbom: 117 components, 94 license texts, 10 crates without a license file` |
| `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e14s2-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` | `** TEST BUILD SUCCEEDED **`; the log runs `PhaseScriptExecution License\ and\ Notices` in target Larsal |
| `ls Larsal.app/Contents/Resources` | `Credits.rtf`, `LICENSE`, `THIRD-PARTY-NOTICES.md`, `rust-std-COPYRIGHT.html`, `sbom.cdx.json` beside the fonts, icons and `LICENSES.md` |
| `shasum -a 256 Larsal.app/Contents/Resources/LICENSE` | `3972dc97…36986` |
| `cmp` of the bundle's notices with `target/larsal-core/notices/THIRD-PARTY-NOTICES.md` | same |
| `codesign --verify --strict Larsal.app` | pass |
| `textutil -convert txt -stdout Credits.rtf` (the Cocoa text reader, offscreen) | the copyright line, the GPL-3.0-or-later and NO WARRANTY notice, where the texts are, the word list attribution |
| `cargo deny --offline --locked check licenses bans sources` (workspace; fuzz with the F-114 config) | `bans ok, licenses ok, sources ok`, both |
| `scripts/check-vendor.sh` | PASS |
| `scripts/check-names.sh /tmp/e14s2-builder-copy` | `names: PASS (9702 files scanned, 16 vault files name-only)` |
| Each of the 9 encoded words of check-names.sh counted, case-insensitive, in the made `THIRD-PARTY-NOTICES.md`, `rust-std-COPYRIGHT.html` and `sbom.cdx.json` (words not printed) | 0 in each |
| `scripts/repro-build.sh --rust` (own `CARGO_TARGET_DIR`) | exit 0; the release folder holds `LICENSE` (SHA-256 `3972dc97…36986` in SHA256SUMS) beside `larsal`, the notices and the bill of materials |

`larsal --license` (debug build), exit 0:

```
Larsal command line tool 0.1.0
Copyright (C) 2026 [Licensor legal name]
License GPL-3.0-or-later: GNU General Public License, version 3 or later,
<https://www.gnu.org/licenses/gpl-3.0.html>.
This is free software: you are free to change and share it under that license.
There is NO WARRANTY, to the extent permitted by law.

The license text (LICENSE) and the licenses of the third-party software in Larsal
(THIRD-PARTY-NOTICES.md) ship with Larsal: in Larsal.app/Contents/Resources, and beside
this tool in a release folder.

Word list: EFF Large Wordlist for Passphrases, by the Electronic Frontier Foundation, https://www.eff.org/dice, unmodified, used under the Creative Commons Attribution 4.0 International license (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/), which provides it as is, with no warranty.
```

`larsal -v` still prints `0.1.0` alone (INT-10.3-b).

## 3a. Shared tree, after the one-step apply

| Command (own `CARGO_TARGET_DIR`) | Result |
|---|---|
| `cargo build --offline --locked --workspace` | exit 0 (1 min 22 s) |
| `cargo test --offline --locked -p larsal-cli --test license` | 3 passed |
| `scripts/check-vendor.sh` | PASS |
| `scripts/check-names.sh` | `names: PASS (9991 files scanned, 16 vault files name-only)` |
| `shasum -a 256 LICENSE` | `3972dc97…36986` |

`scripts/check.sh` was not run (the lead runs it).

## 4. Mutants (private copy, `cargo test --offline --locked -p larsal-cli --test license`)

| Mutant | Result |
|---|---|
| Baseline | 3 passed |
| M1: one byte of `LICENSE` changed (`2007` to `2008` in the version line) | `e14_2_license_is_the_exact_gpl_3_0_text` FAILED |
| M2: `license.workspace = true` removed from `crates/larsal-model/Cargo.toml` | `e14_2_every_crate_of_app_says_gpl_3_0_or_later` FAILED |
| M3: the word "unmodified," removed from the attribution in Credits.rtf | `e14_2_the_license_and_word_list_notices_are_shown` FAILED |
| Restored | 3 passed; `LICENSE` SHA-256 `3972dc97…36986` |

## 5. cargo deny and F-137

Larsal's 12 crates are `publish = false`, so `[licenses.private] ignore = true` skips their license, and the gate passes as before. Probe (private copy, config copy with `ignore = false`): `cargo deny --offline --locked --config <copy> check licenses` gives `licenses FAILED` with 12 `error[rejected]`, one per crate of Larsal, license `GPL-3.0-or-later`. So a fix of F-137 that turns the private skip off must also name Larsal's own crates (an exception each, or a private-registry rule); F-137's own smallest fix (drop `publish = false` from the two vendor copies) does not touch Larsal's crates. `deny.toml` was not edited: the E0-S7 follow-up owns it. Its comment "Our own crates are publish = false and have no license yet (decision D2)" is now out of date.

## 6. The agreements: what was read and why these

Read 2026-10-31 (pages only; the one POST was the public signing service's own read of the agreement text, with the repository name only):

| Source | Its reuse terms | Used? |
|---|---|---|
| Harmony Combined Contributor Agreement Template 1.0, <https://www.harmonyagreements.org/docs/ha-combined-v1> (13,887 bytes, SHA-256 `40a0136e…3eba`) | Its own last lines: "This work is licensed under a Creative Commons Attribution 3.0 Unported License." | **Yes**, for both agreements: a license (the contributor keeps the copyright, 2.1(a), 2.6), Option Five lets the maker license under any license (paid license, App Store) and also keeps each contribution under the project's own license; individual and entity versions. Credit and the list of changes are at the end of CONTRIBUTOR-AGREEMENT.md. |
| Apache ICLA <https://www.apache.org/licenses/icla.pdf> and the license FAQ <https://www.apache.org/foundation/license-faq.html> | FAQ: "Yes, you can re-use and modify them", without the ASF's name except to say it is derived | Studied. A license too, but its promise is only use that fits the ASF's nonprofit status; it says nothing on other licenses. |
| Bitwarden Contributor Agreement (the text of <https://cla-assistant.io/bitwarden/clients>) | none stated | Studied: a copyright assignment with a license back. Not used: it takes the contributor's copyright, and its text has no reuse grant. |
| PolyForm Free Trial 1.0.0 (3,130 bytes, SHA-256 `f7f8e69e…c883`) and Internal Use 1.0.0 (3,314 bytes, SHA-256 `3a4a1539…6ef7`), <https://github.com/polyformproject/polyform-licenses> at tag 1.0.0 | README "License": each contributor licenses everything with the texts; "If you make changes to a PolyForm license, you must remove all mention of "PolyForm" and polyformproject.org" | **Yes**, for TEAMS-LICENSE.md: their acceptance, grants, fair use, no other rights, patent defense, no liability and definitions; Internal Use's 32-day fix; Larsal's own sections for reading and testing, production use with a license file, no sale, no hosting for others, the license file check, notices and the AGPL parts. The text names no PolyForm, as their terms ask. |
| Bitwarden License Agreement v1, <https://github.com/bitwarden/server/blob/main/LICENSE_BITWARDEN.txt>; LICENSE_FAQ.md | none stated | Studied: the model (non-production development and testing free; production needs a paid subscription, per the FAQ). No words copied. |
| GitLab EE license, <https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/LICENSE> | none stated | Studied: the same model (development and testing free; production needs a subscription). No words copied. |
| Elastic License 2.0, <https://www.elastic.co/licensing/elastic-license> and its FAQ | no reuse statement found on the page or in the FAQ | Studied: no hosted service for others, no getting around the license key. Written in Larsal's own words. |
| EFF copyright page <https://www.eff.org/copyright>; FSF license list <https://www.gnu.org/licenses/license-list.html> | — | EFF's own material is under CC BY 4.0; the FSF lists CC BY 4.0 as compatible with all GNU GPL versions (and MPL-2.0 and Apache-2.0 as compatible with GPLv3), so the list and the third-party crates fit GPL-3.0-or-later. |

## 7. Not done, and why

- No per-file license header (SPDX line) in each source file: the GNU notice is in README.md, as the story asks. Add with E14-S6 if wanted.
- The bill of materials does not list the word list as a component; the notices name it.
- The notices list the `net` crates also for a `--no-net` build (make-sbom always walks `--features net`): more than ships, never less.
- The About window was not opened (AGENTS.md rule 10). The standard About window reads `Credits.rtf` from the bundle; the file's text was read offscreen with textutil.
- The AGPL-3.0 text, the server's team folder and its file headers wait for E16 and E18.
- Spec cards were not edited (Builder): INT-10's top-level flag table has no row for `--license` yet, and FEA-03's License row still says the notice text is D2's.
- A lawyer reads both drafts before the first sale and the first outside contribution (legal/README.md).

## 8. Verify (2026-10-31): signed

Verify agent; did not build or check this story. Private copy `/tmp/e14s2-verify-copy`, own `CARGO_TARGET_DIR` (`/tmp/e14s2-verify-target`) and derived data (`/tmp/e14s2-verify-dd`). Web pages were read with GET only, into empty folders in /tmp; nothing was sent. No reference source or app was needed.

### 8.1 Checks run again

| Command | Result |
|---|---|
| `curl https://www.gnu.org/licenses/gpl-3.0.txt`; `shasum -a 256`; `cmp` with `LICENSE` | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` for both; cmp: same |
| `cargo metadata --no-deps` (workspace and fuzz/) | the 12 crates of Larsal and `larsal-fuzz`: `GPL-3.0-or-later` |
| `cargo test --offline --locked --workspace` | exit 0 in 5 min 28 s: 106 test binaries, 2,463 passed, 0 failed, 63 ignored; the three `e14_2_*` tests pass |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`; `cargo fmt --check` (workspace, fuzz/) | exit 0; pass |
| `cargo deny --offline --locked check` (workspace); `check licenses bans sources` on fuzz/ with the check.sh F-114 config | `advisories ok, bans ok, licenses ok, sources ok`; `bans ok, licenses ok, sources ok` |
| `scripts/build-core.sh` | exit 0; `make-sbom: 117 components, 94 license texts, 10 crates without a license file` |
| `xcodebuild ... build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` | `** TEST BUILD SUCCEEDED **`; `PhaseScriptExecution License\ and\ Notices` ran once |
| Larsal.app/Contents/Resources | `LICENSE` (SHA-256 `3972dc97…36986`), `THIRD-PARTY-NOTICES.md` (cmp equal to `target/larsal-core/notices/`), `rust-std-COPYRIGHT.html`, `sbom.cdx.json`, `Credits.rtf` (cmp equal to the source), `LICENSES.md`; `codesign --verify --strict` ok; `textutil` reads Credits.rtf as the copyright line, GPL-3.0-or-later, NO WARRANTY, where the texts are, the word list attribution |
| `sbom.cdx.json` | root Larsal and the 11 shipped crates of Larsal `GPL-3.0-or-later`; 0 components without a license |
| `larsal --license`; `larsal -v`; `larsal -h` | exit 0, the text of section 3; `0.1.0` alone; the usage line names `--license` |
| EFF list: `curl` of eff_large_wordlist.txt, `cmp` with `crates/larsal-core/src/generator/eff_large_wordlist.txt`; eff.org/copyright | same bytes; "original material on the EFF website ... under the Creative Commons Attribution 4.0" |
| `scripts/check-names.sh` on the copy; on the 6 shipped resource files plus the `larsal --license` output | `names: PASS (9704 files scanned, 16 vault files name-only)`; `names: PASS (7 files scanned)` |
| Shared tree against the checked copy, `cmp` of the 29 story files (LICENSE, all manifests, code, scripts, project, Credits.rtf, README.md, legal/, this file) | 29 equal |

Own mutants (`cargo test -p larsal-cli --test license`, private copy), each different from sections 4 and the Checker's:

| Mutant | Result |
|---|---|
| Baseline | 3 passed |
| V1: last byte of `LICENSE` cut (35,148 bytes) | `e14_2_license_is_the_exact_gpl_3_0_text` FAILED |
| V2: `crates/larsal-hwkey` says `license = "MIT"` | `e14_2_every_crate_of_app_says_gpl_3_0_or_later` FAILED |
| V3: `license.workspace = true` of larsal-crypto moved out of `[package]` into another table | `e14_2_every_crate_of_app_says_gpl_3_0_or_later` FAILED |
| V4: `larsal --license` prints `""` instead of `ATTRIBUTION` | `e14_2_the_license_and_word_list_notices_are_shown` FAILED |
| V5: Credits.rtf says `(GPL-3.0)` instead of `(GPL-3.0-or-later)` | `e14_2_the_license_and_word_list_notices_are_shown` FAILED |
| Restored | 3 passed; the 5 files cmp equal to the shared tree |

Not run again: `scripts/repro-build.sh`. It builds in the one fixed folder `/private/tmp/larsal-repro`, one run at a time, and other agents work now. The story's change to it is one line (`LICENSE` added to the `cp` of the release folder), read in the script.

### 8.2 The two drafts against their sources

- **Harmony template** (read again: 13,887 bytes, SHA-256 `40a0136e…3eba`, ends "licensed under a Creative Commons Attribution 3.0 Unported License"; the agreements page gives version 1.0 of 2011-07-04). A script made the template's Individual and Entity license variants with Option Five, without the Media line, with the "[AND BY US TO YOU]" and "[OR US]" words, and diffed them line by line with Agreements 1 and 2. The only differences: the project and party names, no fax, `[Signing instructions]` and `[Jurisdiction]`, the non-owner instructions written into the definition of Contribution and 3(d), "(Agreement 2)" after "the Entity version of this document", and the signature blocks. All are in the list of changes (item 5), except "(Agreement 2)", a cross-reference. No other word differs.
- **What the story asks of the agreements:** for individuals and for entities: yes. Larsal's maker may license a contribution under any license, commercial and proprietary included (2.3, Option Five): yes. The contributor keeps the copyright and every right not licensed (2.1(a), 2.6): yes. Template, license and reason named, with the CC BY 3.0 credit (author, title, version, URL, license URL, changes, no endorsement): yes. Harmony's "how to use" page sets no rule on names; it asks for advice from counsel, which legal/README.md asks for.
- **Studied, not used:** the ASF license FAQ says "Yes, you can re-use and modify them"; the ICLA (v2.2) promises only use that is not "inconsistent with its nonprofit status": both as legal/README.md says. Bitwarden's agreement was not read again: the only copy found is behind a POST to the signing service, and a search found no other copy. The Builder and the Checker quote the same assignment words; it was not used, so this does not change the result.
- **PolyForm** (read again at tag 1.0.0: README, Free Trial `f7f8e69e…c883`, Internal Use `3a4a1539…6ef7`, the values of section 6). The README allows changes if every mention of "PolyForm" and polyformproject.org is removed: TEAMS-LICENSE.md has none (grep: 0). 455 of its 957 seven-word runs come from the two PolyForm texts. It shares 0 runs with the Bitwarden License Agreement or the GitLab EE license (both read again), and the 195 runs it shares with the Elastic License 2.0 are all in PolyForm too. The Elastic FAQ has no reuse statement, as said.
- **What the story asks of the teams license:** free to read and test (Permitted Purposes); production use only with a valid subscription or license file (Permitted Purposes, Definitions); no sale and no hosting for others (its own section); no getting around the license file check (License Files); never the Mac app (first paragraph): yes. Its rule that copies stay inside your company matches the Bitwarden and GitLab EE models (GitLab EE: "it is forbidden to copy, merge, publish, distribute, sublicense, and/or sell the Software", patches allowed).

### 8.3 The plain-words page

legal/README.md is right on each part: GPL-3.0-or-later for the Mac app, engine and tool; AGPL-3.0 for the server when it exists; the Teams License for the team folder only; the contributor agreement for outside work; third-party code under its own licenses. The lawyer line, the `[Licensor legal name]` placeholder and the sources are there, and its relative links open. Notes, none blocking (text only, no F number):

1. "business-model.md section 2.5 asks for" should say section 2, "What this means for Larsal" (Checker 1's note, still open).
2. "Whoever shares a changed Larsal must share its source": GPL-3.0 section 6 asks this of whoever shares Larsal in binary form, changed or not.
3. The Teams License line leaves out that copies may not go to anyone outside your company.

One note on the made notices, not blocking: `scripts/make-sbom.sh` (line 154) now writes the "Built-in word list" section before the table "These crates publish no license file", so that table sits under the word list heading. Every text is still there.

## Current source-available terms

Verified 2026-11-04 under LD-345. The earlier sections record the former policy and remain historical. Current first-party versions use the Larsal Source-Available License 1.0; third-party licenses, required notices and earlier grants retain their effect.

Root, server and packaged LICENSE are byte-equal, SHA-256 `d34eb24ac75b85beda2934911c76260d752de229c2b45e574d623afbdf4a1a7f`. All 18 workspace packages and fuzz resolve the license file without an alternate grant. The current CLI, About, welcome, website, legal guidance, bundled credits and notices agree. The exact word-list credit is preserved. The BOM has 119 components: 13 first-party named-license choices and 106 unchanged external/data/toolchain records.

`cargo test --offline --locked -p larsal-cli --test license` passed all four current tests: `e14_2_license_has_the_approved_terms_and_integrity`, `e16_3_server_uses_the_same_first_party_terms`, `e14_2_every_first_party_crate_resolves_the_license_file` and `e14_2_the_license_and_word_list_notices_are_shown`. Six targeted mutations failed as required; a separate alternate grant was rejected by both the exhaustive test and BOM generator. Recorded mutation preimages match the integrated source.

The complete check, fresh artifact notice/signature checks and actual main integration passed independently; see [E14-S1](E14-S1-name.md) for commands, source binding, totals and limits. E14-S2 and E16-S3's license acceptance are signed; E16-S3's earlier server-functional proof is preserved.

This is local implementation acceptance. Legal review before public release, first sale or outside contribution remains required. No legal certification or full official BOM-schema validation is claimed.
