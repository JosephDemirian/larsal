# E13-S5 Two-person review: merged result

Story: E13-S5, two-person review of every `unsafe` block, crypto call and secret conversion (plan/epics.md; plan/team.md: two Checkers for crypto, file format, unsafe and secret handling; plan/architecture.md Rust rules 2, 3, 6, 7 and the approved crates table; plan/security.md; plan/attacks-and-checks.md AT-C*, AT-J*).
Step: merge. It compares the two independent reviews, gives each item both verdicts, re-reads the code of every finding, files the confirmed ones and sets the status line.
Inputs: [E13-S5-inventory.md](E13-S5-inventory.md) (171 items), [E13-S5-review-a.md](E13-S5-review-a.md) (Checker A, tree read 00:03 to 00:24), [E13-S5-review-b.md](E13-S5-review-b.md) (Checker B, tree read 00:29 to 00:50).
Date: 2026-10-29. Merge read from 00:51 to 00:59.
Clean room: App's own code and App's marked changes in `vendor/` only. No reference source opened.
Edits: this file, rows F-061 to F-071 in security/findings.md, and the E13-S5 status line in plan/epics.md. No product code changed. One read-only `cargo tree --offline --locked` (no build); no test run, no scripts/check.sh.

## Result in one paragraph

All 171 inventory items and all 12 items the Checkers added have two reviews. 9 of the added items were raised by one Checker only, so I reviewed them as the second reviewer at the merge (list below). Nobody found memory unsafety, broken crypto or a secret that an attacker can reach. 11 findings are filed for E13-S6: F-061 (Medium) and F-062 to F-071 (Low). The Medium one is a rule gap, not a leak: live one-time codes, the one-time setup secret, the QR matrix, the generator value and the master password Show and dice cross to Swift although AGENTS rule 4 and its restatements allow only Show. Three Checker findings are not filed: one is already F-059, two are not defects.

## Counts per kind

| Kind | Items | What they are | Reviewed by A | Reviewed by B | Two reviews |
|---|---|---|---|---|---|
| Unsafe | 60 (U-01 to U-60) | 56 `unsafe` blocks (37 product, 8 test tool, 11 unit test), 11 `unsafe fn`, 2 `unsafe impl`, 2 safe `extern "C"` handlers, the generated UniFFI scaffolding and 2 foreign traits | 60 | 60 | 60 |
| Crypto | 58 (C-01 to C-05, C-10 to C-40, C-50 to C-71) | 5 at the Rule 3 boundary, 31 inside app-crypto, 22 caller groups | 58 | 58 | 58 |
| Secrets | 53 (S-01 to S-06, S-10 to S-24, S-30 to S-40, S-45 to S-48, S-50 to S-56, S-60 to S-69) | 6 types and helpers, 15 Rust conversions, 11 Rust-to-Swift crossings, 4 Swift-to-Rust crossings, 7 sinks, 10 Swift holders | 53 | 53 | 53 |
| Added by the Checkers | 12 (M-01 to M-12) | 5 unsafe, unchecked or process items, 2 crypto, 5 secret handling (table below) | 8 | 7 | 12 (9 with the merge as second reviewer) |
| **Total** | **183** | | 179 | 178 | **183** |

## Items with one Checker only: second review at the merge

| Item | Raised by | My review (time read) |
|---|---|---|
| M-01 `scripts/build-core.sh:36` | B (A's C-02 verdict said the opposite) | Confirmed (00:53). The Mac app's core is built with `-p app-ffi --features net`. `cargo tree --offline --locked -p app-ffi --features net -e normal -i ring` reaches app-ffi through app-platform and rustls; without the feature, `ring` is not in the tree; `-i getrandom@0.2.17` shows it under ring. So rustls, ring and getrandom 0.2.17 ship. Approved use (LD-194, LD-197); the texts are wrong: F-068. |
| M-05 `crates/app-platform/src/hardening.rs:23-42` | B | Sound (00:58). Release only; both steps run whatever the other did; one fixed M11-01 line on stderr; no flag, setting or environment is read. Called first by app-ffi start.rs:87 and app-cli main.rs:31. |
| M-06 `vendor/ssh-key/src/private/opaque.rs:141-142` | B | Confirmed, with a smaller reach (00:56). `OpaquePrivateKeyBytes` derives `Clone` and has no wipe on drop. But the only product caller of `OpenSshKey::parse` is app-sshagent `SshKey::read` (key.rs:63), which refuses a type outside INT-06.6 right after the parse (key.rs:64-67). So such a key never reaches an agent, contrary to B-10; only its transient plain bytes rely on the zeroing allocator: F-070. |
| M-07 `macos/App/Platform/ShownPasswordField.swift:107-188` | B | Code fact confirmed (00:55): no `allowsUndo` anywhere in `macos/App`; text field cells allow undo by default. The undo copies are not proven (a probe needs a visible window, rule 10): F-069. |
| M-08 `macos/App/AutoType.swift:18` `WindowID: @unchecked Sendable` | A | Sound (00:55, file changed at 00:47:35, after both Checkers). It wraps an `AnyHashable` holding an `AXUIElement` (an immutable CF object; hashing and equality are thread-safe) or a test fake. |
| M-09 `macos/App/Platform/DiskWatch.swift:12` `DiskWatch: @unchecked Sendable` | A | Sound (00:56). All mutable state is touched on its own serial queue; blocks hold `self` weakly, so `deinit` cannot run while one of them runs. |
| M-10 `crates/app-ffi/src/edit.rs:1104-1117, 1145-1150` `open_folder`, `clean_open_copies` | A (B judged S-53 sound) | Confirmed and widened (00:54): F-065. `clean_open_copies` reads the same `TMPDIR` folder with no check at all, and `wipe_file` opens by path after `symlink_metadata`. |
| M-11 `crates/app-cli/src/term.rs:68-86` stdout buffer | A (B judged S-55 sound) | Confirmed (00:58): `out_parts` writes through `io::stdout()`'s line buffer. This is F-059 (open, Low, accepted by the lead 2026-10-28), so no new row. |
| M-12 Non-constant-time `==` and `cmp` on secret values (inventory observation 6) | A | No finding (00:57). Sampled edit.rs:1624, breach.rs:205 and :572, refs.rs:864, attachments.rs:152, app-autotype lib.rs:811, app-cli commands.rs:853: local search, sort, de-duplication and a y/n answer. None compares a MAC or key (Rust rule 6), and nothing outside the process can time them. |

Not items: the other `MainActor.assumeIsolated` uses in Swift (AutoType.swift:162, 177; SecureInput.swift; LockSignals.swift; ScreenProtection.swift; QuitSignals.swift) are checked at run time (they trap off the main thread), so they are not unchecked contracts.

## Both verdicts per item

"Sound" means the SAFETY note, crypto use or secret handling is right as written. F-numbers are the rows filed in security/findings.md (merged findings below).

### Unsafe

| Id | Checker A | Checker B | Merged |
|---|---|---|---|
| U-01 | Sound | Sound | Sound |
| U-02 | Sound | Sound | Sound |
| U-03 | Sound | Sound | Sound |
| U-04 | Sound (two ops in one block, Info) | Sound | Sound |
| U-05 | Sound | Sound | Sound |
| U-06 | Sound | Sound | Sound |
| U-07 | Sound | Sound | Sound |
| U-08 | Sound | Sound | Sound |
| U-09 | Sound | Sound | Sound |
| U-10 | Sound | Sound | Sound |
| U-11 | Sound | Sound | Sound |
| U-12 | Sound | Sound | Sound |
| U-13 | Sound as memory; one-guard rule not enforced | Sound; B-6 | Sound; F-063 |
| U-14 | Sound; F3 | Sound; B-6 | Sound; F-063 |
| U-15 | Sound; F3 | Sound; B-6 | Sound; F-063 |
| U-16 | Sound | Sound; B-6 | Sound; F-063 |
| U-17 | Sound (test feature) | Sound (test feature) | Sound |
| U-18 | Sound | Sound | Sound |
| U-19 | Sound | Sound | Sound |
| U-20 | Sound | Sound | Sound |
| U-21 | Sound (two ops, Info) | Sound | Sound |
| U-22 | Sound | Sound | Sound |
| U-23 | Sound | Sound | Sound |
| U-24 | Sound (two ops, Info) | Sound | Sound |
| U-25 | Sound | Sound | Sound |
| U-26 | Sound | Sound | Sound |
| U-27 | Sound | Sound | Sound |
| U-28 | Sound | Sound | Sound |
| U-29 | Sound | Sound | Sound |
| U-30 | Sound | Sound | Sound |
| U-31 | Sound | Sound | Sound |
| U-32 | Sound | Sound | Sound |
| U-33 | Sound | Sound | Sound |
| U-34 | Sound | Sound | Sound |
| U-35 | Sound (two ops, Info) | Sound | Sound |
| U-36 | Sound | Sound | Sound |
| U-37 | Sound | Sound | Sound |
| U-38 | Sound (two ops, Info) | Sound | Sound |
| U-39 | Sound (block); no `# Safety` (F8) | Sound; B-7 | Sound; F-067 |
| U-40 | Sound (block); F8 | Sound; B-7 | Sound; F-067 |
| U-41 | Sound (tool) | Sound (tool) | Sound |
| U-42 | Sound (tool) | Sound (tool) | Sound |
| U-43 | Sound (tool) | Sound (tool) | Sound |
| U-44 | Sound (tool) | Sound (tool) | Sound |
| U-45 | Sound (tool) | Sound (tool) | Sound |
| U-46 | Sound (test) | Sound (test) | Sound |
| U-47 | Sound (test) | Sound (test) | Sound |
| U-48 | Sound (test) | Sound (test) | Sound |
| U-49 | Sound (test) | Sound (test) | Sound |
| U-50 | Sound (test) | Sound (test) | Sound |
| U-51 | Sound (test) | Sound (test) | Sound |
| U-52 | Sound (test) | Sound (test) | Sound |
| U-53 | Sound (test) | Sound (test) | Sound |
| U-54 | Sound (test) | Sound (test) | Sound |
| U-55 | Sound (test) | Sound (test) | Sound |
| U-56 | Sound (test) | Sound (test) | Sound |
| U-57 | Sound (test) | Sound (test) | Sound |
| U-58 | Sound (generated, LD-157) | Sound (generated) | Sound |
| U-59 | Sound | Sound (note for E8-S3: `FocusCheck` reads AX on the Rust thread) | Sound; note kept for E8-S3 |
| U-60 | Sound | Sound | Sound |

### Crypto

| Id | Checker A | Checker B | Merged |
|---|---|---|---|
| C-01 | Sound | Sound | Sound |
| C-02 | Sound (says `net` is on in no product crate) | Sound use; B-1 (ships in the Mac app) | Sound use; A's reason corrected by M-01; F-068 |
| C-03 | Sound | Sound | Sound |
| C-04 | Sound | Sound | Sound |
| C-05 | Info (App never calls it) | Sound; B-1 (ring calls getrandom 0.2.17 for TLS) | Sound; F-068 |
| C-10 | Sound | Sound | Sound |
| C-11 | Sound | Sound | Sound |
| C-12 | Sound | Sound | Sound |
| C-13 | Sound (probe: real 256 KiB scrub) | Sound (best effort) | Sound |
| C-14 | Sound | Sound | Sound |
| C-15 | Sound | Sound | Sound |
| C-16 | Sound | Sound | Sound |
| C-17 | Sound | Sound | Sound |
| C-18 | Sound | Sound | Sound |
| C-19 | Sound | Sound | Sound |
| C-20 | Sound | Sound | Sound |
| C-21 | Sound | Sound | Sound |
| C-22 | Sound | Sound | Sound |
| C-23 | Sound | Sound | Sound |
| C-24 | Sound | Sound | Sound |
| C-25 | Sound | Sound | Sound |
| C-26 | Sound | Sound | Sound |
| C-27 | Sound | Sound | Sound |
| C-28 | Sound | Sound | Sound |
| C-29 | Sound | Sound | Sound |
| C-30 | Sound | Sound | Sound |
| C-31 | Sound | Sound | Sound |
| C-32 | Sound | Sound | Sound |
| C-33 | Sound | Sound | Sound |
| C-34 | Sound | Sound | Sound |
| C-35 | Sound | Sound | Sound |
| C-36 | Sound | Sound; B-10 | Sound; F-070 |
| C-37 | Sound | Sound | Sound |
| C-38 | Sound | Sound | Sound |
| C-39 | Sound | Sound | Sound |
| C-40 | Sound | Sound | Sound |
| C-50 | Sound | Sound | Sound |
| C-51 | Sound | Sound | Sound |
| C-52 | Sound | Sound | Sound |
| C-53 | Sound | Sound | Sound |
| C-54 | Sound | Sound | Sound |
| C-55 | Sound | Sound | Sound |
| C-56 | Sound | Sound | Sound |
| C-57 | Sound | Sound | Sound |
| C-58 | Sound | Sound | Sound |
| C-59 | Sound | Sound | Sound |
| C-60 | Info (F11, no caller) | Sound (no caller) | Sound today; F-071 |
| C-61 | Sound | Sound | Sound |
| C-62 | Sound | Sound | Sound |
| C-63 | Sound | Sound | Sound |
| C-64 | Sound | Sound | Sound |
| C-65 | Sound | Sound | Sound |
| C-66 | Sound | Sound | Sound |
| C-67 | Sound | Sound | Sound |
| C-68 | Sound | Sound | Sound |
| C-69 | Sound | Sound | Sound |
| C-70 | Sound | Sound | Sound |
| C-71 | Sound | Sound | Sound |

### Secrets

| Id | Checker A | Checker B | Merged |
|---|---|---|---|
| S-01 | Sound | Sound | Sound |
| S-02 | Sound | Sound | Sound |
| S-03 | Sound (`Entry::value()` a hidden expose) | Sound (same remark) | Sound |
| S-04 | Sound | Sound | Sound |
| S-05 | Sound | Sound | Sound |
| S-06 | Sound | Sound; B-8 (API.md stale) | Sound; F-068 |
| S-10 | Sound | Sound | Sound |
| S-11 | Sound | Sound | Sound |
| S-12 | Sound | Sound | Sound |
| S-13 | Sound | Sound | Sound |
| S-14 | Sound (allocator wipes) | Sound (limit) | Sound |
| S-15 | Sound | Sound | Sound |
| S-16 | Sound | Sound | Sound |
| S-17 | Sound | Sound | Sound |
| S-18 | Sound | Sound | Sound |
| S-19 | Sound | Sound | Sound |
| S-20 | Sound | Sound | Sound |
| S-21 | Sound as memory; F6 | Low B-5 | F-066 |
| S-22 | Sound | Sound | Sound |
| S-23 | Info (F11) | Sound | Sound today; F-071 |
| S-24 | Sound | Sound (for now) | Sound; review again in E8-S3 |
| S-30 | Sound (Show) | Sound | Sound |
| S-31 | Sound | Sound | Sound |
| S-32 | Sound | Sound | Sound |
| S-33 | Sound flow; F1, F2 | Sound flow; B-2 | Sound flow; F-062 |
| S-34 | Sound | Sound | Sound |
| S-35 | Sound flow; F1, F2 | Sound flow; B-2 | F-061, F-062 |
| S-36 | Crossing without Show (F1); F2 | Low B-3; B-2 | F-061, F-062 |
| S-37 | Crossing (F1); F2; F4 | Low B-3, B-4; B-2 | F-061, F-062, F-064 |
| S-38 | Sound; F1 | Sound; B-2 (`Clone`) | F-061, F-062 |
| S-39 | Sound flow; F1 | Sound flow; B-8 | F-061 |
| S-40 | Sound flow; F1 | Sound flow; B-8 | F-061 |
| S-45 | Sound | Sound | Sound |
| S-46 | Sound | Sound | Sound |
| S-47 | Sound | Sound | Sound |
| S-48 | Sound | Sound | Sound |
| S-50 | Sound | Sound (limit) | Sound |
| S-51 | Sound | Sound | Sound |
| S-52 | Sound | Sound | Sound |
| S-53 | Sound as file handling; F5 | Sound (limit) | F-065 (merge confirms A, M-10) |
| S-54 | Sound | Sound | Sound |
| S-55 | Sound for reads; F7 | Sound | Sound; the stdout buffer is F-059 (M-11) |
| S-56 | Sound | Sound | Sound |
| S-60 | Sound (Swift limit) | Sound (Swift limit) | Sound; re-read after UnlockView.swift changed at 00:48:22 (binding unchanged) |
| S-61 | Sound | Sound; B-9 | Sound; F-069 |
| S-62 | Sound | Sound; B-9 | Sound; F-069 |
| S-63 | Sound | Sound | Sound |
| S-64 | Sound | Sound (documented, F-060) | Sound |
| S-65 | Sound | Sound | Sound |
| S-66 | Sound | Sound | Sound |
| S-67 | Sound | Sound | Sound |
| S-68 | Sound | Sound; B-9 | Sound; F-069 |
| S-69 | Sound | Sound | Sound; re-read after EditorEntryPage.swift changed at 00:02:01 |

### Added by the Checkers

| Id | Location | Checker A | Checker B | Merged |
|---|---|---|---|---|
| M-01 | scripts/build-core.sh:36 | (C-02: "on in no product crate") | B-1 | Confirmed at the merge; F-068 |
| M-02 | macos/App/AutoType.swift:39-40 `unsafeDowncast` | Sound | Sound | Sound (re-read at 00:55 after the 00:47 change) |
| M-03 | macos/App/AutoType.swift:105-110 Carbon callback | Sound | Sound | Sound (re-read at 00:55) |
| M-04 | crates/app-ffi/src/edit.rs:1222-1243 `wifi_text` | F4 | B-4 | F-064 |
| M-05 | crates/app-platform/src/hardening.rs:23-42 | (not listed) | Sound | Sound at the merge |
| M-06 | vendor/ssh-key/src/private/opaque.rs:141-142 | (C-36 sound) | B-10 | Confirmed, reach narrowed; F-070 |
| M-07 | macos/App/Platform/ShownPasswordField.swift:107-188 undo | (S-61 sound) | B-9 | Code fact confirmed; F-069 |
| M-08 | macos/App/AutoType.swift:18 `WindowID` | Sound | (not listed) | Sound at the merge |
| M-09 | macos/App/Platform/DiskWatch.swift:12 | Sound | (not listed) | Sound at the merge |
| M-10 | crates/app-ffi/src/edit.rs:1104-1117, 1145-1150 | F5 | (S-53 sound) | Confirmed and widened; F-065 |
| M-11 | crates/app-cli/src/term.rs:68-86 | F7 | (S-55 sound) | Already F-059 |
| M-12 | `==`/`cmp` on secret values (observation 6) | Info, no oracle | (not listed) | No finding at the merge |

## Merged findings

Each was read once more at the merge (times in the table above). Rows are in security/findings.md with steps, location and the smallest fix; E13-S6 fixes them.

| F | Severity | From | Items | Finding | Smallest fix |
|---|---|---|---|---|---|
| F-061 | Medium | A F1 (Medium), B B-3 (Low) and B-8 | S-35 to S-40 | Live one-time codes (`codes`, `totp`, `draft_code`; up to 200 a call, once a second, no Show), the setup secret (`totp_setup`), the QR matrix (`totp_qr`, `wifi_qr`; a lossless picture of the link or Wi-Fi password), the generator value and the wizard and vault settings `password`, `repeat`, `generate` cross to Swift. AGENTS rule 4, architecture.md:189 and API.md:5 allow only Show; API.md:95 says "Secret: none" for QR; API.md:243 misses QR and the master password crossings; views.rs:1284 calls codes "never a secret". Medium, not Low: rule 4 is a never-broken rule that only the owner can widen, which is Medium's "owner accepts in writing" path. | One lead decision naming every allowed crossing; the owner's written yes for rule 4's wording; align API.md:5, :95, :243, architecture.md:189 and the `codes` doc. No code change. |
| F-062 | Low | A F2, B B-2 | S-33, S-35 to S-38 | `TotpView`, `TotpSetup`, `VersionView`, `Qr` derive `Debug` and `Clone` over a secret; `Generated` derives `Clone` (Rust rule 3). Only tests format them today. | Hand-written `Debug` hiding `code`, `secret`, `password`, `modules`; drop `Clone` where not needed. |
| F-063 | Low | A F3, B B-6 (both probed) | U-13 to U-16 | Two live `QuitGuard`s dropped oldest first leave the `note` handler installed for good. Not reachable today; no memory unsafety. | Static `AtomicBool` in `catch_quit`, cleared in `Drop`. |
| F-064 | Low | A F4, B B-4 | S-37, M-04 | `wifi_text` puts the Wi-Fi password in plain `String`s and a `format!` (Rust rule 3); only the zeroing allocator wipes them. | One exact-capacity buffer wrapped at once. |
| F-065 | Low | A F5; widened at the merge | S-53, M-10 | Opened-attachment folder from `TMPDIR` with a mode check but no owner check; `clean_open_copies` checks nothing and `wipe_file` follows a link swapped in after its check. Needs `TMPDIR` unset or shared and another local user. | `user_temp_dir()` and an owner check in both functions. |
| F-066 | Low | A F6, B B-5 | S-21 | Command line messages, `ls`, paths and merge records print flag-protected Titles (LD-207). | Mask them, or one line in LD-207 leaving the command line out. |
| F-067 | Low | A F8, B B-7 | U-39, U-40 | IOKit callbacks have no `# Safety` section and no `catch_unwind`. | Add both. |
| F-068 | Low | A F10, B B-1 and B-8 | C-02, C-05, S-06, M-01 | rustls, ring and getrandom 0.2.17 ship in the Mac app (`build-core.sh:36`); AGENTS rule 3 and Rust rule 7 name no exception; stale "no product build", "lead co-sign open" and API.md:243 allocator texts. | Name the TLS exception; fix the four texts. |
| F-069 | Low | B B-9; code fact confirmed at the merge | S-61, S-62, S-68, M-07 | The no-copy field editor keeps undo on, so earlier shown texts may sit in the window's undo manager. Not proven (rule 10). | `allowsUndo = false` on the cell and in `harden()`. |
| F-070 | Low | B B-10; reach narrowed at the merge | C-36, M-06 | Vendored ssh-key's unknown-type private bytes are not wiped; `SshKey::read` refuses those types, so only a transient plain copy relies on the zeroing allocator. | One line in LD-182's conditions. |
| F-071 | Low | A F11; B: no caller | C-60, S-23 | `remember_key` stores an unsalted SHA-256 of the command; no caller yet. | Document and hash the unresolved command, or HMAC with a per-install key. |

Not filed, with the reason:

- A F7 (stdout line buffer keeps a printed value): already F-059, open and accepted by the lead on 2026-10-28.
- A F9 (five blocks hold two unsafe operations each): each note covers both operations; a style choice, not a defect.
- A missed item 6 (non-constant-time compares on secret values): local lookups only, not MACs or keys (M-12).
- Notes kept for later stories, not findings: U-59 and S-24 for E8-S3 (Auto-Type typing posts the plan's values and runs `FocusCheck` AX reads on the Rust thread); S-53's overwrite does not reach old blocks on APFS (documented in MOD-05).

Disagreements and how they were settled:

- C-02: A said `net` is on in no product build; B showed `build-core.sh:36` turns it on. B is right (cargo tree at the merge).
- F-061 severity: A Medium, B Low. Merged as Medium (reason in the row).
- S-53: B judged it sound; A's F5 holds, and the merge found the start-up cleanup is weaker still.
- B-10: B said unknown key types can go to the agent; `SshKey::read` refuses them first, so only the plain copy is at stake.

## Items both Checkers found sound

- Unsafe: U-01 to U-12, U-17 to U-38, U-41 to U-60 (54 items); U-13 to U-16 and U-39, U-40 are memory-sound too, with F-063 and F-067 on rules and docs.
- Crypto: C-01, C-03, C-04, C-10 to C-35, C-37 to C-59, C-61 to C-71 (54 items; C-36 is sound as crypto, with F-070 on the vendored crate's wipe; C-02, C-05 and C-60 are sound uses with F-068 and F-071 on texts and a future caller).
- Secrets: S-01 to S-05, S-10 to S-20, S-22, S-24, S-30 to S-32, S-34, S-45 to S-48, S-50 to S-52, S-54, S-56, S-60, S-63 to S-67, S-69 (38 items). The other 25 inventory items carry a finding (6 unsafe, 4 crypto, 15 secrets).
- Added items: M-02, M-03 (both); M-05, M-08, M-09 (one Checker and the merge).

## Files read at the merge, with their state

Hashes are SHA-256, first 16 hex, taken at 00:59. The Rust files match the inventory and Checker A where they list them.

| File | Modified | SHA-256 (16) |
|---|---|---|
| crates/app-ffi/src/edit.rs | 10-28 19:18:39 | fec93139f05e3289 |
| crates/app-ffi/src/views.rs | 10-28 15:41:28 | 0b3f3922a4c579b7 |
| crates/app-ffi/src/generator.rs | 10-28 15:25:31 | d6b05cc21c204f3f |
| crates/app-ffi/src/wizard.rs | 10-28 16:08:38 | 93d8c91f4c841b5b |
| crates/app-ffi/src/vault_settings.rs | 10-28 19:33:35 | 52742759b79a88f1 |
| crates/app-ffi/API.md | 10-28 21:22:16 | 06b7dd40a569ee58 |
| crates/app-platform/src/macos/signals.rs | 10-28 05:28:55 | 8fadf27d0193b4ae |
| crates/app-platform/src/hardening.rs | 10-28 03:39:32 | 3d66e42cda450a1c |
| crates/app-hwkey/src/usb/watch.rs | 10-28 07:40:07 | 67d8a043a5f66243 |
| crates/app-cli/src/commands.rs | 10-28 09:21:39 | ee52b8dd6873e346 |
| crates/app-cli/src/term.rs | 10-28 04:28:41 | 515d7268307792ba |
| crates/app-core/src/url.rs | 10-28 08:21:12 | c15331ee3821fdf0 |
| crates/app-crypto/src/ssh.rs | 10-28 09:03:24 | 8aef08046b3a8986 |
| crates/app-sshagent/src/key.rs | 10-28 05:11:26 | 3d646b8202627d0d |
| vendor/ssh-key/src/private/opaque.rs | 10-28 14:50:36 | a98c39eb7af28030 |
| scripts/build-core.sh | 10-28 13:02:38 | 236d925a094a7dad |
| plan/architecture.md | 10-28 20:45:14 | 313cf4ff124a62ec |
| macos/App/Platform/ShownPasswordField.swift | 10-28 21:26:26 | a2d094563a019e0c |
| macos/App/Platform/DiskWatch.swift | 10-28 18:19:13 | 7dbb762fc82554f8 |
| macos/App/AutoType.swift | **10-29 00:47:35 (after both Checkers)** | 0969c8065d901ab9 |
| macos/App/UnlockView.swift | **10-29 00:48:22 (after both Checkers)** | 10179bb377614c51 |
| macos/App/EditorEntryPage.swift | 10-29 00:02:01 (before both read it) | def0b8ea7adb7eac |

Changed since midnight (`find -newer`, 00:57): MainWindowModel.swift 00:01:53, EditorEntryPage.swift 00:02:01, Dialogs.swift 00:02:48 (both Checkers read these after the change); plan/epics.md 00:40:19, spec/decisions.md 00:41:57 (B read LD-197 and LD-207 after it); crates/app-ffi/tests/autotype.rs 00:45:22 (test, no `unsafe`); AutoType.swift and AutoTypePicker.swift 00:47:35, UnlockView.swift 00:48:22 (after both Checkers: I re-read the reviewed lines; `WindowID`, `unsafeDowncast`, the Carbon callback and the unlock password binding are as reviewed; the picker draws rows that Rust has already masked). E5-S11, E6-S5 and E8-S2 builders are still at work.

## Report

- Story: E13-S5 (merge step).
- Files changed: security/parity/E13-S5-two-person-review.md (new); security/findings.md (rows F-061 to F-071); plan/epics.md (E13-S5 status line). No product code.
- Proof: both Checkers' clippy runs (`-D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment`, exit 0 for app-platform and app-hwkey), app-platform tests (A 27 passed; B 10 passed), the two quit-guard probes (`note=true`), A's stack probe; at the merge `cargo tree --offline --locked -p app-ffi --features net -e normal -i ring` (reaches app-ffi) and without `--features net` (no `ring`), and the code reads above; scripts/check-names.sh after the edits.
- Open issues: F-061 needs a lead decision and the owner's written yes for the rule 4 wording; F-062 to F-071 are small code or text changes for E13-S6.
- Next step: E13-S6 fixes and re-tests F-061 to F-071.
- Re-check 2026-10-29 20:29 to 20:35 (the merge step ran a second time): the 22 files above still have the same SHA-256; no file under crates, macos, scripts, vendor or spec changed after this file was written. Both reviews and this file cover all 171 inventory ids (script check). The code behind F-061 to F-071 and F-059 was re-read and still holds. No new rows were filed and the status line was not changed. scripts/check-names.sh: PASS, exit 0.
