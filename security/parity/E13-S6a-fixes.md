# E13-S6 part a: re-test of F-061, F-062, F-064, F-065, F-068, F-069

Story: E13-S6 part a ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Earlier proof: [E13-S5 two-person review](E13-S5-two-person-review.md) (merge items M-01, M-04, M-07, M-10; inventory items C-02, C-05, S-06, S-33 to S-40, S-53, S-61, S-62, S-68). Ruling: LD-220 (1) the allowed crossings to Swift, (2) the TLS exception, (3) the AGENTS wording parked as W-18.
Date: 2026-10-29 (the runs took place from 06:54 to 07:12 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| F-061 (Medium) | **fixed, re-tested** | Every export that hands Swift a secret (17 of them) has a doc line naming its LD-220 class, and API.md:5, :99, :296 and architecture.md:183, :189 name the same crossings. None of the old wording ("the one secret", "Never a secret", "Secret: none", "no export returns a secret, with one exception") is left. Text fix; the values still cross by design (LD-220 (1)). |
| F-062 | **fixed, re-tested** | `{:?}` of `TotpView`, `TotpSetup`, `VersionView` and `Qr` prints `<hidden>` for the code, secret, password and modules; none of the five records derives or implements `Clone`. Each of the four fields printed again in a private copy fails `f_062` with that secret in the message. |
| F-064 | **fixed, re-tested** | `wifi_join` escapes into one `String` of the exact size (capacity 49 for 49 bytes). The old escape-and-`format!` body gives capacity 60; a capacity one byte short gives 96 (the buffer grew). Both fail `f_064`. |
| F-065 | **fixed, re-tested** | With `TMPDIR=/tmp/`, a private folder, or unset, the folder is `/var/folders/…/T/App/open-attachments` (mode 0700, this user); nothing is made under `/tmp/App`. With `std::env::temp_dir()` back, `f_065` fails. My probe (copy only) shows the start-up clean leaves a file planted under `TMPDIR` alone and wipes it with the old code. Two leftovers for the lead (below). |
| F-068 | **fixed, re-tested** | `cargo tree … --features net -i ring` still reaches app-ffi and the texts now say so: Rust rule 7 and the HTTPS cell name the TLS exception, the HTTPS and QR cells say "co-signed by the lead" (LD-197, LD-198 say the same), the Cargo.toml comment says the Mac app's core turns `net` on, and API.md:296 says the zeroing allocator wipes UniFFI's buffers. Text fix. |
| F-069 | **fixed, re-tested** | `ShownPasswordFieldTests/shownPasswordNoUndo` passes: after editing starts as a click starts it, the cell and its field editor have undo off, and Undo brings back no earlier demo secret. With the cell's override removed (copy) it fails twice. The visible-window check stays "needs Mac QA (owner's go)". |

All 6 rows were re-tested and are fixed.

## Setup

- **Shared tree, own target** (`CARGO_TARGET_DIR=/tmp/e13s6a-verify-target`). Load average 20 to 46 on 14 cores.
  - `cargo test -p app-ffi --no-fail-fast`: 16 targets, 272 passed, 0 failed, 4 ignored (lib 147, autotype 15, autotype_typing 2, clipboard 9, edit 19, generator 12, key_pages 2, memory 1, messages 7, new_vault 12, option_a 8, reports 3, session 11, ssh 17, vault_settings 7).
  - `cargo fmt -p app-ffi -p app-platform -- --check`: exit 0. `cargo clippy -p app-ffi -p app-platform --all-targets -- -D warnings` and `cargo clippy -p app-ffi --features net --all-targets -- -D warnings`: no issues.
  - `xcrun swift format lint --strict` and SwiftLint 0.65.1 `lint --strict --quiet` on ShownPasswordField.swift and ShownPasswordFieldTests.swift: exit 0. `scripts/check-names.sh`: `names: PASS (3187 files scanned, 16 vault files name-only)`.
  - The ten part a files had the same SHA-1 at the start and at the end of my run, so every result is for the same code.
- **Private copy** `/tmp/e13s6a-verify-copy` (`rsync -a --exclude target --exclude app-shots`), its own targets (`/tmp/e13s6a-verify-ctarget` for `scripts/build-core.sh`, `/tmp/e13s6a-verify-mtarget` for the mutants) and DerivedData `/tmp/e13s6a-verify-dd`. At the start its part a files matched the tree's (`shasum -c`).
  - `scripts/build-core.sh`: exit 0.
  - `xcodebuild -project macos/App.xcodeproj -scheme App -destination 'platform=macOS,arch=arm64' -derivedDataPath /tmp/e13s6a-verify-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `Test run with 310 tests in 42 suites passed after 191.804 seconds`, TEST SUCCEEDED.
  - The copy folder already existed from an earlier run (files dated 2026-10-29 22:09 to 22:18; no process of that run was alive). A dry run of `rsync -a -n --delete` from the tree afterwards listed no extra file in the copy, only my probe and the files I edited, so no stale file took part.
  - The probe's child runs `clean_open_copies`, which also cleans the real per-user App/open-attachments folder, as every App start does. That folder was empty (`ls -ld`: 2 links).
  - Only the copy got my probe tests (`verify_probe_clean_child`, `verify_probe_clean_reads_only_the_user_folder` in edit.rs's test module) and the mutants. Each mutant was written over a fresh copy of the saved file (new mtime, so cargo and Xcode rebuilt), and the saved file went back after the last one (`cmp`: identical).
- **Rules.** Demo values only (`492 039`, `JBSWY3DPEHPK3PXP`, `old-demo-pass-3`, `p\a;s,s:w"d-demo`, `first-demo-secret`, `demo bytes`). No window, focus, key events or general pasteboard; AppTests use offscreen hosts and private pasteboards. I edited no product code. Shared files I edited: the six rows in security/findings.md, the E13-S6 status line in plan/epics.md, and this file.

## F-061 (Medium): secrets that cross to Swift

- **Steps (E13-S5 merge, code path).** For each export the finding lists (`codes`, `totp`, `draft_code`, `totp_setup`, `totp_qr`, `wifi_qr`, `generate`, and the wizard's and vault settings' `password`, `repeat`, `generate`), read what it returns to Swift and what AGENTS rule 4 (as LD-220 reads it), architecture.md, API.md and the doc line say about it.
- **Before.** Each returns a secret to Swift; API.md:5 and architecture.md:189 said only Show's value crosses; API.md's QR row said "Secret: none"; the crossing list missed the QR matrix and the wizard and vault settings passwords; `codes` said "Never a secret".
- **After.**
  - The values still cross (LD-220 (1) allows them; this is a text fix). The lib tests that call these exports pass (147).
  - Doc lines: all 17 crossing exports (views.rs `codes`, `totp`, `show_field`; edit.rs `draft_password`, `show_draft_field`, `show_version`, `show_version_field`, `totp_setup`, `draft_code`, `totp_qr`, `wifi_qr`; generator.rs `generate`; wizard.rs `password`, `repeat`, `generate`; vault_settings.rs `password`, `repeat`) name their LD-220 class: the Show value, a live code, the setup secret, the QR matrix, or the generator's value.
  - API.md:5 (the rule), :99 (the QR row's Secret cell: "**the QR matrix** (LD-220): modules only, a lossless picture of the one-time link or the Wi-Fi password"), :294 (the records) and :296 ("Secrets that cross (LD-220, nothing else)") list the same crossings. architecture.md:183 (the API.md row) and :189 (app-ffi Must) say the same.
  - `grep -rn -i` for "one secret", "never a secret", "only secret", "Secret: none", "no export returns a secret", "co-sign open", "no product build", "until the zeroing", "the single value" over crates/app-ffi, crates/app-platform/Cargo.toml, plan/architecture.md and macos/App/Platform: the only matches are the new LD-220 text (API.md:5, :294), window.rs:8 (part d's preview, which LD-230 names in LD-220 (1)), app_settings.rs:1234 and architecture.md:187 (about values that are not secret).
  - Other String exports (`add_field`, `commit_edit`, `file_name`, `memory_note`, messages, version texts) return no secret.
- **Residual.** AGENTS.md rules 3 and 4 keep the owner's words until W-18 (LD-220 (3)).

## F-062: records that carry a secret

- **Steps.** `format!("{:?}")` of a `TotpView`, `TotpSetup`, `VersionView` and `Qr` holding demo values; look for `Clone` on them and on `Generated`.
- **Before.** All four derived `Debug, Clone`, so `{:?}` printed the code, secret, earlier password and modules; `Generated` derived `Clone`.
- **After.**
  - Each has a hand-written `Debug` that prints `<hidden>` for that field and keeps the others. The derives are `PartialEq, Eq, uniffi::Record` only (views.rs:361, edit.rs:286, :490, :559, generator.rs:96), and there is no `impl Clone` for any of them.
  - `edit::tests::f_062_secret_records_hide_their_secret_in_debug`: ok.
- **Mutants (copy).** Each of the four fields printed again with `&self.<field>` fails f_062, and the message holds that demo value:
  - m1: `492 039 printed: TotpView { code: "492 039", …`
  - m2: `JBSWY3DPEHPK3PXP printed`
  - m3: `old-demo-pass-3 printed`
  - m4: `[1, 0, 0, 1] printed`

## F-064: Wi-Fi QR text

- **Steps.** Build the Wi-Fi join text for a name and password with every special character (`Café;Net`, `p\a;s,s:w"d-demo`), and compare the buffer's capacity with its length.
- **Before.** `wifi_text` escaped each part into its own `String` and joined them with `format!`.
- **After.**
  - `wifi_join` (edit.rs:1306) works out the exact size (15 fixed bytes plus each part and its escapes) and writes into one `String`. The only caller is `wifi_text`, which wraps the result in a `SecretString` at once, and `wifi_qr` is the only caller of `wifi_text`.
  - `f_064_wifi_text_is_one_buffer_of_the_exact_size`: ok (text `WIFI:T:WPA;S:Café\;Net;P:p\\a\;s\,s\:w\"d-demo;;`, capacity equals length).
- **Mutants (copy).**
  - m5, the per-part escape and `format!`: FAILED, `left: 60 right: 49`.
  - m6, capacity 14 + … instead of 15 + …: FAILED, `left: 96 right: 49` (the buffer grew).

## F-065: opened-attachment folder

- **Steps (demo data).** Run the folder code with `TMPDIR` set to the shared `/tmp/`, to a private folder, and unset. Read `open_folder` and `clean_open_copies`.
- **Before.** The folder was `$TMPDIR/App/open-attachments` (or `/tmp/App/…`), with a mode check and no owner check. `clean_open_copies` read the same path with no check.
- **After.**
  - `open_folder` (edit.rs:1169) builds the folder from `app_platform::macos::user_temp_dir()` (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, never the environment). It refuses a link, any group or other mode bit, and an owner other than `geteuid()`. `clean_open_copies` (:1217) lists only `open_folder()`'s result, and the attachment open (:2481) uses it too.
  - `TMPDIR=/tmp/`, `TMPDIR=/private/tmp/e13s6a-verify-shared-tmp/` and `env -u TMPDIR`, each with `cargo test -p app-ffi --lib -- --exact edit::tests::f_065_child --ignored --nocapture`, all print `folder /var/folders/95/…/T/App/open-attachments` (the `getconf DARWIN_USER_TEMP_DIR` folder). `ls -ld` shows it `drwx------` for this user, and no `/tmp/App` or `…/e13s6a-verify-shared-tmp/App` exists afterwards.
  - `f_065_opened_attachments_live_in_the_users_own_temp_folder`: ok.
  - In the copy, my probe `verify_probe_clean_reads_only_the_user_folder` plants `planted-demo.txt` in `/tmp/e13s6a-verify-probe-<pid>/App/open-attachments`, runs a child with that `TMPDIR` that calls `clean_open_copies`, and the file is still there: ok.
  - The other `std::env::temp_dir()` calls in app-ffi product code (saving.rs:384, :462, wizard.rs:844) only pass `private_temp` to `SaveRequest::plain`, whose safe method never uses it. The rest are in test modules.
- **Mutants (copy).**
  - m7, `std::env::temp_dir()` back in `open_folder`: f_065 FAILED (the child panicked at `open_folder().unwrap()` with `TMPDIR=/nonexistent-tmpdir/`).
  - m8, `clean_open_copies` reading `std::env::temp_dir().join("App/open-attachments")`: f_062, f_064 and f_065 all pass (as Checker 1 found), and only my probe FAILED: the planted file was wiped.
  - m9, the owner check removed: every test passes. That branch needs a second local user to test.
- **Residuals (for the lead).**
  1. No product test fails when the start-up clean goes back to `TMPDIR`. My probe is the smallest guard; it could join edit.rs's tests as an `f_065_…` case.
  2. The owner refusal has no test.
  3. `wipe_file` still checks and then opens by path, but only inside this user's own 0700 folder.
  - Both the Builder and Checker 1 recorded 2 and 3. I accept them: the folder is no longer one another user can reach.

## F-068: approved crates and rule texts

- **Steps.** `cargo tree --offline --locked -p app-ffi --features net -e normal -i ring`, with and without `net`, and `-i getrandom@0.2.17`; `scripts/build-core.sh`'s features; then the texts the finding names.
- **Before.** ring, rustls and getrandom 0.2.17 shipped in the Mac app's core while the texts said "in no product build yet" and "lead co-sign open", Rust rule 7 named no exception, and API.md said UniFFI buffers are freed without wiping.
- **After.**
  - The build is unchanged (a text fix, LD-220 (2)). With `net`, ring reaches app-ffi through rustls and app-platform (and app-core, app-format, app-autotype, app-sshagent). Without `net`, "package ID specification `ring` did not match any packages". `getrandom v0.2.17` sits under ring only. build-core.sh:24 still has `features=(--features net)`, and `--no-net` turns it off (:28).
  - architecture.md:284 Rust rule 7 names the exception (LD-194, LD-197, LD-220 (2)). The HTTPS cell (:268) says "co-signed by the lead, LD-197" and "the TLS exception of LD-220 (2)", and the QR cell (:261) says "co-signed by the lead, LD-198". spec/decisions.md LD-197 and LD-198 both record "co-signed by the lead 2026-10-28".
  - crates/app-platform/Cargo.toml:23-25 says "the Mac app's core turns it on (scripts/build-core.sh, app-ffi `net`: the TLS exception of LD-220 (2))". API.md:296 ends "the zeroing allocator that app-ffi's `lib.rs` installs (LD-133, LD-193) wipes each one on free".
  - `cargo clippy -p app-ffi --features net --all-targets -- -D warnings`: no issues.
- **Residual.** AGENTS rule 3's wording waits on W-18. The E13-S5 inventory's C-02 and C-05 stay as the dated record that the merge corrected.

## F-069: undo in the no-copy field editor

- **Steps (merge M-07, code fact).** `grep -rn allowsUndo macos/App`; then the no-window test.
- **Before.** `allowsUndo` appeared nowhere in macos/App, and text field cells allow undo by default.
- **After.**
  - ShownPasswordField.swift:121 `NoCopyCell.allowsUndo` is always false (an empty setter), and :150 `harden()` sets `allowsUndo = false`.
  - Every shown-secret field is a `NoCopyTextField`: the unlock form, `EditorPasswordField` (also used by the one-time secret sheet), `GeneratorPanel` and `SecretFields`.
  - `ShownPasswordFieldTests/shownPasswordNoUndo` ("F-069: …") passed in the full run.
- **Mutants (copy),** each run with `-only-testing:AppTests/ShownPasswordFieldTests`:
  - s1, the cell's `allowsUndo` override removed: FAILED with two issues, `ShownPasswordFieldTests.swift:55 Expectation failed: !cell.allowsUndo && !editor.allowsUndo` and `:59 Expectation failed: Self.textAfterUndo(editor) == "second"`.
  - s2, only `harden()`'s line removed: passes (the cell override alone does the work; the line is a second guard).
  - Restored: `Test run with 2 tests in 1 suite passed`, TEST SUCCEEDED, and the file is back as it was (`cmp`).
- **Residual.** A check with a visible window and the window's own undo manager while a person types needs Mac QA (owner's go).

## For the lead (no row changed)

- LD-220 (1), API.md:5 and architecture.md:189 list "the wizard's and vault settings' password, repeat and generate". vault_settings.rs has no `generate`, so the list names one crossing that does not exist; API.md:296 has it right. This came from Checker 1, and I confirmed it (`grep -n "pub fn generate" crates/app-ffi/src/vault_settings.rs`: none). It is text only, and nothing crosses that is not named.
- F-065 residual 1 above: add the start-up clean case as a product test (m8 is missed today).
- Checker 1's open question still stands: protected Title, UserName, URL and Notes (F-060) are edited in plain SwiftUI fields (Forms.swift PlainField, EditorProtected.swift NotesBox), which keep the window's undo. It is outside F-069's items (S-61, S-62, S-68).
