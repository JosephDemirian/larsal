# E5-S5 Editor: Verify

Date: 2026-10-28. Role: Verify (did not build or check this story). Cards: MOD-01 to MOD-10, FEA-04.22/.23, FEA-05.7, INT-02.29, APP-05; decisions LD-139, LD-170 (4), LD-192, LD-198, LD-199. Reference access: the reference CLI 2.7.11, read only, on a /tmp copy with a throwaway HOME.

**Verdict: not signed.** Two acceptance checks fail (items 1 and 2 below) and one MOD-01 gap needs a lead decision (item 3). Everything else the brief asks for is proven below.

## Failures and smallest fixes

1. **A new entry loses the expiry set in the editor** (MOD-09.10 "Saving: `Expires` = the box, `ExpiryTime` = the field"; MOD-01 coverage). `commit_edit` adds a new entry through app-core `edit::add_entry`, which sets `expires = false` and `expiry = now` (app-core `edit.rs` lines 296 to 304). The Entry page offers the switch, the date and the presets on a new entry too (`EditorEntryPage.swift` `expiry`). Proof: driver test `v1_mod01_every_field_round_trips`: `V1 new entry expiry after reopen: expires false expiry 1793177470 (set: true 1900000000)`; the reference CLI's export of the same file shows `Expires False`. An existing entry keeps its expiry (`Wise` reads back `true 1900000100`; reference CLI `Expires True 1900000100`).
   Smallest fix: in app-ffi `commit_edit`, new-entry branch, after `edit::add_entry` put the draft's `times.expires` and `times.expiry` back on the added entry when the box is ticked (MOD-01.25's defaults stay for the other callers); one test that a new entry with an expiry reads back with it.
2. **Protected standard fields reach Swift without Show** (rule 4, LD-105 "A protected value never reaches the screen without Show", MOD-01.7; API.md says `EditorView` holds "No password, no protected value"). `edit.rs` `view()` fills `title`, `user`, `url` and `notes` from the draft whatever their protected flag; the detail view blanks them. Proof: driver test `v2_editor_views_hold_no_secret` on a demo vault whose `UserName`, `Notes` and `URL` are protected (own flag and vault flags): `detail view carries []; editor view carries ["protected-user-77", "protected-notes-77", "protected-url-77"]`. Any vault saved with the reference's "protect user name / URL / notes" settings sends those values to the screen layer on every Edit. Filed as F-060 (Medium).
   Smallest fix: in `view()`, give an empty value plus a protected flag for each standard field whose own flag is on (as `custom` does), let `show_draft_field` accept those standard names, and draw them on the Entry page masked with Show, as the protected custom fields are; the same for protected `KP2A_URL*` values in `urls`. One test like `v2` that fails without it.
3. **MOD-01 properties with no editor control** (acceptance check "every field in card MOD-01 can be edited"): the colours (MOD-01.14, "When the user picks a color") and the report exclusion (MOD-01.19, "A boolean on the edit screen") have no app-ffi edit call and no control; the locked mockup draws neither, and LD-192 does not mention them. Smallest fix: a lead decision: either a mockup addition (as W-10 for the generator) with `set_colors` and `set_exclude_from_reports` exports, or a written move to a named later story.

Not blocking: notes at the end.

## 1. MOD-01 coverage through the edit API

Driver `crates/app-ffi/tests/verify_e5s5.rs` (Verify's own, private copy only), test `v1_mod01_every_field_round_trips`, on a copy of testdata/option-a-personal.appvault. A new entry in Work gets: title, user name, URL, two-line notes, password (typed into `set_password`), two additional URLs, an unprotected and a protected custom field, tags, expiry, standard icon 12, a 4,352-byte attachment (all 256 byte values), Auto-Type off with an own sequence and two windows, Allow and Deny sites, the three browser options, and one-time password settings (8 digits, 60 s, SHA-256). `Wise` gets a custom icon (symbol tile PNG) and an expiry; `GitHub` goes custom icon → standard icon 3 (MOD-01.13). Commit, `save`, then a fresh `Session` opens the file:

| Field | Read back |
|---|---|
| Title, user name, URL, notes (with line break) | equal |
| Password | `draft_password` equal; `password_chars` 15 |
| Additional URLs | `KP2A_URL`, `KP2A_URL_1` equal |
| Custom fields | unprotected value shown; protected value empty in the view, `show_draft_field` equal |
| Tags | `alpha`, `beta` (sorted, MOD-07) |
| Expiry | existing entry equal; **new entry lost (failure 1)** |
| Icon | standard 12; custom "airplane cyan" (icon -1); custom → standard 3 |
| Attachment | name and size equal; Save… bytes equal |
| Auto-Type | off, sequence and both windows equal |
| Browser (INT-02.29) | Allow `allow.example`, Deny `deny.example`, options true/true/true |
| One-time password | 8, 60, SHA-256, valid; `totp_setup` secret equal, choice `custom`; `draft_code` 8 digits |

Then the remove paths (field, URL, attachment, window, site, a tag, expiry off, one-time password removed) are committed, saved and read back as removed. Result line: `V1: every listed MOD-01 field saved and read back from /tmp/e5s5v/work/mod01.appvault; new-entry expiry kept: false`.

**Interop (reference CLI 2.7.11, HOME=/tmp throwaway, a /tmp copy of the saved file):** `export -f xml` exit 0; the new entry has every string above with `Password`, `Secret field` and `otp` protected, `Tags alpha,beta`, `IconID 12`, the Auto-Type block and both associations, the four custom data items (browser options and site access `{"Allow":["allow.example"],"Deny":["deny.example"],"Realm":""}`), `Expires False` (failure 1); `Wise`: custom icon `airplane cyan`, `Expires True 1900000100`; `GitHub`: `IconID 3`, no custom icon. `attachment-export` → bytes equal (4,352). `show -s -a otp -a "Secret field" -a Password` → the same values; `show -t` → an 8-digit code.

## 2. Secrets

- **Opens masked:** Swift `EditorModel.shownPassword == nil` after Edit; the masked field is `FocusSecureField` (existing test "Hide password drops the shown value…", passed). Rust: `EditorView` has `password_chars` only; `v2`: GitHub's password, its one-time secret and a protected custom value are not in `format!("{:?}", editor(v))`.
- **Typed values go to Rust:** Verify's Swift test `VerifyE5S5Tests.modelWalk` types into the masked field through its delegate: `draftPassword` returns the typed text; no model holds it. Protected custom values cannot be typed while protected (the cell is a Show button); typing happens unprotected, then `protectField`.
- **Model walk** (every `String` reachable from `MainWindowModel` by reflection, `Session` handles skipped), with positive controls: `editor opened (masked): none; typed in the masked field: none; Show password: 1 found; Hide password: none; Show protected field: 1 found; Hide protected field: none; entry change: none; vault switch (Discard): none; vault switch (Finder open, editor paused): none; one-time setup sheet open: 1 found; one-time setup sheet closed: none; earlier version sheet open: 1 found; earlier version sheet closed: none; discard: none; before lock: 1 found; lock: none; draft gone after lock: true`.
- **Drafts wiped on lock:** `v2`: `has_draft` true → lock → false; Swift: after lock and unlock `editor(vault:)` throws.
- **Kept password page-locked:** `password_pages_locked` = `Some(true)` unlocked, `None` after lock, `Some(true)` after unlock (`v2`); existing `ld_199_3_kept_password_is_page_locked` passed.
- **QR matrix only:** `let Qr { size, modules } = …` (exhaustive pattern, no other field); one-time QR 61 × 61, Wi-Fi 53 × 53, values 0 and 1 only. Swift `struct Qr` has `size` and `modules` only.
- **Not covered here (protected standard fields): failure 2.**

## 3. Saving

- **Safe save:** `save` builds with app-format and writes with app-core `storage::save(SaveRequest::plain(…))` (method Safe). `v3_safe_save_and_failed_saves`: new inode after the save (temp file renamed over), mode 0640 kept, no temp file left in the folder.
- **Failed saves leave the file untouched:** read-only file, a folder that takes no new file, and a file changed on disk: each `failure` set, `changes` 1, file byte-identical (the third: equal to the other program's bytes).
- **Concurrent saves:** `v3_concurrent_saves_write_the_newest_copy` and `v3_racing_saves_leave_nothing_unsaved`: 24 rounds, the file always held the newest change. These black-box tests did not catch the regression (copy taken before the save lock: 3 of 3 runs still passed); the builder's hook tests do: `ld_199_4_a_waiting_save_writes_the_change_made_while_it_waited` and `ld_199_4_a_save_waiting_across_a_lock_writes_nothing` pass, and both fail with that regression (Verify mutation in the copy, restored, `cmp` equal).
- **Reference CLI opens the saved file with the same content:** section 1.

## 4. Attachments

- `v4_attachment_copies` (TMPDIR pointed at a private folder): the copy is 0600 in a 0700 `App/open-attachments`, named 12 random characters plus `.txt`; wiped on editor close by Cancel, editor close by Save, lock, quit (lock all), remove, a new edit, a second Open of the same file (older copy), and close.
- Next start: a unit test in the copy plants a file and calls `clean_open_copies()` → wiped; `start.rs` line 170 calls it on the primary's start.
- `v4_save_refuses_path_tricks` on a demo vault with hostile names: `../../escape-up.txt` → `....escape-up.txt` inside the folder, nothing outside; `a/b\c:d.txt` → `abcd.txt`; `..`, `.`, `///` refused; a planted link at the target: first asks (false), then is replaced by a 0600 regular file, the link's target untouched; attaching a folder or `/dev/null` refused (`CannotOpen`).

## 5. LD-139 and LD-170 (4)

- `v5_ld139_every_edit_forgets_the_rating`: 5 rounds of two password edits in the same second (5 of 5), each re-rated (weak then strong); clone, delete, restore and empty bin each reset the Health Check. Mutation: `commit_edit` without `rated.forget` → the test fails. No merge or reload exists in app-ffi yet (E5-S10).
- `v5_ld170_show_and_copy_hide_otp_and_passkey_fields`: `{S:otp}`, `{S:TOTP Seed}`, `{S:TOTP Settings}`, `{S:TimeOtp-Secret-Base32}`, `{S:KPEX_PASSKEY_PRIVATE_KEY_PEM}`, `{S:KPEX_PASSKEY_USERNAME}` resolve to nothing in Show and Copy (private pasteboard) of the password, the notes and a custom field, and through `{REF:P@I:…}` and `{REF:N@I:…}`; `{S:Plain}` still resolves (`abcdefgvisible`); the six fields themselves are refused by Show and Copy. Mutation: no hidden fields → the test fails.
- Strength meter (FEA-05.7, LD-137): `rate_draft` runs in `Task.detached` after a 300 ms pause (`EditorModel.rate(after:)`). Verify's Swift test: six changes 60 ms apart leave the rating unchanged; the new rating (21 characters, 106 bits) arrives 0.28 s after the last key, 2 of 2 runs.

## 6. AT-E06 drops

`grep -rn "onDrop\|dropDestination\|registerForDraggedTypes\|NSDraggingDestination\|performDragOperation\|DropDelegate"` in macos/App: three targets only: the editor's attachment target (file URLs only, `EditorPages.swift` line 154; Rust refuses anything but a regular file), the welcome window's vault-file drop (`FileOpen.droppedVaults`, test "APP-09.26-a, AT-E06: a drop opens vault files only" passed) and the unlock form's key file row (LD-163 (2), accepted at the E5-S4 Verify; it only sets the key file path). A real drag needs a visible window: Mac QA.

## 7. Design parity

Reports: design/parity/editor/, design/parity/dialogs/, design/parity/states/ (report.md, report.html, findings.json, app/, diff/), each with a "Verify run for E5-S5" section listing the commands.

| Section | Result | Pixels, outside accepted (worst) |
|---|---|---|
| editor | 9/9 PASS | 0.87 % |
| dialogs | 11/11 PASS (10 frames of later stories) | 1.38 % |
| states | 15/15 PASS (incl. states-unsaved-changes, states-delete-as-a-sheet) | 1.71 % |

66 `Parity …` behaviour tests passed, 0 failed; every built frame has at least one. Checked by eye: editor-editor-entry (light) and dialogs-one-time-code-as-qr (dark) against their references. Accepted rules checked against LD-163, LD-167, LD-192 and LD-199 (8): they hold (details in each report). The parity tool `ocr.swift` no longer type-checks on this toolchain (`unable to type-check this expression in reasonable time`, line 25); a copy with the expression split read 88 images; smallest fix: the same split in design/parity/tools/ocr.swift.

## Commands (private copy /tmp/e5s5v/tree, `rsync -a --exclude target` at 09:40, deleted afterwards)

1. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0 (1 min 38 s).
2. `TMPDIR=/tmp/e5s5v/tmpdir cargo test -p app-ffi --test verify_e5s5 -- --test-threads=1 --nocapture` → 8 passed, 1 failed (`v1`, failure 1). Lines quoted above.
3. `TMPDIR=… cargo test -p app-ffi` → lib 26, clipboard 9, edit 17, generator 9, key_pages 2 (1 ignored), memory 1, messages 7, option_a 8 (1 ignored), session 11: all passed.
4. Mutations (each restored, `cmp` equal): no `rated.forget` in `commit_edit` → `v5_ld139` FAILED; `hidden: |_name| false` → `v5_ld170` FAILED; no `opened.clear()` in `cancel_edit` → `v4_attachment_copies` FAILED; copy before the save lock → `ld_199_4_a_*` 2 FAILED (the black-box `v3_*` passed 3 of 3: timing).
5. Reference CLI (version 2.7.11): `export -f xml`, `attachment-export`, `show -s -a …`, `show -t` on /tmp/e5s5v/interop/check.appvault with `HOME=/tmp/e5s5v/refhome`; outputs in section 1.
6. `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e5s5v/dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → 110 tests in 19 suites, 109 passed, 1 failed (Verify's own meter test, a 700 ms wait under the parallel run); reworked, `-only-testing:AppTests/VerifyE5S5Tests` passed 2 of 2 runs (both tests).
7. Parity: `node design/option-a/tools/export-reference.mjs` (91 + 91 frames, manifest identical), `node design/parity/tools/mockup-dom.mjs editor,dialogs,states` (45 frames, 2903 text runs per theme), the OCR copy (88 images), `node design/parity/tools/compare.mjs editor|dialogs|states` (results above).

## Notes, not blocking

- The leave-the-vault question (LD-199 (2)) reuses the close-with-unsaved-changes look with "Discard"; that frame belongs to E5-S10, so it has no parity row here.
- A Finder open of another vault while editing pauses the editor (shown values dropped, draft kept) instead of asking; nothing is lost (walk step "Finder open, editor paused": none).
- The parity rule notes cite LD-192 (5) and LD-166 for the history limit sentence ("per entry", MOD-03.6) and the SSH comment (demo data); neither decision names them. The attachment line says "1 GB" where LD-192 (3) says 1 GiB. The one-time QR frame also masks the card's countdown and Copy row (an area the mockup leaves empty).

## For Mac QA (owner's go, visible window)

Real key-window focus and the focus ring; secure input in the password and one-time secret fields (`SecureInput`, `onDisappear`); a real drag onto the three drop targets; the attachment watch (MOD-05.13); Open handing the copy to a real default app.

## CPU

About 30 CPU-minutes in all (largest: build-core 12.3 CPU-minutes); no single run over 2 minutes of wall time. Only processes started here; Chrome headless stopped by its own driver.

## Re-check after the fixes (2026-10-28, 13:45 copy)

**Verdict: not signed.** Failure 1's fix brought a new, small regression (R1 below); everything else holds. Failures 2 and 3 are closed.

### R1. A new entry saved without an expiry gets ExpiryTime 0001-01-01 (MOD-01.25, MOD-09.1)

The fix copies the draft's `expires` and `expiry` onto every new entry after `add_entry`, but a new draft's `expiry` is the zero time (`begin_new` view: `expires false expiry -62135596800`). So every entry made in the editor without an expiry is stored with ExpiryTime = year 1 instead of its creation time. Before the fix it was the commit time, as MOD-01.25 (D-01-4) and MOD-09.1 ask. It is invisible while Expires is off, and the reference CLI opens the file, but it is a card rule that the fix broke.
- Proof: driver test `v8_new_entry_without_expiry_gets_its_creation_time`: `V8 saved: expires false expiry Time(0) creation Time(63928788669)`; the reference CLI's export of the F-060 vault shows the entry made in App with `Expires False -62135596800` (year 1).
- Smallest fix: in `commit_edit`'s new-entry branch, run the `change_entry` only when `expires` is true. Tried in the copy: `v1` (expiry 1,900,000,000 and a preset both kept) and `v8` pass; restored, `cmp` equal. Add `v8` as a test.

### Failure 1 (expiry kept): holds

`v1_mod01_every_field_round_trips`: `V1 new entry expiry after reopen: expires true expiry 1900000000`; a preset on a second new entry is kept (`preset 1793796509 kept`). The reference CLI export shows `Verify Title Expires True 1900000000`, `Verify Preset Expires True`. Mutation: the `change_entry` block removed → `v1` FAILED. Every other listed MOD-01 field still reads back equal.

### Failure 2 (F-060, with LD-207): holds

`v7_f060_ld207_protected_standard_fields_on_every_view` runs on a demo vault with ProtectTitle, ProtectUserName, ProtectURL and ProtectNotes on. Output:
- **Read entry:** rows, detail and editor carry none of the values; `show_draft_field` gives 5 values (Title, UserName, URL, Notes, `KP2A_URL`); Password, `otp`, `TOTP Seed` and the passkey field are refused.
- **Earlier version:** title, user and URL come empty and are named in `protected`; `show_version_field` gives them; password, `otp` and passkey are refused.
- **Entry made in App** (own flags off, vault flags on): the draft, rows, search, detail, editor and earlier version carry none of the values; Show gives them.
- **After save and reopen:** all four fields are written protected (FMT-11.20) and the views carry none.
- **The Personal vault with ProtectUserName on:** GitHub's user name is masked in rows, detail, editor and version, and an entry made in App is masked; titles still show. The passkey's own user name (an INT-04 field the vault flag does not cover) still shows in `PasskeyView`, which is correct under LD-207.
- **Mutations:** `is_protected` with the own flag only → `v7` FAILED; `protected_texts` empty → `v7` FAILED (each restored, `cmp` equal).
- **Swift `protectedWalk`:** `rows and detail: none; editor opened: none; Show user name: 1 found; Hide user name: none; typed (shown as typed): 1 found; saved: rows, detail: none; editor again: none; earlier version sheet: none; Show again: 1 found; lock: none`.
- The reference CLI reads the App-made entry's four fields with `ProtectInMemory="True"`.

F-060 marked verified.

### Item 3 (LD-205): closed by decision

LD-205 moves the controls to W-11. `v6_ld205_colours_and_exclusion_kept`: `#GG0000`, `RED` and the exclusion are kept after a Title edit and a save, with 1 history item.

### Checks re-run: unchanged

- **Secrets:** `v2` passes (no secret in the editor views; pages locked; draft wiped on lock; QR 61×61 and 53×53 of 0 and 1). The Swift walk gives the same 17 steps as the first pass ("none" after Hide, entry change, both vault switches, the sheets closing, discard and lock; the positive controls found).
- **Saving:** `v3_safe_save_and_failed_saves` and `v3_concurrent_saves…` pass (12 rounds, 0 left unsaved).
- **Attachments:** `v4_attachment_copies` and `v4_save_refuses_path_tricks` pass.
- **LD-139 and LD-170 (4):** `v5_ld139…` and `v5_ld170…` pass.
- **app-ffi suite:** all passed (lib 43, clipboard 9, edit 18, generator 12, key_pages 2, memory 1, messages 7, option_a 8, reports 2, session 11, ssh 10, my driver 10).
- **Xcode:** `✔ Test run with 127 tests in 21 suites passed after 72.895 seconds`; the general-pasteboard check passed.
- **Parity:** editor 9/9, dialogs 12/12 (dialogs-ssh-key-use now built), states 15/15; 75 Parity behaviour tests passed. The shared `ocr.swift` runs (100 images).

### Note, not blocking

The masked standard fields switch to "shown as typed" when the user types in them (`EditorModel.set`); real typing focus with a key window is for Mac QA.

### Commands (copy /tmp/e5s5r/tree, deleted afterwards)

`scripts/build-core.sh`; `TMPDIR=/tmp/e5s5r/tmpdir cargo test -p app-ffi --test verify_e5s5 -- --test-threads=1 --nocapture` (10 of 10 before `v8` was added; `v8` FAILED, R1); `cargo test -p app-ffi`; the 3 mutations above; the reference CLI 2.7.11 `export -f xml` with a throwaway HOME on /tmp copies; the xcodebuild step above; `export-reference.mjs`, `mockup-dom.mjs editor,dialogs,states`, `ocr.swift`, `compare.mjs editor|dialogs|states`. CPU for the re-check: about 20 CPU-minutes (build-core 8 CPU-minutes the largest); no run over 2 minutes of wall time.

## R1 re-check and sign-off (2026-10-28, 13:57 copy)

**Verdict: signed.** The fix in `commit_edit`'s new-entry branch copies the draft's expiry onto the entry only when `expires` is on.

- Driver `v1_v8_new_entry_expiry` (private copy):
  - `R1 set (true, 1900000000, false)`
  - `preset (true, 1793797246, …) (want 1793797246)`
  - `none (false, 1793192446, true)`: ExpiryTime equals the creation time.
  - `ticked-unticked (false, 1793192446, true)`
- The reference CLI 2.7.11 (`export -f xml`, throwaway HOME) reads the same vault the same way:
  - `Set expiry Expires True 1900000000`
  - `Preset Expires True 1793797246`
  - `No expiry Expires False ExpiryTime 1793192446 Creation 1793192446`
- Mutation (guard undone to `if true`): `mod_09_1_a_new_entry_without_expiry_keeps_the_creation_time` FAILED and `v1_v8_new_entry_expiry` FAILED (`none (false, -62135596800, false)`). Restored; `cmp` equal.
- `cargo test -p app-ffi`: 148 passed, 0 failed. This includes `mod_09_10_a_new_entry_keeps_the_expiry_set_in_the_editor` and `mod_09_1_a_new_entry_without_expiry_keeps_the_creation_time`.
- The change is Rust only and one guard. The 13:45 re-check above (F-060 with LD-207, LD-205, secrets, saving, attachments, LD-139, LD-170 (4), Swift 127 of 127, parity editor 9/9, dialogs 12/12, states 15/15) stands.
- Left for E5-S12 Mac QA, with the owner's go:
  - real key-window focus and the focus ring;
  - secure input in the password and one-time secret fields;
  - real drags onto the three drop targets;
  - the attachment watch (MOD-05.13);
  - Open handing the copy to a real default app;
  - typing focus in a masked standard field.
- CPU: about 6 CPU-minutes.
