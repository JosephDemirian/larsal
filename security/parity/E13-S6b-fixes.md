# E13-S6 part b: re-test of F-063, F-066, F-067, F-070, F-071, F-035, F-047

Story: E13-S6 part b ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Earlier proof: [E13-S5 two-person review](E13-S5-two-person-review.md) (F-063 to F-071), [E13-S2 AT-I](E13-S2-AT-I.md) (F-I3, the F-047 race). Decisions: LD-70, LD-131, LD-193, LD-207, LD-209, LD-220.
Date: 2026-10-29 (the workflow's day; round 2 ran while the Mac clock read 2026-10-30, from 07:24 to about 07:50). Role: Verify, rounds 1 and 2 (two separate Verify agents). Neither found, built or checked these fixes.

## Round 2: result

| Finding | Result | One line |
|---|---|---|
| F-063 | **fixed, re-tested** (again) | Unchanged since round 1; its test passes and fails again with the check undone. |
| F-066 | **fixed, re-tested** | `app clip -b` on a Title-protected vault copies again and prints `Best match: /••••••.`; merge Modified, Conflict and Moved records are masked when either copy of the entry flags its Title. Each fix fails its test when undone. |
| F-067 | **fixed, re-tested** (again) | Unchanged since round 1; its test passes and fails again with `catch_unwind` removed. |
| F-070 | **fixed, re-tested** (again) | Unchanged since round 1; its test passes and fails again with the wipe undone. |
| F-071 | **fixed, re-tested** | The doc and MOD-08.31 now agree: "Remember my choice" only for a URL that is not protected and that resolving leaves as typed, so the hashed text is the exact command. Its one caller, app-ffi `auto_open::remember_key`, does that; its test fails when either condition is removed. |
| F-035 | **accepted by design** (lead, LD-226 (1)) | Behaviour re-confirmed; the reader is unchanged. |
| F-047 | **fixed, re-tested** | The F-I3 race, 5 rounds per binary. With the fix, the link reached the vault path in 4 rounds. Each time, the add whose rename moved it said "changed on disk while this command ran. Nothing was saved". No such add said "saved", and no "The file on disk is unchanged" came after a landing. With the post-rename check undone, the link landed in 5 of 5 rounds and the add that moved it said "New entry rN saved." each time. |

All seven rows re-tested. Six are fixed (F-063, F-066, F-067, F-070, F-071, F-047), and F-035 is accepted by the lead's ruling. Round 1's two failures (F-066, F-071) and Checker 1's findings 1 and 2 are closed.

## Round 2: setup

- **Shared tree, own target.** `CARGO_TARGET_DIR=/tmp/e13s6b-verify2-target cargo test --locked -p app-platform -p app-core -p app-hwkey -p app-crypto -p app-cli -p app-format`: exit 0 in 2 min 8 s, 73 `test result: ok`, 1,915 passed, 0 failed, 55 ignored. Every named test is `ok`: `macos::signals::tests::f_063_second_quit_guard_is_refused`, `f_066_clip_best_match_with_protected_titles`, `f_066_protected_titles_masked_in_messages_lists_and_paths`, `f_066_merge_records_mask_protected_titles`, `int10_29_f_best_match`, `f_067_a_panicking_sink_never_unwinds_into_iokit`, `t23_iokit_watch_starts_and_stops_without_a_key`, `f_070_unknown_type_private_bytes_are_wiped_on_drop`, `f_047_rename_stays_in_the_folder_it_checked`, `f_047_temp_swapped_after_the_check_fails_the_save`, `fmt_12_22_protected_metadata` and `fmt_10_7_attributes_not_by_local_name`.
- **app-ffi.** In the shared tree, app-ffi did not build at that moment: another story's edit in progress in app-sshagent gave `error[E0063]: missing field 'agent' in initializer of 'Record'`. That crate is not part b's. So app-ffi ran in the private copy, taken at 07:24 when that crate was whole: `cargo test --locked -p app-ffi --lib auto_open` gave 6 passed, `f_080_open_url_follows_mod_08_31` among them.
- **Private copy.** `rsync -a --exclude target --exclude app-shots` to `/tmp/e13s6b-verify2-copy`, with its own target `/tmp/e13s6b-verify2-copy-target`. Before any change I took SHA-1 sums of the 17 files under test, and the copy matched them. In the copy, every named test passes. My script (`mutate.py`) made each mutation with one exact replace that must match once, ran the test, put back the original bytes and checked them. At the end, `shasum -c` gave 0 mismatches in the copy and 0 in the shared tree, so no file under test changed during my run.
- **Lint.** In the copy, `cargo clippy --locked -p app-core -p app-cli -p app-platform -p app-hwkey -p app-crypto --all-targets -- -D warnings` found no issues, and `cargo fmt` on the same crates with `--check` gave exit 0.

## Round 2: F-063, a second quit guard

- **Steps.** The E13-S5 probe is now the test itself: make two guards, drop them in the order they were made, then read SIGTERM's action (signals.rs:288-311).
- **Before** (`if LIVE.swap(true, Ordering::SeqCst) && false {`): `f_063_second_quit_guard_is_refused ... FAILED`, "a second guard was made" (signals.rs:306), exit 101.
- **After:** `ok` in the shared tree and in the copy. The file is unchanged since round 1 (it was last changed 2026-10-29 20:55).

## Round 2: F-066, protected Titles in command line texts and merge records

- **What changed in round 2.** `find_paths` (commands.rs:522) now returns `(id, shown path)`. `clip -b` takes its single match with `entry(&s.vault, id)` and keeps the masked path only for its messages (commands.rs:690-713). `entry_conflict` uses `shown_title(te, mask || own_flag(e))` (merge.rs:870), and `entry_move` uses `shown_title(e, mask || own_flag(&moved))` (merge.rs:838), so either copy of the entry having the flag masks the record.
- **Steps (round 1's failing probe).** A demo vault `small_vault("Demo login")` with the vault's Title flag on, password `demo-pass-1`, and `Password` = `demo-secret-9`; run `app clip -b t.appvault Demo 0` on a private named pasteboard. `f_066_clip_best_match_with_protected_titles` (int10.rs:3008) runs exactly this through the real `app` binary.
- **Before** (m1, the round-1 lookup by the masked path put back: `Some(_) => find_entry(&s.vault, &path)...`): `f_066_clip_best_match_with_protected_titles ... FAILED`, `left: Some(1) right: Some(0)`, output `Best match: /••••••.` then `app: no entry at /••••••.`. That is the regression round 1 found.
- **After:** exit 0. The output starts `Best match: /••••••.`, neither stdout nor stderr holds "Demo login", and the private pasteboard holds `demo-secret-9`. `int10_29_f_best_match` (best match with the flag off) still passes.
- **Merge records, mixed flags (Checker 1's finding 2).** m2, where the Conflict record reads only the target's flag: `left: ["Alpha", "••••••", "••••••"] right: [mask; 3]` (mod11.rs:2416), FAILED. m3, where the Moved record reads only the source's flag: `left: ["Beta", "Gamma", "••••••"] right: ["Gamma", mask, mask]` (mod11.rs:2419), FAILED. With the fix the test passes.
- **Other places checked.** `search` prints the shown paths only. No other command looks an entry up again from a `find_paths` path; `find_entry` takes only paths that the user typed (commands.rs:100, 243, 423, 712, 823).
- **Left, not blocking.** The merge's "outside the shared group" Conflict record (merge.rs:779, `shown_title(e, mask)`) reads only the source copy's own flag. It shows the source's Title, so the target copy's own flag is not consulted. This happens only when neither vault has the flag and the target's copy carries its own Title flag, which only a crafted file can do (the builder's open issue). It is not part of F-066.

## Round 2: F-067, IOKit callbacks

- **Steps.** Call `arrived` and `removed` with a sink that panics (test-only feature `test-callbacks`, tests/watch.rs).
- **Before** (m8: `tell` calls `(watching.sink)(change);` with no `catch_unwind`): `f_067_a_panicking_sink_never_unwinds_into_iokit ... FAILED`, "demo sink panic" at tests/watch.rs:32, exit 101.
- **After:** `ok`, and `t23_iokit_watch_starts_and_stops_without_a_key` is `ok`. watch.rs is unchanged since round 1 (it was last changed 2026-10-29 20:58).

## Round 2: F-070, unknown SSH key types

- **Steps.** Parse an unprotected OpenSSH key of an unknown type with `OpenSshKey::parse`, then drop it under a probe allocator that counts freed blocks still holding the private bytes (tests/ssh_wipe.rs).
- **Before** (m9, `if false { self.0.zeroize(); }` in opaque.rs's `Drop`): "a freed block still held the private bytes", `left: 1 right: 0`, FAILED, exit 101.
- **After:** `ok`. opaque.rs and app-crypto ssh.rs are unchanged since round 1.

## Round 2: F-071, the remembered Yes key

- **What changed in round 2.** The `remember_key` doc (url.rs:613-620) and MOD-08.31 now say "Remember my choice" is offered only when the URL is not protected (its own flag or the vault's, LD-207) and resolving it changes nothing. The stored text is then the exact command, and every other command asks every time, with no box. This answers both points of round 1: the hash never covers a secret, and a sync that changes a field the command reads gets the question again (LD-70).
- **Caller.** A grep of crates and macos for `remember_key`, `remember_command`, `command_remembered` and `run_url_command`: the only product caller is app-ffi `auto_open.rs`. Its `remember_key` (line 256) gives `Some` only for `!is_protected(v, "URL", f) && f.value == full`. Line 175 looks up a remembered Yes with that key, and `remember: key.is_some()` shows the box. Line 244 stores a Yes only when the same key is `Some`, so `remember = true` from the screen is ignored for any other URL. No Swift file calls `runUrlCommand` yet.
- **Before** (in the copy): m10 drops the "resolving changes nothing" condition. `f_080_open_url_follows_mod_08_31` then FAILED at auto_open.rs:704, because row 39's command, `/usr/bin/touch …/{USERNAME}`, was offered with `remember: true`. m11 drops the protected-URL condition, and the test FAILED at auto_open.rs:663: row 33, a protected URL, was offered `remember: true`.
- **After:** `f_080_open_url_follows_mod_08_31 ... ok`. In it, a protected URL is never remembered, and row 39 asks again after `remember = true` and runs nothing after a reload changes its user name.

## Round 2: F-035, protected metadata values

- **Ruling.** Accepted by design: lead 2026-10-29, LD-226 (1).
- **Re-confirmed.** `fmt_12_22_protected_metadata` and `fmt_10_7_attributes_not_by_local_name` are `ok` in the shared run. `raw` (read.rs:1026-1042) still decodes a protected value into `Raw::Secret`; only the metadata model's plain copy is a `String`. Nothing in this part changed the reader.

## Round 2: F-047, rename inside the checked folder

- **What changed in round 2.** The check after the rename now gives `SaveError::ChangedOnDisk`, carrying the checksum of the file now at the vault path (storage.rs:599-609). `app` prints "... changed on disk while this command ran. Nothing was saved; run the command again." (vault.rs:360), and the window gets `Wrote::ChangedOnDisk`, which asks the APP-05.28 question (app-ffi saving.rs:487, 290). Backups and exports still map it to `Other` (storage.rs:696, 778). That checksum read uses `open_regular` (no blocking, regular files only), so a link to a pipe cannot make it wait.
- **Steps (F-I3, demo data).** Copy `testdata/password-only.appvault` to a fresh folder. My racer (`python3 -I racer.py`, started by the round script and stopped through a stop file and `wait` on its PID) waits a random 0 to 6 ms after each new App temp file appears (seeds 1 to 5). It then renames the temp file into `moved/` with a number and plants a link to `other/victim.txt` at its name. `app open X.appvault` gets `demo-pass-1` and then `add r1` to `add r300`. Each add prints one line, so line N belongs to `add rN`. App's in-memory vault keeps every add, so the last temp file the racer moved holds every entry up to the add whose rename put the link at the vault path. `app ls` on that file gives that add's number K, and line K is what App said about that save.
- **Two binaries,** both release builds from the copy: `app-fixed` (the tree as it is) and `app-check-off` (m5, `let landed: io::Result<()> = Ok(());`, the post-rename check off).
- **Before** (`app-check-off`), the link landed in 5 of 5 rounds:

  | Round | saved | could not save | changed on disk | Landing add (last moved temp) | Its line |
  |---|---|---|---|---|---|
  | 1 | 16 | 239 | 45 | r255 | `New entry r255 saved.` |
  | 2 | 6 | 33 | 261 | r39 | `New entry r39 saved.` |
  | 3 | 3 | 17 | 280 | r20 | `New entry r20 saved.` |
  | 4 | 1 | 18 | 281 | r19 | `New entry r19 saved.` |
  | 5 | 19 | 170 | 111 | r189 | `New entry r189 saved.` |

- **After** (`app-fixed`), the link landed in 4 of 5 rounds:

  | Round | saved | could not save | changed on disk | Landing add (last moved temp) | Its line |
  |---|---|---|---|---|---|
  | 1 | 5 | 36 | 259 | r42 | `app: X.appvault changed on disk while this command ran. Nothing was saved; run the command again.` |
  | 2 | 16 | 72 | 212 | r89 | the same |
  | 3 | 12 | 201 | 87 | r214 | the same |
  | 4 | 24 | 276 | 0 | none: the vault path stays App's file, holding up to r292, the last "saved" line | every "could not save" is true |
  | 5 | 0 | 3 | 297 | r4 | the same as round 1 |

  Every "could not save ... The file on disk is unchanged." line comes before the landing line: the last one is at line 40, 88, 213 and 3, against the first "changed on disk" at line 42, 89, 214 and 4. So none of them is false any more (Checker 1's finding 1, which round 1 left open). In all 10 rounds `victim.txt` kept its SHA-1, so nothing was written through a link.
- **Tests and mutations** (copy): m4 (the post-rename check gives `write_err` again, as in round 1) makes `f_047_temp_swapped_after_the_check_fails_the_save` FAIL with `left: Err(Write { kind: Other, kept_temp: None })` and `right: Err(ChangedOnDisk(Checksum { len: 7, .. }))`. m5 (the check off) makes it FAIL with `left: Ok(SaveReport ..)`. m6 (`fs::rename(&temp, target)` by path) makes `f_047_rename_stays_in_the_folder_it_checked` FAIL at app05.rs:1391 with `Err(ChangedOnDisk(..))`. Each run exited 101.
- **Left, not blocking.** (1) An SMB share is still untested: nothing may leave this Mac, so it needs Mac QA (owner's go). (2) plan/security.md SD-01 ("residual rename window F-047 until E6") and security/parity/SD-01-SD-02-SD-03-SD-09.md ("F-047 (accepted until E6)") still describe the old state. LD-131 is updated; the other two are not my files, so they are left to their owner. (3) `folder.rs` changed after round 1 (2026-10-30 00:13, for another story). The F-047 tests above pass against it. The second review of its `fstatat` and `renameat` blocks (Rust rule 2) is not part of this re-test.

## Round 2: cleanup

The probes and mutations ran only in `/tmp/e13s6b-verify2-copy`, with their own target. Every file was put back and checked with `shasum -c`. The racers were mine; each was stopped by its stop file and `wait` on its PID. `/tmp/e13s6b-verify2-*` and the test folders that my failing mutants left in the user temp folder are deleted.

## Round 1: result

| Finding | Result | One line |
|---|---|---|
| F-063 | **fixed, re-tested** | A second `catch_quit()` is refused; the E13-S5 probe now prints `note=false dfl=true` (with the check undone: `note=true dfl=false`). |
| F-066 | **re-test failed** | Every message, list, path and merge record is masked, but the fix breaks `app clip -b` on a vault whose Title flag is on: it prints `Best match: /••••••.`, then `app: no entry at /••••••.`, exit 1, nothing copied. Before the fix it copied. |
| F-067 | **fixed, re-tested** | `# Safety` sections on both callbacks; a panicking sink stays inside `catch_unwind`. |
| F-070 | **fixed, re-tested** | 0 freed blocks hold the private bytes of an unknown key type after parse and drop; 1 with the wipe undone. The vendor diff holds only LD-209 changes 1 to 3. |
| F-071 | **re-test failed** | The new doc rule (key on the stored URL text, never the resolved command) contradicts MOD-08.31 and LD-70 and opens the hole LD-70 closes: a remembered Yes would still cover the command after a sync changes a field its placeholder reads. |
| F-035 | not fixed; **accept** (lead to rule) | Behaviour re-confirmed as the row says. I agree with the proposal to accept it; reason below. |
| F-047 | **fixed, re-tested** | The F-I3 race: with the fix, the save that puts the attacker's link at the vault path reports "could not save"; with the post-rename check undone, the same race reports "New entry rN saved." (5 of 5 rounds; the link landed in all 5). |

Four rows re-tested as fixed (F-063, F-067, F-070, F-047); F-035 re-confirmed for the lead's ruling; two failed (F-066, F-071).

## Round 1: setup

- Shared tree, own target: `CARGO_TARGET_DIR=/tmp/e13s6b-verify-target cargo test --locked -p app-platform -p app-core -p app-hwkey -p app-crypto -p app-cli`: exit 0, 53 `test result: ok`, 0 FAILED (2 min 31 s). The eight named tests all `ok`: `macos::signals::tests::f_063_second_quit_guard_is_refused`, `f_066_protected_titles_masked_in_messages_lists_and_paths`, `f_066_merge_records_mask_protected_titles`, `f_067_a_panicking_sink_never_unwinds_into_iokit`, `t23_iokit_watch_starts_and_stops_without_a_key`, `f_070_unknown_type_private_bytes_are_wiped_on_drop`, `f_047_rename_stays_in_the_folder_it_checked`, `f_047_temp_swapped_after_the_check_fails_the_save`.
- Private copy for every probe and mutation: `rsync -a --exclude target --exclude app-shots` to `/tmp/e13s6b-verify-copy`, target `/tmp/e13s6b-verify-copy-target`. Baseline in the copy: all named tests pass. Each mutation was applied with an exact one-place replace, its test run, then the file restored and compared with `cmp` against the shared tree's file.
- Other agents edited the shared tree during this run (app-cli `commands.rs` line 1037, `settings::tune(.., &mut host, ..)` at 21:49; app-platform `macos/mod.rs` `pub mod keyboard;` at 21:52). Neither touches part b's fixes; my shared-tree run and the copy predate them. Later (21:58 to 22:14) other stories' fixes (F-089, F-101, F-110) changed app-core `storage.rs`, app-platform `folder.rs` and the app05 and mod11 tests in the shared tree; `is_file_in`, `rename_in`, both `ours_in` checks and the post-rename check are unchanged, and a re-run on that tree, `cargo test --locked -p app-core --test app05 -- f_047`, gave 2 passed.

## Round 1, F-063: a second quit guard

- **Steps (E13-S5 probe):** in a private-copy test, reset the quit signals, make two guards with `catch_quit()`, drop them in creation order, read SIGTERM's action.
- **Before** (fix undone, `if LIVE.swap(..) && false`): `VERIFY second_ok=true note=true dfl=false`, the `note` handler stays for good; `f_063_second_quit_guard_is_refused ... FAILED` with "a second guard was made" (signals.rs:306), test exit 101.
- **After:** `VERIFY second_ok=false note=false dfl=true`; `f_063_second_quit_guard_is_refused ... ok`.
- **Callers:** app-ffi `cli.rs:235` and app-cli `term.rs:176` take `echo_off(..).ok()`, app-cli `commands.rs:732` takes `catch_quit().ok()`; `echo_off` gets its guard from `catch_quit()` (terminal.rs:42). A refused guard means a second, overlapping prompt would read with echo on; no caller overlaps today (the builder's open issue; I agree it is not reachable).

## Round 1, F-066: protected Titles in command line texts and merge records

- **Steps:** demo vault `small_vault("Demo login")` with `meta.memory_protection.title = true`, password `demo-pass-1`; run `ls -R`, `search`, `edit`, `add`, `mv`, `rm`, `merge`, and `clip -b`.
- **Before** (masking undone in the copy): `vault::title` returning `e.value("Title")`: `f_066_protected_titles_... FAILED` (int10.rs:2997); the `ls` list unmasked: FAILED; the `add` message unmasked: FAILED; every merge record unmasked: `case 0 left: ["Alpha", "Beta", "Gamma", "Delta"] right: ["••••••" x4]`, FAILED.
- **After:** both F-066 tests pass; messages, lists, paths and records show `••••••`.
- **Re-test failed, a regression of the fix:** `clip -b` (INT-10.29, M10-67) takes the path that `find_paths` returns and looks the entry up by it again (commands.rs:690-706: `path.clone_from(one)`, then `find_entry(&s.vault, &path)`). `find_paths` now returns masked paths, so the lookup compares `/••••••` with the real Title and finds nothing. Throwaway probe in the copy (`clip -b t.appvault Demo 0`, `APP_TEST_PASTEBOARD=1`, a private named pasteboard, never the general one):
  - fixed tree, flag off: `code=Some(0) items=1 out="Best match: /Demo login.\nPassword of /Demo login copied. ..."`
  - fixed tree, flag on: `code=Some(1) items=0 out="Best match: /••••••.\n" err="... app: no entry at /••••••.\n"`
  - fix undone (`vault::title` = raw Title), flag on: `code=Some(0) items=1 out="Best match: /Demo login.\nPassword of /Demo login copied. ..."`
  So `clip -b` worked before the fix and fails after it whenever the vault protects Titles. No test covers `clip -b` with the flag on.
- **Smallest fix:** let `find_paths` return the entry ids with the shown paths (or keep the ids from `search::run`) and, in `clip -b`'s one-match arm, take the entry by its id; keep the masked path only for the messages. Add a test: `clip -b` on a Title-protected vault copies to the private pasteboard and prints `Best match: /••••••.`
- **Also, while it is open (Checker 1's note, not blocking alone):** the Modified and Conflict record (`entry_conflict`, `shown_title(te, ..)`) reads only the target entry's own flag; a crafted source entry with its own Title flag, in vaults with neither vault flag, gets a plain record. Mask when either entry's own flag is set.

## Round 1, F-067: IOKit callbacks

- **Steps:** read `arrived` and `removed` (crates/app-hwkey/src/usb/watch.rs); call both as IOKit does with a sink that panics (test-only feature `test-callbacks`).
- **Before** (`tell` without `catch_unwind`): `f_067_a_panicking_sink_never_unwinds_into_iokit ... FAILED`, "demo sink panic" escapes at tests/watch.rs:32, exit 101.
- **After:** both callbacks have `# Safety` sections; `tell` wraps the sink in `catch_unwind`; the test and `t23_iokit_watch_starts_and_stops_without_a_key` pass.

## Round 1, F-070: unknown SSH key types

- **Steps:** an unprotected OpenSSH key of an unknown type (`demo-unknown@example.com`) whose private bytes are a marker, parsed with `OpenSshKey::parse` and dropped under a probe allocator that counts freed blocks holding the marker (no freed memory is read).
- **Before** (`self.0.zeroize()` under `if false`): `left: 1 right: 0`, "a freed block still held the private bytes", FAILED, exit 101.
- **After:** 0 such blocks; the test passes.
- **Vendor diff:** `diff -rq` of the registry `ssh-key-0.7.0-rc.11/src` against `vendor/ssh-key/src`: only `lib.rs`, `private/ecdsa.rs` and `private/opaque.rs` differ; `opaque.rs` adds only `use zeroize::Zeroize;` and the marked `Drop` impl (LD-209 change 3). The crate's DSA, Ed25519 and RSA private key types have the same kind of `Drop` (dsa.rs:104, ed25519.rs:96, rsa.rs:91).

## Round 1, F-071: the remembered Yes key

- **Steps:** read `url::remember_key` and its doc (crates/app-core/src/url.rs); grep callers in crates and macos.
- **Before:** an unsalted SHA-256 of "the exact command"; wired with the resolved command, the settings file would hold an offline-guessable hash of a value that may hold a password.
- **After:** doc only. No caller outside url.rs and app-core tests/mod08.rs:1057-1058 (grep), so nothing to run.
- **Re-test failed.** The new rule says `command` is the stored URL text, "never the resolved command". MOD-08.31 says the command is the resolved text and the Yes is remembered for "this vault, entry id and exact command text"; LD-70 exists because "anyone who can change the vault (sync, shared group, import) could otherwise make one click run a program". Keyed on the stored text, a remembered Yes for `cmd://{S:Tool}` or `cmd://{USERNAME}` keeps running after a sync changes that field, so a changed command no longer asks again. The doc and the card now disagree, and the future MOD-08.31 caller would follow the doc into LD-70's hole.
- **Smallest fix (text, no caller yet):** add to the doc and to MOD-08.31 (or an LD): "Remember my choice" is offered only when resolving the URL changes nothing (the stored text is the exact command) and the URL is not protected; any other command asks every time. Then the stored text, the resolved command and the hashed text are one and the same, and none of it is a protected value. The other option of the E13-S5 review, an HMAC of the resolved command under a per-install key, also closes it but needs code and a key store.

## Round 1, F-035: protected metadata values

- **Steps:** `cargo test -p app-format --test document_read -- fmt_12_22_protected_metadata fmt_10_7_attributes_not_by_local_name` (copy): both `ok`. A crafted document with `<DatabaseName Protected="True">` and `<DatabaseDescription Protected="True">` reads as `meta.name` / `meta.description` = "Secret" in plain `String` fields (app-model vault.rs:68-76).
- **Before / after:** unchanged; the builder did not change the reader.
- **Ruling proposed: accept.** `raw` decrypts the protected bytes in a `SecretBytes` (read.rs:1026-1041) and only then makes the plain copy; App's writer marks only entry fields protected (write.rs:535-542, the only caller of its `protected` writer), so only a crafted file triggers it; metadata values are plain by design (window title, lists, menus) in App's model and the reference's; the plain copy is freed through the zeroing allocator of every product binary (LD-193). A secret type in `app_model::Meta` would protect a value App itself shows on screen. Lead to rule; the row stays open until then.

## Round 1, F-047: rename inside the checked folder

- **Steps (F-I3, demo data):** copy `testdata/password-only.appvault` to a folder; a racer (`python3 -I racer.py`, started and stopped by me) renames every new `*.tmp` there away and puts a symbolic link to `other/victim.txt` at its name; feed `app open X.appvault` the password `demo-pass-1` and 300 `add rN` lines. Two binaries from the private copy: `app-fixed` and `app-f047b-undone` (post-rename check off). For each round: the counts, whether the vault path ends as a link, and the line just before the first "changed on disk".
- **Before** (`app-f047b-undone`): round 1: saved 12, could not save 68, changed on disk 220, vault path a link; the line before the first "changed on disk" is `New entry r80 saved.` Round 2: saved 1, could not save 4, changed on disk 295, link; the line before is `New entry r5 saved.` Rounds 3 to 5: the link landed each time and the line before is `New entry r101 saved.`, `New entry r60 saved.`, `New entry r27 saved.` That is the red team's F-I3 symptom ("New entry r256 saved."), 5 of 5 rounds.
- **After** (`app-fixed`): round 1: saved 5, could not save 255, changed on disk 40, link; the line before is `app: could not save .../X.appvault: other error. The file on disk is unchanged.` Round 2: saved 31, could not save 69, changed on disk 200, link; the line before is the same "could not save". Rounds 3 to 5: the link never reached the vault path (saved 5/0/36, every other add refused by the LD-131 check). In every round of both binaries `victim.txt` kept its SHA-1: nothing was written through a link.
- **Tests and mutations:** `fs::rename(&temp, target)` in place of `rename_in`: `f_047_rename_stays_in_the_folder_it_checked` FAILED (app05.rs:1339); the post-rename check off: `f_047_temp_swapped_after_the_check_fails_the_save` FAILED (`left: Ok(SaveReport ..) right: Err(Write { kind: Other, .. })`).
- **Unsafe:** `folder.rs` `is_file_in` (`fstatat`, `AT_SYMLINK_NOFOLLOW`, `assume_init` only after a 0 return) and `rename_in` (`renameat` on one borrowed descriptor, names live across the call): sound in my reading; the two-person review of Rust rule 2 still needs its second reviewer.
- **Left, not blocking:** (1) after an attacker's link lands, the message says "The file on disk is unchanged", which is false (Checker 1's finding 1); the next command says "changed on disk", and App never says "saved". A distinct error text, or a line in the row, closes it. (2) The check after the rename assumes a file keeps its device and inode across a rename in one folder; Checker 1 saw it hold on APFS, HFS+, exFAT and FAT disk images. An SMB share could not be tried here (nothing leaves this Mac): needs Mac QA (owner's go). (3) plan/security.md SD-01 ("residual rename window F-047 until E6") and SD-01-SD-02-SD-03-SD-09.md ("F-047 (accepted until E6)") still describe the old state; not my files.

## Round 1: cleanup

Probes and mutations ran only in `/tmp/e13s6b-verify-copy`; every product file there was restored and compared with `cmp`. The racer processes were mine, started in the race script and ended by their stop file (`wait` on their PID). `/tmp/e13s6b-verify-*` deleted at the end.
