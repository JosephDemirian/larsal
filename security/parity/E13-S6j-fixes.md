# E13-S6 part j: Rust security follow-ups (F-123, F-124, F-128, F-129, the F-066 edge case, folder.rs unsafe review)

Story: E13-S6 part j ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Rulings: LD-228 (3) (F-123, F-124), LD-238 (1) (F-128), LD-238 (2) (F-129), LD-227 (4) (folder.rs unsafe review, the optional change to `keep_file_info`). LD-240 (1) (the F-066 edge case), (2) (the second review of the newer folder.rs blocks) and (5) (part j is these follow-ups only).
Date: 2026-10-30, by the Mac's clock. Role: Builder. I did not find these problems. Clean room: Larsal's own code only; I did not open the reference source.

| Item | Result | One line |
|---|---|---|
| F-123 (Medium) | fixed, re-tested (Verify 2026-10-29) | `check_writable` uses storage's probe (a random name made with create_new) and `open_regular`. The settings load uses `open_regular` too. A planted link is never followed, and a FIFO is refused at once. |
| F-124 (Low) | fixed, re-tested (Verify 2026-10-29) | `ResourceBusy` no longer counts toward APP-05.14. |
| F-128 (Low) | fixed (round 2 after Checker 1), re-tested (Verify 2026-10-29) | `run_url_command` gets the question's text and clock. It resolves the entry on that clock and runs and keeps nothing unless the command still reads that way. Swift asks again on false, and false means only that. |
| F-129 (Low) | fixed, re-tested (Verify 2026-10-29) | `refs::Resolved::masked` is set when the mask is put in. `resolve_field` (URL, key file paths) uses that flag instead of comparing texts. |
| F-066 edge case | fixed, re-tested (Verify 2026-10-29) | The "outside the shared group" Conflict record masks the Title when either copy flags it. |
| folder.rs unsafe | second review done; one observation fixed; the reshaped blocks reviewed by Checker 1 and Verify | 6 blocks reviewed (the F-089 four, fstatat, renameat), plus `open_regular` (safe code). All are sound. The creation date reply length was unchecked; that is fixed. The optional "each part on its own" change is made. |

## Code changes

| File | Change |
|---|---|
| crates/larsal-ffi/src/larsal_settings.rs | `check_writable`: makes the folder, then `larsal_core::storage::is_writable(path)` and `open_regular(path)` for an existing file. `read_json` opens with `open_regular`. The unused `OpenOptions` and `OpenOptionsExt` imports are gone. Test `f_123_check_writable_follows_no_planted_link_or_fifo`. |
| crates/larsal-core/src/storage.rs | `Failures::failed`: `ErrorKind::ResourceBusy` added to the kinds that do not count, and the doc says why. |
| crates/larsal-core/tests/app05.rs | `app05_14_repeated_failures` now counts `NotFound` (a missing folder, as in F-087's test). New `f_124_a_busy_vault_file_does_not_count`. |
| crates/larsal-core/src/refs.rs | `Resolved::masked`, and `Run::mask()`, the one place that copies the mask: `{S:…}`, `field_step` (standard fields, references, `{URL:…}`) and `{TOTP}`. |
| crates/larsal-core/src/auto_open.rs | `resolve_field` returns the display run's `masked` flag; the text compare and its `ponytail` note are gone. A small edit in a part b file: this is the one function that url_of, the vault link's key file path and auto-open all call, so it is the root fix. |
| crates/larsal-core/tests/mod08.rs | New `f_129_masked_marks_every_mask`. |
| crates/larsal-ffi/src/auto_open.rs | `run_url_command(vault, entry, command, at, remember)` (round 2: `at`, and true also when the program did not start); `UrlAction::Ask` carries `at`; `url_of` takes the time; `run_command` returns nothing. Three existing calls in `f_080_open_url_follows_mod_08_31` now pass the shown text. New tests `f_128_…` and `f_129_…`. |
| crates/larsal-ffi/API.md | The `run_url_command` row: new argument and the F-128 rule. A small edit in a part a file, needed because the signature changed. |
| macos/Larsal/OpenURL.swift | `ask(...)` passes `command:` and the question's clock (`at:`, round 2) and calls `openURL(entry:)` again when the answer is false. |
| crates/larsal-core/src/merge.rs | `entry()`'s Outside branch: `shown_title(e, self.mask_titles \|\| <target copy's own flag>)`. |
| crates/larsal-core/tests/mod11.rs | New `f_066_outside_the_shared_group_record_masks_either_flag`. |
| crates/larsal-platform/src/macos/folder.rs | `keep_file_info` is split into `creation_date`, `tags` and `acl`. Each runs on its own, and the first error comes back at the end. The creation date reply's length is checked. The source is opened with `O_NOCTTY` as well. New unit test `f_089_each_part_is_copied_on_its_own`. |

Before and after, F-066 (merge.rs, `entry()`, Outside branch):

```
before: let title = shown_title(e, self.mask_titles);   // source copy's own flag only
after:  let theirs = self.ix.entry_mut(&mut self.t.root, e.uuid);
        let title = shown_title(e, self.mask_titles || theirs.is_some_and(|t| own_flag(t)));
```

## Tests that fail with the fix undone (private copy)

Copy: `rsync -a --delete --exclude target --exclude larsal-shots --exclude fuzz/target` to `/tmp/e13s6j-builder-copy`, with its own `CARGO_TARGET_DIR=/tmp/e13s6j-builder-mtarget`. A script applied one mutant at a time, ran the named test, then put the file back with a fresh mtime. All 10 runs exited 101.

| Mutant | Test | Failed at |
|---|---|---|
| M1: the fixed-name probe with create and truncate back in `check_writable` | `f_123_check_writable_follows_no_planted_link_or_fifo` | the demo file check (emptied through the link) |
| M2: the append open of settings.json back | same | `expect("answered at once")` after 5.01 s (the open waits on the FIFO) |
| M3: `fs::File::open` back in `read_json` | same | `expect("answered at once")` after 5.00 s (load waits on the FIFO) |
| M4: `ResourceBusy` removed from the kinds that do not count | `f_124_a_busy_vault_file_does_not_count` | app05.rs:426, the third busy failure asks |
| M5: the question-text compare off | `f_128_a_command_changed_after_the_question_does_not_run` | auto_open.rs:764, `assert!(!ran)`: the swapped command ran |
| M6: the text compare back in `resolve_field` | `f_129_a_transform_cannot_pass_a_protected_value_as_plain` | auto_open.rs:816, row 60 opened `https://example.com/?p=six` |
| M7: `mask()` does not set the flag | mod08 `f_129_masked_marks_every_mask` | mod08.rs:1639 |
| M7b: same mutant | larsal-ffi `f_129_…` | auto_open.rs:816 |
| M8: the Outside record reads the source's flag only | `f_066_outside_the_shared_group_record_masks_either_flag` | mod11.rs:2456, `record(true, false)` gave `["Alpha"]` |
| M9: `keep_file_info` returns at the first error (the old shape) | `f_089_each_part_is_copied_on_its_own` | folder.rs:236, the access list was not copied |

The baseline in the copy passed before the mutants: `f_123`, `f_128` and `f_129` all ok.

## Checks in the shared tree (own target `/tmp/e13s6j-builder-target`)

- `cargo build --locked --workspace --all-targets`: Finished.
- `cargo test --locked --no-fail-fast -p larsal-core -p larsal-platform -p larsal-ffi`: 1,039 passed, 34 ignored, 0 failed (49 suites).
- The named tests, each `ok`: `larsal_settings::tests::f_123_check_writable_follows_no_planted_link_or_fifo`, `auto_open::tests::f_128_a_command_changed_after_the_question_does_not_run`, `auto_open::tests::f_129_a_transform_cannot_pass_a_protected_value_as_plain`, `auto_open::tests::f_080_open_url_follows_mod_08_31`, `auto_open::tests::f_080_a_key_file_path_holding_a_secret_is_not_kept`, app05 `f_124_a_busy_vault_file_does_not_count`, `app05_14_repeated_failures` and `f_089_safe_save_keeps_creation_date_tags_and_acl`, mod08 `f_129_masked_marks_every_mask`, mod11 `f_066_outside_the_shared_group_record_masks_either_flag` and `f_066_merge_records_mask_protected_titles`, larsal-platform `macos::folder::tests::f_089_each_part_is_copied_on_its_own`.
- `cargo clippy --locked -p larsal-core -p larsal-platform -p larsal-ffi --all-targets -- -D warnings`: no issues. The same with `-p larsal-platform --features net`, and with `--features appkit,memory,test-memory,test-signals -- -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment`: no issues. `-p larsal-ffi --test app09`: no issues.
- `cargo fmt --check`: exit 0. `scripts/check-names.sh`: `names: PASS (3194 files scanned, 16 vault files name-only)`.
- Swift: see the next section.

## Swift (private copy, re-synced from the tree at about 08:00)

- `scripts/build-core.sh` (`CARGO_TARGET_DIR=/tmp/e13s6j-builder-mtarget`) finished. The generated binding reads `func runUrlCommand(vault: UInt64, entry: String, command: String, remember: Bool) throws -> Bool`.
- `swift format lint --strict Larsal/OpenURL.swift`: exit 0. `swiftlint lint --strict --quiet Larsal/OpenURL.swift` (0.65.1, `DEVELOPER_DIR` set): exit 0.
- `xcodebuild … -derivedDataPath /tmp/e13s6j-builder-dd test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: the build succeeded, so OpenURL.swift compiles against the new binding with warnings as errors. 319 tests in 45 suites ran, with 8 issues in 4 tests. None of them is about OpenURL.
- I re-ran the 4 suites alone (`test-without-building -only-testing:` ProtectedUndoTests, ParitySavingTests, MenuKeysTests, ParityEditorPagesTests): 47 tests, and only ProtectedUndoTests "F-127 …" fails (4 cases, ProtectedUndoTests.swift:62). That file and LockLeaveTests.swift were being edited by part i during my run (mtimes 08:08 and 08:11), so part i owns that test. LD-228 (1), APP-08.14 and "Parity dialogs-delete-forever" pass when run alone; they failed only under load.
- No LarsalTest drives MSG-08-2 (a modal alert), as part f also noted. The rule rests on Rust (`f_128_…`). Seeing the question come back after a sync needs Mac QA (owner's go, W-08).

## F-123 (Medium)

- **Root.** The probe had a fixed name and was opened with create and truncate, so it followed a link planted there. Settings.json was opened with `append`, which waits on a FIFO. The load at `use_folder` opened settings.json with a blocking `File::open` as well. That is the same vector, and it would stop Larsal at start, so I fixed it in the same file.
- **Callers.** `check_writable` is called by the Swift settings screen (APP-01.12). `read_json` is called only by `load`. `storage::is_writable` is already used for vaults (APP-05.18), and the settings check now uses the same probe.
- **Test steps.** A demo file `victim.txt` ('victim, demo text'), with a link at `.larsal-settings-check` pointing at it. `store(dir).check_writable()` gives `None`, the file keeps its text, and the link stays. Then `/usr/bin/mkfifo settings.json`; a new store loads and checks on a worker thread. The answer comes within 5 s and names `settings.json`.
- **Behaviour change.** An existing settings file now needs a write bit and must be a regular file that can be read. The old check also wanted append access. The settings write (F-111, `write_export`) replaces the file in its folder, so folder access is what it needs, and the probe checks exactly that.

## F-124 (Low)

`Failures::failed` no longer counts `ResourceBusy` (F-110's lock held past the wait), so it never offers MSG-SAVE-UNSAFE-ASK for it. The unsafe methods take the same lock and could not help.

## F-128 (Low)

- `run_url_command` resolves the entry again, on the question's clock (`UrlAction::Ask`'s `at`, round 2). It goes on only when `url::question_text(<display resolution>)` equals the `command` the question showed. Otherwise it returns `Ok(false)` and runs and keeps nothing. Once it goes on it returns `Ok(true)`, also when the program did not start.
- Swift (OpenURL.swift `ask`): `let ran = try? session.runUrlCommand(vault:entry:command:at:remember:)`; `if ran == false { openURL(entry:) }`. The question then comes back with the current command.
- **Limits, by design.**
  1. The question shows at most 400 characters. A change after character 400 of a longer command passes the compare, but the user never saw that part either.
  2. A protected URL shows as `******`. A sync that changes it while the question is open still runs the new hidden command, but the user agreed to run a hidden one. Neither case can be remembered (F-071).
  3. A program that does not start says nothing, as before part j (MOD-08.31 names no message for it). `false` never means that, so the question does not come back for it (round 2).
  4. The command runs as resolved on the question's clock. A date or one-time code is the one shown, even when Yes comes minutes later.

## F-129 (Low)

- `Resolved::masked` is true when the display resolution put the mask in for a protected value. `{S:…}`, every `field_step` (which covers references `{REF:…}` and `{URL:…}`) and `{TOTP}` all go through the one helper `Run::mask()`.
- `resolve_field` returns `(full, shown.text, shown.masked)`. Without masks, the display run and the full run take the same steps, because `display` changes only `masked()` and the `{TOTP}` branch. So the flag alone is exact, and no text compare is needed.
- **Test steps.** Protected Password `demo-s`, URL `https://example.com/?p={T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}`. Open gives MSG-08-4; before the fix it gave `Open { url: "https://example.com/?p=six" }`. A vault link whose user name is `{T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}.larsalkey`: B's message does not name `six.larsalkey`, and no key file is kept while S-START-08 is on. mod08 checks the flag for the probe, `{S:Pin}`, `{PASSWORD}`, `{REF:P@I:…}` and `{TOTP}`: true with display on, false with display off, and false for `{USERNAME} {TITLE} {S:Nope}`.

## F-066 edge case

`Merger::entry`'s Outside branch now looks up the target copy (`self.ix.entry_mut`) and masks the record's Title when either copy flags its own Title, as `entry_move` and `entry_conflict` already do. Test `f_066_outside_the_shared_group_record_masks_either_flag` covers three cases: neither copy flagged gives `Alpha`; target only or source only gives the mask. I did not edit the F-066 row in findings.md, because it is not one of this part's rows.

## Second review of the folder.rs unsafe blocks (Rust rule 2; LD-227 (4))

Inventory style as in [E13-S5-inventory.md](E13-S5-inventory.md), with my verdict as the second, independent reviewer. The first reviews were part b's Verify (E13-S6b-fixes.md: `is_file_in`, `rename_in`) and part e's Builder and Verify (E13-S6e-fixes.md: the four F-089 blocks). I wrote none of these blocks. I reviewed the F-089 blocks as part e left them (folder.rs read at 07:30, mtime 00:13:54) before making the optional change. libc is 0.2.191 (Cargo.lock), and I checked the declarations in its source.

| ID | Location (before part j) | Kind | Purpose | SAFETY note (short) | Build | Second review |
|---|---|---|---|---|---|---|
| U-61 | crates/larsal-platform/src/macos/folder.rs:29 `is_file_in` | block | `fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW)`, then `assume_init` (F-047) | 25-28: `dir` open while borrowed; `name` NUL-terminated and alive; `st` valid for one stat; `assume_init` only after 0 | product | **Sound.** `c_name` refuses an inner NUL; the `CString` lives to the end of the function. `MaybeUninit<libc::stat>` matches libc's `stat`. On x86_64 libc links `fstatat$INODE64`, the layout of its `stat`; arm64 has one layout. The early `return` inside the block leaves `st` uninitialised and unread. A link at `name` is lstat'ed and fails `S_IFREG`. `st_dev as u64` sign-extends as std's `MetadataExt::dev` does, so the compare is consistent. |
| U-62 | folder.rs:50 `rename_in` | block | `renameat(fd, from, fd, to)` in one open folder | 48-49: `dir` open while borrowed; both names NUL-terminated and alive | product | **Sound.** Both `CString`s are bound for the whole call, and one borrowed descriptor serves both sides. `renameat` does not follow a link at either final name. errno is read at once by `last_os_error`. |
| U-63 | folder.rs:119-134 `keep_file_info` (block 1 of 4) | block | `fgetattrlist(s, ATTR_CMN_CRTIME)` into `buf[20]`, then `fsetattrlist(d, …, buf+4, 16)` | 116-118: both descriptors open; `list` and `buf` alive; sizes their own; the kernel writes at most `buf.len()` | product | **Sound for memory.** `src` is an owned `File` alive to the end, and `to` is borrowed. `attrlist` matches libc's layout with `bitmapcount = ATTR_BIT_MAP_COUNT`. `buf.as_mut_ptr().add(4)` stays inside the 20-byte array, and the set reads 16 bytes from offset 4, also inside. User-space alignment does not matter (the kernel copies in). `&&` runs the set only after a good get, and errno belongs to the call that failed. **Observation (correctness, not safety):** the reply's length word was not read. On a volume without creation dates the reply holds only the 4-byte length, and the zeroed 16 bytes would set the date to 1970-01-01. **Fixed in part j:** the reply is used only when its length covers the timespec. A second observation was already noted by part e's Verify: an error here skipped the tags and the access list; the change below fixes it. |
| U-64 | folder.rs:142 (block 2 of 4) | block | `fgetxattr(s, TAGS, tags[64 KiB], 64 KiB, 0, 0)` | 139-140: name NUL-terminated and static; `tags` valid for writes of its length | product | **Sound.** `TAGS` is a `c"…"` literal. `position` and `options` are 0, and the no-follow flag applies only to path calls. An attribute over 64 KiB gives `ERANGE` (-1), so the kernel never writes past the buffer. |
| U-65 | folder.rs:145 (block 3 of 4) | block | `fsetxattr(d, TAGS, tags, n, 0, 0)` | 144: as above; the first `n` bytes written | product | **Sound.** `n` comes from `usize::try_from` of a non-negative return, at most `tags.len()` (the kernel's promise), so the read stays in bounds. Options 0 creates or replaces, which fits a new temp file. |
| U-66 | folder.rs:156 (block 4 of 4) | block | `fcopyfile(s, d, NULL, COPYFILE_ACL)` | 154-155: both descriptors open; a null state is allowed; the flag copies the ACL only | product | **Sound.** copyfile(3) allows a NULL state, and `COPYFILE_ACL` (1 << 0) touches only the access list. It returns < 0 with errno set. |
| — | folder.rs:65 `open_regular` | safe code | F-101: refuse a non-regular path, open read with `O_NONBLOCK \| O_NOCTTY`, `fstat` again | no unsafe | product | **Sound, no unsafe.** `metadata` follows links, and anything but a regular file gives `InvalidInput` before the open. A FIFO swapped in between does not block (`O_NONBLOCK`) and is refused by the second check. `O_NONBLOCK` stays set on the `File` and has no effect on reads of a regular file. Callers: storage (`read_checksum`, the lock), session, saving, and now larsal_settings (`read_json`, `check_writable`). |

**The source open in `keep_file_info`** (safe code): `O_NOFOLLOW | O_NONBLOCK`. A link at `from` gives `ELOOP`, so nothing is copied, and the save still goes on (storage ignores the result). `O_NOCTTY` was missing; a device at `from` cannot reach this point, because the safe save refuses a non-regular vault path first (F-101). Part j adds `O_NOCTTY` to match `open_regular`.

**After part j's change** (the optional change of LD-227 (4)): `keep_file_info` runs `creation_date`, `tags` and `acl` (folder.rs:112-202; blocks at :127, :149, :174, :186, :198) one after another, each on the borrowed `File`s. It collects the results and returns the first error. The unsafe calls, their arguments and their SAFETY notes are unchanged in substance. Block U-63 is now two blocks, `fgetattrlist` (:127) and `fsetattrlist` (:149), and the set takes the `time` half of `buf.split_at_mut(4)` instead of `buf.as_mut_ptr().add(4)`, so no pointer arithmetic is left. Folder.rs now has 7 unsafe blocks (2 + 5). Rust rule 2 needs two reviews of the reshaped blocks. I wrote them, so part j's Checker and Verify are their two reviewers.

**Lint proof:** `cargo clippy -p larsal-platform --features appkit,memory,test-memory,test-signals --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment` (own target) found no issues.

## Not done, for the lead

- larsal-autotype `matching.rs` `reads_protected` (about line 593) compares texts the same way F-129 did (`d.text.expose() != plain`). A transform that maps the mask and the value to the same text makes it treat a protected read as plain. The new `Resolved::masked` lets its owner (E8-S2) fix it with `|| d.masked`. I did not edit it, because it is not my file.
- F-066's row in findings.md still says "Left: the 'outside the shared group' record…". Part j fixed that edge case. The row's owner or Verify should update the note.
- The reshaped `keep_file_info` blocks need their two reviews (part j's Checker and Verify).

## Checker 1 round 1 (2026-10-30): review of the reshaped keep_file_info blocks, and result

Second reviewer of the five blocks part j reshaped (Rust rule 2; part j's Verify is the other). I wrote none of them. Declarations checked in libc 0.2.191 `src/unix/bsd/apple/mod.rs` (`fgetattrlist`, `fsetattrlist`: `*mut c_void` list and buffer, `size_t`, `u32` options; `fgetxattr`, `fsetxattr`; `fcopyfile`; `attrlist`; `ATTR_BIT_MAP_COUNT` 5; `ATTR_CMN_CRTIME` 0x200; `COPYFILE_ACL` 1 << 0).

| Block | Call | Checker 1 review |
|---|---|---|
| folder.rs:127 | `fgetattrlist(src, &list, buf[20], 20, 0)` | **Sound.** `list` and `buf` are locals alive across the call; the size passed is `buf.len()`, so the kernel writes at most 20 bytes. The reply length is read native-endian before the time is used; a reply shorter than 20 bytes (no creation date) sets nothing. |
| folder.rs:149 | `fsetattrlist(to, &list, time, 16, 0)` | **Sound.** `time` is `buf[4..20]` from `split_at_mut(4)`, so no pointer arithmetic; the kernel only reads `time.len()` bytes. Attributes start 4-byte aligned after the length word, and the timespec is 16 bytes on arm64. |
| folder.rs:174 | `fgetxattr(s, TAGS, tags[64 KiB], 64 KiB, 0, 0)` | **Sound.** Heap buffer valid for its length; an attribute over 64 KiB gives -1 (`ERANGE`), never a write past the end. |
| folder.rs:186 | `fsetxattr(d, TAGS, tags, n, 0, 0)` | **Sound.** `n` comes from a non-negative return with a non-null buffer, so `n <= tags.len()`; only the written bytes are read. |
| folder.rs:198 | `fcopyfile(s, d, NULL, COPYFILE_ACL)` | **Sound.** A null state is allowed; the flag copies the access list only; `!= 0` covers its `< 0` error return. |

`keep_file_info` builds the array of the three results before `collect`, so every part runs and the first error comes back (mutant M9 below confirms it). Clippy with `-D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment` (features appkit, memory, test-memory, test-signals): no issues.

Re-run in a private copy (`/tmp/e13s6j-checker1-copy`, own target): baseline `cargo test --locked --no-fail-fast -p larsal-core -p larsal-platform -p larsal-ffi` 1,039 passed, 0 failed, 34 ignored (49 suites). Mutants M1 to M9 as above, each exit 101 at the same lines. `scripts/build-core.sh` and `xcodebuild … build SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: BUILD SUCCEEDED.

**Sent back (2):** (1) F-128's text compare uses the clock of the Yes, not of the question: a command with a date placeholder (`cmd:///usr/bin/touch …/ran-{DT_SIMPLE}`) never runs. Each Yes 1.1 s after the question gives false and the question comes back with the new second (probe: 3 rounds, `ran false` each, 0 files made). The same happens with `{DT_SECOND}` every time, and with an unprotected `{TOTP}` or `{DT_MINUTE}` when a boundary is crossed. (2) false also means "the program did not start", so with Remember off the question comes back after every Yes, with no word why (probe `cmd:///nonexistent/demo-program`: 3 rounds, `Ask` each time). Limit (3) above says "once".

## Round 2 (2026-10-30): Checker 1's two F-128 findings

Both were right. Fixed as the Checker proposed.

1. **A dated command never ran.** `run_url_command` resolved on the clock of the Yes, so `{DT_SIMPLE}` or `{DT_SECOND}` never matched, and `{DT_MINUTE}` or an unprotected `{TOTP}` failed across a boundary. Fix: `UrlAction::Ask` carries `at` (the time `open_url` resolved with, seconds since year 1). `run_url_command(vault, entry, command, at, remember)` resolves both texts with `Time(at)`. OpenURL.swift passes it back (`at: clock`; SwiftLint wants a name of three letters or more). A sync still makes the text differ.
2. **false had two meanings.** It meant "changed" and also "did not start", so a missing program asked again after every Yes. Fix: true once the compare passed. `run_command` no longer returns a value, since no caller used it. Before part j, Swift ignored the result too.

**Test:** larsal-ffi `auto_open::tests::f_128_yes_asks_again_only_for_a_changed_command`. Entry 51 is `cmd:///usr/bin/touch <dir>/ran-{DT_SIMPLE}`. Open asks, the test waits until the clock passes the question's second, then Yes with the shown text and `at` gives true and makes the shown file (`ran-20261030073345` in the mutant's message). Entry 52 is `cmd:///nonexistent/demo-program`: Yes gives true. `f_080_…` and `f_128_a_command_changed_…` compare `Ask` with `at` set to 0 (helper `untimed`) and pass `now()` to `run_url_command`; their commands hold no date.

**Mutants** (private copy `/tmp/e13s6j-builder-copy`, target `/tmp/e13s6j-builder-mtarget`), each exit 101:

| Mutant | Fails | Where |
|---|---|---|
| M10: `run_url_command` resolves with `now()`, not `Time(at)` | `f_128_yes_asks_again_only_for_a_changed_command` | auto_open.rs:841, `assert!(ran, …)`; the shown text was `…/ran-20261030073345` |
| M11: the answer is false when the program is missing (`Path::exists` of the first word) | the same test | auto_open.rs:844, `assert!(yes(52, false).0)` |
| M5 re-run: the text compare off | `f_128_a_command_changed_after_the_question_does_not_run` | auto_open.rs:782 |

**Checks** (shared tree, target `/tmp/e13s6j-builder-target`): `cargo build --locked --workspace --all-targets` exit 0. `cargo test --locked --no-fail-fast -p larsal-core -p larsal-platform -p larsal-ffi`: 1,043 passed, 0 failed, 34 ignored (49 suites). `cargo clippy --locked -p larsal-ffi --all-targets -- -D warnings` exit 0. `cargo fmt --check` exit 0. In the private copy: `scripts/build-core.sh` exit 0, and the binding reads `runUrlCommand(vault: UInt64, entry: String, command: String, at: Int64, remember: Bool) throws -> Bool`. `swift format lint --strict Larsal/OpenURL.swift` exit 0, SwiftLint 0.65.1 `lint --strict --quiet Larsal/OpenURL.swift` exit 0, `xcodebuild … build SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: BUILD SUCCEEDED. `xcodebuild test -skip-testing:LarsalUITests`: 319 tests, 2 issues, none about OpenURL. When the two suites ran alone, APP-08.14 (MenuKeysTests) passed, so it failed only under load. WindowFixesTests `F-074, MOD-13.8 T13` still failed at line 215, `settings.sheet == .changePassword`. That test covers Vault Settings, whose Swift files the E5 follow-up batch was editing at 08:28 to 08:29, just before my copy at about 08:33.

Mac QA (W-08) is unchanged: seeing MSG-08-2 come back after a sync, and a dated command run after a slow Yes, needs a visible window.

## Verify round 1 (2026-10-29; the Mac's clock read 2026-10-30)

Role: Verify. I did not find, build or check these fixes. Clean room: Larsal's own code, `spec/`, the libc 0.2.191 source and the macOS SDK headers and man pages; I did not open the reference source. Demo data only: every vault, file and folder was made by the tests in the system temp folder.

Setup: the shared tree's part j files were hashed at 09:05 (`auto_open.rs` 5fc17cdd…, the same file Checker 1 passed) and copied with `rsync -a --delete --exclude target --exclude larsal-shots --exclude fuzz/target` to `/tmp/e13s6j-verify-copy`, with its own `CARGO_TARGET_DIR=/tmp/e13s6j-verify-target` and `-derivedDataPath /tmp/e13s6j-verify-dd`. My probes (tests named `verify_probe_*`) and mutants lived in that copy only. At the end, `shasum -c` of the shared files: all OK, so nothing in the tree changed under the re-test.

Baseline in the copy: `cargo test --locked --no-fail-fast -p larsal-core -p larsal-platform -p larsal-ffi`: 49 suites, 1,043 passed, 0 failed, 34 ignored. Each named part j test `ok`: `larsal_settings::tests::f_123_check_writable_follows_no_planted_link_or_fifo`, app05 `f_124_a_busy_vault_file_does_not_count` and `app05_14_repeated_failures`, `auto_open::tests::f_128_a_command_changed_after_the_question_does_not_run`, `auto_open::tests::f_128_yes_asks_again_only_for_a_changed_command`, `auto_open::tests::f_129_a_transform_cannot_pass_a_protected_value_as_plain`, mod08 `f_129_masked_marks_every_mask`, mod11 `f_066_outside_the_shared_group_record_masks_either_flag`, `macos::folder::tests::f_089_each_part_is_copied_on_its_own`, app05 `f_089_safe_save_keeps_creation_date_tags_and_acl`, `auto_open::tests::f_080_open_url_follows_mod_08_31`.

| Item | Verdict |
|---|---|
| F-123 (Medium) | fixed, re-tested |
| F-124 (Low) | fixed, re-tested |
| F-128 (Low) | fixed, re-tested (both rounds) |
| F-129 (Low) | fixed, re-tested; one new reference-search case reported to the lead (not this row's vector) |
| F-066 edge case | fixed, re-tested |
| folder.rs unsafe | second review of the five reshaped blocks done (Checker 1 was the first); U-61, U-62 and `open_regular` re-read: sound |

### My mutants (private copy, one at a time, file put back and compared after each)

| Mutant | Test | Result |
|---|---|---|
| VM1: the fixed-name probe `.larsal-settings-check` opened with create and truncate back in `check_writable` | `f_123_…` | FAILED at larsal_settings.rs:1615 (the demo file was emptied), exit 101 |
| VM2: the regular-file check of the settings file dropped (`&& true`) | `f_123_…` | FAILED at :1632 (no error for the FIFO), exit 101 |
| VM3: `read_json` opens with `std::fs::File::open` | `f_123_…` | FAILED at :1631 after 5.01 s (load waits on the FIFO), exit 101 |
| VM4: `ResourceBusy` removed from the kinds that do not count | app05 `f_124_…` | FAILED at app05.rs:426, exit 101 |
| VM5: `run_url_command` keeps the Yes before the text compare | `f_128_a_command_changed_…` | FAILED at auto_open.rs:785 (the next open was `Done`), exit 101 |
| VM6: `run_url_command` resolves one second after the question's clock | `f_128_yes_asks_again_…` | FAILED at auto_open.rs:841, exit 101 |
| VM7: the `{S:…}` branch copies the mask without the flag | mod08 `f_129_…` | FAILED at mod08.rs:1639, exit 101 |
| VM8: the `{TOTP}` branch copies the mask without the flag | mod08 `f_129_…` | FAILED at mod08.rs:1639, exit 101 |
| VM9: `resolve_field` answers `false` for the flag | larsal-ffi `f_129_…` | FAILED at auto_open.rs:889, exit 101 |
| VM10: the Outside record ignores the target copy's flag | mod11 `f_066_outside_…` | FAILED at mod11.rs:2456, exit 101 |
| VM11: `keep_file_info` stops at the first failing part (`?` chain) | `f_089_each_part_…` | FAILED at folder.rs:236 (the access list was not copied), exit 101 |
| VM12: the creation-date reply length check off | `macos::folder` tests | survived, exit 0: on APFS the reply always holds the date. A devfs source (`/dev/null`) gives EINVAL before the set, so it does not reach the branch either. The branch rests on the code read below; a volume without creation dates needs a mounted disk image, not done on the owner's Mac |

### F-123 (Medium)

- **Steps** (the row's, as probe `verify_probe_f123`): a folder with `victim.txt` ('victim, demo text') and a link `.larsal-settings-check` to it; `use_folder(folder)`, then `check_writable()`. Then a FIFO (`/usr/bin/mkfifo`) at `state.json`, a new store loaded and checked on a worker thread with a 5 s limit. Then a link at `settings.json` to a FIFO elsewhere, the same.
- **Before** (the row): `answer None; victim now 0 bytes ""; link left: false`, and the append open of settings.json waits on a FIFO.
- **After**: `answer None; victim now 17 bytes "victim, demo text"; link left: true; folder [".larsal-settings-check", "victim.txt"]` (no probe file left). FIFO at state.json: the notice and the check both name `…/state.json`, in 0.32 ms. Link to a FIFO at settings.json: both name `…/settings.json`, in 0.14 ms.
- **Proof**: `f_123_…` ok; VM1, VM2, VM3 each fail it.

### F-124 (Low)

- **Steps** (probe `verify_probe_f124_real_lock`): a demo vault file 'OLD'; the test holds `File::lock` on it; `storage::save` (safe method, last known checksum of 'OLD'); the real error fed to `Failures::failed` three times.
- **Before** (the row, and VM4): the third busy failure asks MSG-SAVE-UNSAFE-ASK.
- **After**: `Err(Write { kind: ResourceBusy, kept_temp: None }) after 5.018 s; asks after 3 busy failures [false, false, false]; count 0`; the file still reads 'OLD'. larsal-ffi `saving.rs` feeds the same `Failures::failed` (its one caller), so the root fix covers the app.
- **Proof**: `f_124_…` and `app05_14_repeated_failures` ok; VM4 fails `f_124_…`.

### F-128 (Low)

- **Steps** (probe `verify_probe_f128`): entry 70 `cmd:///usr/bin/touch <dir>/shown`; Open; while the question is open, the vault file is rewritten with `…/swapped` and reloaded (`resolve_disk(Reload)`: `Ok(Reloaded)`); Yes with Remember on, passing the question's `command` and `at`. Entry 71 `cmd:///usr/bin/touch <dir>/sec-{DT_SECOND}-{DT_SIMPLE}`: three rounds of Open, wait 1.1 s, Yes. Entry 72: a command over 400 characters whose last word a sync changes after the question.
- **Before** (the row): `Yes ran=true; shown exists=false, swapped exists=true; next open Done`. Round 1 (Checker 1): dated commands never ran.
- **After**: `Yes ran=Ok(false); shown exists=false, swapped exists=false`; the next Open asks with `…/swapped` and Remember offered, so nothing was kept. Dated: rounds 0, 1, 2 each `ran Ok(true); file made true`.
- **Swift**: OpenURL.swift `ask` passes `command:` and `at: clock` and calls `openURL(entry:)` again only when the answer is `false` (`try?` gives `nil` on an error, so no new question then). `runUrlCommand` has one caller. `swift format lint --strict Larsal/OpenURL.swift` exit 0; SwiftLint 0.65.1 `lint --strict --quiet Larsal/OpenURL.swift` exit 0; build results below. Seeing the question come back in a window is Mac QA (W-08).
- **Limit 1 seen**: entry 72's question is cut at 400 characters (`… […]`, 404 characters); after a sync that changes only the last word, Yes answers true and runs it (`tail-B made true`). Builder's limit 1 says so; noted for the lead.
- **Proof**: both `f_128_…` tests ok; VM5 and VM6 fail them; Checker 1's M10 to M12 and the Builder's M5 cover the other parts.

### F-129 (Low)

- **Steps** (probe `verify_probe_f129`, one vault, Password `demo-s` protected unless said): entry 80 the row's probe `https://example.com/?p={T-REPLACE-RX:/{PASSWORD}/^.{6}$/six/}`; 81 the same regex over `{REF:P@I:<entry 80>}`; 82 the probe nested in `{T-CONV:|…|U|}`; 83 a protected custom field `{S:Pin}` with `/^.*$/any/`; 84 a protected `otp` field and `{TOTP}` with `/^.{6}$/six/`; 85 the probe with the Password field's own flag off (the vault's Password flag on, its default). Control: a second vault with the vault's Password flag off and the field plain. Auto-open: an AutoOpen entry whose user name is `<probe>.larsalkey`.
- **Before** (the row): `Open { url: "https://example.com/?p=six" }`.
- **After**: entries 80 to 85 each `Refused { message: "Larsal does not open this kind of link." }` (MSG-08-4). Control: `Open { url: "https://example.com/?p=six" }`, so the refusals come from the flag. Auto-open `key_secret: [true]`. (A first try of entry 82 with `/` as the T-CONV separator opened `?p=`: the separator split the inner regex, so nothing was read, which is correct.)
- **Code read**: `Run::mask()` is the only place that copies `MASK` (refs.rs:318-320); `{S:…}`, `field_step` (standard fields, `{REF:…}` fields, `{URL:…}`) and the `{TOTP}` branch all call it. Up to the first mask, the display run and the full run take the same steps, so a work or depth bound cannot stop the display run before the mask while the full run reads the value.
- **New case, not this row's vector (reported to the lead)**: entry 86 `https://example.com/?t={REF:T@P:demo-s}` opens `Open { url: "https://example.com/?t=Target" }`, and entry 87 with a wrong guess opens `?t=`. A reference search compares the searched field's raw value (refs.rs `find`, `find_indexed`), protected or not, and puts in only the found entry's plain Title, so no mask and no flag. A planted entry learns per click whether some entry's protected password equals a guess. The old text compare missed it too. Smallest fix: in `reference_step`, set the flag in display mode when the search reads a protected field (`@P`, `@A`, or a protected field of a visited entry).
- **Proof**: both `f_129_…` tests ok; VM7, VM8, VM9 fail them.

### F-066 edge case

- **Steps**: the test `f_066_outside_the_shared_group_record_masks_either_flag`, a shared-group import whose source entry also sits outside the shared group in the target, run for neither, target-only and source-only Title flags.
- **Before** (Builder's M8, my VM10): `record(true, false)` gave `["Alpha"]`.
- **After**: `["Alpha"]`, mask, mask. Code read: merge.rs:779-792 looks up the target copy with `self.ix.entry_mut` (a lookup only) and passes `self.mask_titles || own_flag(target)` to `shown_title`, which adds the source's own flag; a source without a Title field shows "" (never the target's). The group record (merge.rs:551-559) has no title. The F-066 row's "Left: …" note is part b's row; I did not edit it.
- **Proof**: the test ok; VM10 fails it.

### Second review of the folder.rs unsafe blocks (Rust rule 2; LD-227 (4), LD-240 (2))

Second independent reviewer of the five blocks part j reshaped (Checker 1 was the first), and a re-read of the two older blocks and `open_regular` (part b's Verify and part j's Builder were their two reviewers). I wrote none of them. Declarations checked in libc 0.2.191 (`src/unix/bsd/apple/mod.rs`, `src/unix/mod.rs`) and the SDK headers: `unistd.h` (LP64 `fgetattrlist`/`fsetattrlist` take `unsigned int` options, as libc's `u32`), `sys/attr.h` (`attrlist` is `u_short, u_int16_t` then five `u_int32_t`; `ATTR_BIT_MAP_COUNT` 5; `ATTR_CMN_CRTIME` 0x200), `sys/xattr.h`, `copyfile.h` (`COPYFILE_ACL` 1<<0); `getattrlist(2)` (the reply's first `u_int32_t` is the length including itself) and `setattrlist(2)` (the set buffer has no leading length).

| Block | Call | Verify review |
|---|---|---|
| folder.rs:29 `is_file_in` | `fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW)` | **Sound.** `name` is the `CString` from `c_name` (inner NUL refused), alive to the end of the function. On arm64 libc's `stat` is the one layout; on x86_64 libc links `fstatat$INODE64` (src/unix/mod.rs:1097-1100). `assume_init` only after 0; the early return leaves `st` unread. `dev_t` is `i32`; `as u64` matches std's `MetadataExt::dev`. |
| folder.rs:50 `rename_in` | `renameat(fd, from, fd, to)` | **Sound.** Both `CString`s are bound for the whole call; errno read at once. |
| folder.rs:65 `open_regular` | safe code | **Sound, no unsafe.** `metadata` (follows links) refuses anything but a regular file; `O_NONBLOCK \| O_NOCTTY` open; `fstat` again refuses a swap. |
| folder.rs:127 `creation_date` | `fgetattrlist(src, &list, buf[20], 20, 0)` | **Sound.** `list` (24 bytes, the SDK layout) and `buf` are locals alive across the call; the size passed is `buf.len()`, so the kernel writes at most 20 bytes; errno read right after. The reply is used only when its length word (native-endian) is at least 20, so a volume without creation dates sets nothing (VM12: not reachable by a test here). |
| folder.rs:149 | `fsetattrlist(to, &list, time, 16, 0)` | **Sound.** `time` is `buf[4..20]` from `split_at_mut(4)`: the 16-byte arm64 `timespec`, no pointer arithmetic; the kernel only reads it; the set buffer has no length word, as setattrlist(2) says; `list` asks for the creation time only. |
| folder.rs:174 `tags` | `fgetxattr(s, TAGS, tags[64 KiB], 64 KiB, 0, 0)` | **Sound.** `TAGS` is a static `c"…"`; heap buffer valid for its length; an attribute over 64 KiB gives -1 (`ERANGE`), never a longer write; `usize::try_from` of a negative return reads errno at once (ENOATTR is no error). |
| folder.rs:186 | `fsetxattr(d, TAGS, tags, n, 0, 0)` | **Sound.** `n` is a non-negative return with a non-null buffer, so `n <= tags.len()`; only written bytes are read. |
| folder.rs:198 `acl` | `fcopyfile(s, d, NULL, COPYFILE_ACL)` | **Sound.** copyfile(3) allows a null state; the flag copies the access list only; `!= 0` covers its `< 0` error. |

`keep_file_info` builds the array of the three results before `collect`, so each part runs and the first error comes back (VM11 proves the test sees it). The source opens with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`; storage ignores the result (storage.rs:577), so a part that cannot be copied never fails a save. `cargo clippy -p larsal-platform --features appkit,memory,test-memory,test-signals --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment` in the copy: see checks below. With Checker 1's review, each of the five reshaped blocks now has two reviews.

### Checks (copy refreshed from the tree after the mutants, without my probes)

- `cargo clippy --locked -p larsal-core -p larsal-platform -p larsal-ffi --all-targets -- -D warnings`: Finished, no warnings. The unsafe-lint clippy named above: Finished, no warnings. `cargo fmt --check -p larsal-core -p larsal-platform -p larsal-ffi`: exit 0.
- `scripts/build-core.sh` (`DEVELOPER_DIR` set): finished. The binding reads `func runUrlCommand(vault: UInt64, entry: String, command: String, at: Int64, remember: Bool) throws -> Bool`, and `UrlAction.ask` lists `message: String, command: String, remember: Bool, at: Int64`, so OpenURL.swift's fourth binding `clock` is `at`.
- `xcodebuild -project Larsal.xcodeproj -scheme Larsal -configuration Debug -derivedDataPath /tmp/e13s6j-verify-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES build`: BUILD SUCCEEDED. I did not run the Swift tests: no LarsalTest drives OpenURL (`runUrlCommand` is called only in OpenURL.swift; `openURL(entry:)` is called from OpenURL.swift and RailView.swift).
- `scripts/check-names.sh` after my edits to this file, findings.md and epics.md: `names: PASS (3197 files scanned, 16 vault files name-only)`.

### Open after this round

- Mac QA (W-08, owner's go): MSG-08-2 coming back after a sync, and a dated command run after a slow Yes, in a window.
- The creation-date length branch (VM12) has no test; it needs a volume without creation dates.
- For the lead: the reference-search case above (new, Low), F-128 limit 1, and the F-066 row's "Left: …" note (part b's row).
