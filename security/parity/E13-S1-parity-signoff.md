# E13-S1 Parity sign-off: collected results

Story: E13-S1 (plan/epics.md). Matrix: [security.md](../../plan/security.md), "Security parity matrix" (84 rows). Fleet plan: [attacks-and-checks.md](../../plan/attacks-and-checks.md), "The final verification fleet (E13)".
Date: 2026-10-29.
Role: collector. The eight group Verify agents ran the rows on today's tree; I did not verify rows and fixed nothing. I spot-checked one verified row per group against its proof file, filed the new findings and wrote this page.

**Result: not signed.** 46 of 84 rows are verified today. 11 failed, 4 wait for Mac QA and 23 wait for a story, a decision or the owner's go. The 11 failed rows are places where Larsal does less than the reference or its own card today; their findings are listed below.

## Counts per group

| Group | Proof | Rows | Verified | Failed | Mac QA | Waits |
|---|---|---|---|---|---|---|
| SF File and crypto | [E13-S1-SF.md](E13-S1-SF.md) | 18 | 15 | 2 | 1 | 0 |
| SR Runtime | [E13-S1-SR.md](E13-S1-SR.md) | 16 | 8 | 4 | 3 | 1 |
| SC Clipboard and screen | [E13-S1-SC.md](E13-S1-SC.md) | 8 | 5 | 2 | 0 | 1 |
| SD Data safety | [E13-S1-SD.md](E13-S1-SD.md) | 13 | 6 | 3 | 0 | 4 |
| SG Generator and checks | [E13-S1-SG.md](E13-S1-SG.md) | 7 | 6 | 0 | 0 | 1 |
| SI Integrations | [E13-S1-SI.md](E13-S1-SI.md) | 14 | 2 | 0 | 0 | 12 |
| SN Network | [E13-S1-SN.md](E13-S1-SN.md) | 5 | 3 | 0 | 0 | 2 |
| SB Build and supply chain | [E13-S1-SB.md](E13-S1-SB.md) | 3 | 1 | 0 | 0 | 2 |
| **Total** | | **84** | **46** | **11** | **4** | **23** |

Counts follow each row's result as the group reported it. The SR summary says "10 pass, 5 fail"; its row list gives 8 verified, 3 Mac QA, 4 failed, 1 waits, and this page uses the row list. Groups differ on rows whose table status is "verified, Mac QA open": SC counts SC-02, SC-03, SC-07 and SC-08 as verified, while SR counts SR-01, SR-02 and SR-07 as Mac QA.

## Spot checks (one verified row per group)

Each check compares the group's reported evidence with its proof file section and the row in plan/security.md.

| Row | Proof section | Matches the reported evidence | Table status |
|---|---|---|---|
| SF-07 | E13-S1-SF.md, SF-07 | Yes: the same test names; 40 resaves, 40 of 40 distinct master seeds, IVs and KDF seeds, 120 of 120 across kinds; reference guard as described. | verified, linked, "verified again 2026-10-29" |
| SR-13 | E13-S1-SR.md, SR-13 | Yes: the reference prints `PROTECTED` without `-s`; Larsal prints `(hidden)`, `-s` gives the value, `--password` and `-p` give "unknown option" exit 1; int10 114 passed with the named cases. | verified, linked, dated |
| SC-06 | E13-S1-SC.md, SC-06 | Yes: 8 of 8 levels equal (table of bits for both tools); typing probe values Weak 61, Poor 16, Poor 25 (editor 1, LD-44), Weak 45, Good 76, Poor 8, empty nil. | verified, linked, dated |
| SD-04 | E13-S1-SD.md, SD-04 | Yes: mod03 18 passed; both tools end with current user-9 and the same 10 history items. | verified, linked |
| SG-07 | E13-S1-SG.md, SG-07 | Yes: fea04 30 and mac 8 pass; 7 of 7 storage forms equal in the same window; python HMAC 602802 equals `larsal show -t`. | verified, linked, dated |
| SI-08 | E13-S1-SI.md, SI-08 | Yes: R and C equal python and `fmt_04_6_e_vector_hk`; both tools open the reference's hardware-key test vault with the variable answer (exit 0) and refuse the fixed one (exit 1); M06-17 with no key; T53 open. | verified, software only, dated |
| SN-03 | E13-S1-SN.md, SN-03 | Yes: `sn03_*` pass; the product client refused self-signed, expired, wrong-host and untrusted-root servers; 2 accepts, 0 finished per server; the `s_client` control got `HTTP/1.0 200 ok`. | verified, linked |
| SB-02 | E13-S1-SB.md, SB-02 | Yes: `cargo deny` and `cargo audit` exit 0; 66 entries pinned with `=`; 254 of 254 crates.io packages with a checksum (fuzz lock file 127 packages, 117 from crates.io); probes P1 to P3 fail as they should, P4 refused by cargo itself. | verified, linked, dated |

All eight spot checks hold.

## Failed rows

| Row | Finding | Severity | What fails |
|---|---|---|---|
| SF-12 | F-073 | Low | A merge copies the reference's public id item into the target (merge.rs:1228). The header writer itself is clean. |
| SF-18 | F-072 | Low | The key file note shows a file name with U+202E uncleaned (`session::read_key`). |
| SR-03 | F-078 | Medium | Lock on minimize always waits 1 s, not the clipboard countdown (AppDelegate.swift:36). |
| SR-06 | F-076 | High | The Caps Lock warning is only on the unlock form. |
| SR-08 | F-077 | High | The expired-entries notice after unlock is not wired. |
| SR-10 | F-079 | Medium | Auto-open is not built and no story owns it. |
| SC-01 | F-081 | High | Text selected in the editor's Notes is copied with no marker and never cleared. Every copy action passes. |
| SC-04 | F-082, F-084 | High, Low | Hide notes, Hide one-time codes and Show dots for empty passwords change nothing on screen. |
| SD-01 | F-087, F-089 | Medium, Low | No offer to turn off safe saving after 3 failed saves; creation date, Finder tags and ACL are dropped. |
| SD-03 | F-085 | High | A file re-keyed elsewhere: Merge and Discard stop; Keep mine overwrites the other side and undoes the key change. |
| SD-11 | F-086 | High | An opened attachment edited in another app is wiped without a save-back question. |

## Waiting rows

**Mac QA (4).**
- SF-03: a quiet Mac. The band tests failed both ways at load average 35 to 255 on 14 cores. Run `cargo test --release -p larsal-crypto --test kdf -- --ignored benchmark_` and the side-by-side `db-create -t 1000` timing. Range and default already match.
- SR-01: real idle time and input in other apps (T05).
- SR-02: real screen lock, user switch and sleep on this Mac.
- SR-07: the lldb dump of the real Larsal.app.

**Owner's go or D7 (2).**
- SG-05: a network capture of a real breach check. It sends data to the outside service (rule 7) and starts from the window. Every check that stays on the Mac passes.
- SB-01: Developer ID signing, notarization, stapling and the keychain access group wait for D7 (E14-S3, AT-J05). Today's Release Larsal.app already has the hardened runtime and no entitlements.

**E7 browser bridge, decision D4 (8).**
- SI-01 (E7-S1), SI-02 (E7-S2), SI-03 (E7-S3), SI-04 (E7-S4), SI-05 (E7-S5), SI-10 (E7-S4), SI-11 (E7-S4), SI-12 (E7-S1, E7-S2).

**Stories in flight or planned (9).**
- SR-04: quick unlock, E6-S3, which needs a signing team (D7).
- SC-05: E6-S5's Verify fix (Checker next), then Mac QA for the real capture paths. The product passes every check that could run (13 tests, 7 hidden launches).
- SD-08: the E13-S2 Red team run of AT-G03 (running now).
- SI-06: E8-S2's Swift part (in flight) and E8-S3. The Rust matching part passes.
- SI-09: E11 (W-15). The LD-61 core rule passes (T52).
- SI-13: E11 (W-15), decision D-INT09-1.
- SI-14: E8-S3. The row's reference text is wrong (F-091).
- SN-04: Larsal's release feed (E14, D-01-2). No E14 story names it yet (F-095).
- SB-03: E14-S4 (in flight) and a release signing key (D7). No story owns the detached signature (F-097).

**No owning story yet (4).** The lead adds a story or rules the row out.
- SD-07: the app's plain export screens (File > Export is disabled; the command line warning holds).
- SD-12: the APP-05.33 notice about old copies after a key change (F-088). The parity part holds.
- SD-13: attachment preview, MOD-05.9.
- SN-02: icon download (F-094). The parts that exist pass.

## Findings filed

All in [security/findings.md](../findings.md), dated 2026-10-29, status "open; fix in E13-S6". No group finding duplicated an open row. The int06_22 timing failure seen by the SF group is folded into F-092.

| ID | Severity | Row | Area |
|---|---|---|---|
| F-072 | Low | SF-18 | Key file name in the key file note, `session::read_key` |
| F-073 | Low | SF-12 | Merge copies public header items |
| F-074 | Low | SF-13 | Window key change reminder (MOD-13.7 to .10) not built, no story |
| F-075 | Low | SF-03 | `larsal db-create` under load: an ask is reported as a write failure |
| F-076 | High | SR-06 | Caps Lock warning only on the unlock form |
| F-077 | High | SR-08 | Expired-entries notice after unlock not wired |
| F-078 | Medium | SR-03 | Minimize lock delay always 1 s |
| F-079 | Medium | SR-10 | Auto-open not built, no story |
| F-080 | Low | SR-11, SR-12 | MOD-08.31 URL rules and remembered key files not wired |
| F-081 | High | SC-01 | Selected-text copy without marker or clear |
| F-082 | High | SC-04 | Hide notes and Hide one-time codes not applied |
| F-083 | Low | SC-08 | Search clear timer not restarted on a screen change |
| F-084 | Low | SC-04 | Show dots for empty passwords not applied |
| F-085 | High | SD-03 | File re-keyed elsewhere: changes lost, key change undone |
| F-086 | High | SD-11 | No save-back of an edited opened attachment |
| F-087 | Medium | SD-01 | No offer to turn off safe saving after repeated failures |
| F-088 | Medium | SD-12 | Old copies after a key change not listed |
| F-089 | Low | SD-01 | Safe save drops creation date, Finder tags and ACL |
| F-090 | Low | SD-05 | Test hygiene: unbounded busy-wait in a session test; one int05_match flake |
| F-091 | Low | SI-14 | Matrix wording for the reference's permissions |
| F-092 | Low | SI-06, SI-07 | Wall-clock test bounds (t40, int06_22) flaky under load |
| F-093 | Low | SN-05 | No documented no-network build switch |
| F-094 | Low | SN-02 | Icon download has no story; row text out of date |
| F-095 | Low | SN-04 | Update check has no story |
| F-096 | Low | SN-04 | Settings update row wording |
| F-097 | Medium | SB-03 | Detached release signature has no story |

Totals: 0 Critical, 6 High, 5 Medium, 15 Low.

## For the lead

- **SF-12** still says "verified" in the table although today's run failed (F-073). The SF agent left it for you to decide whether to lower it to built.
- **SC-01** and **SR-03** carry partial statuses ("verified for copy actions; selected-text copy open", "verified in part, `r` open").
- **SG-05**'s proof text still says it waits for E6-S7 and E5-S7. Both are Done; only the owner-go capture remains.
- **SN-02**'s row text says PNG, JPEG and ICO; LD-109 accepts PNG and ICO only (F-094).
- **SR-15** and **SR-16** are verified for today's app. The browser sockets and dialogs come with E7 and must be checked again then (AT-E08 in E7-S1 and E7-S6).
- **The SC group** saw the name guard fail on one hit in release/THIRD-PARTY-NOTICES.md (another agent's file). The other groups saw it pass.
- **Mac QA items** named by the groups, besides the four rows above: the SF-15 alert and SF-16 dialogs, the SR-05 lldb and forced-crash runs, a clipboard history app, Universal Clipboard and Command-L or Command-Q (SC-02, SC-03), SC-07 on the general pasteboard, the SC-08 real focus loss, the SN-02 reference redirect capture, the SI-07 macOS system agent (V-INT06-3) and the SI-08 real key run (T53).

## Re-run after E13-S6 (2026-10-30)

Role: Verify. I re-ran the 34 rows above that failed (11) or waited (23), after their findings F-072 to F-094 were fixed and re-tested in E13-S6 parts d, e and f (LD-223), F-081 in the E5 follow-up batch, and F-122 in part i. I did not build or fix anything. The four Mac QA rows of the first run (SF-03, SR-01, SR-02, SR-07) were not in this re-run.

**Result: 14 verified, 0 fail, 4 Mac QA, 16 wait.** Every waiting row waits on an item parked for the owner: E7 (W-01, D4), E11 (W-15), signing (W-02, D7), the release location (E14-S3, publishing), the icon mockup (W-20) or the owner's go for a request that leaves the Mac (rule 7). With the first run, the matrix now reads 60 verified, 0 failed, 8 Mac QA, 16 waiting.

### Setup

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots` to `/tmp/e13rr-verify-copy`, taken at **12:18:04** on 2026-10-30, with its own `CARGO_TARGET_DIR=/tmp/e13rr-verify-target` and `-derivedDataPath /tmp/e13rr-verify-dd`. Nothing in the copy was changed. One shared file changed after the copy: macos/LarsalTests/HygieneFixesTests.swift (another agent; see SC-01).
- **Build.** `scripts/build-core.sh` -> 'build-core (debug): target/larsal-core/LarsalFFI.xcframework …'. `xcodebuild build-for-testing … SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` -> '** TEST BUILD SUCCEEDED **'.
- **Rust.** `cargo test --locked --no-fail-fast -p larsal-ffi -p larsal-core -p larsal-platform --features larsal-ffi/net`, run under `sandbox-exec` with outside network denied (localhost allowed), HOME and TMPDIR in /tmp, no SSH_AUTH_SOCK: 1,067 passed, 1 failed, 36 ignored. The one failure is `fea06_29_offline_streams`, which reads its own memory with `ps`, and the sandbox refuses `ps` ('Operation not permitted'); outside the sandbox `cargo test -p larsal-core --test fea06`: 38 passed. `cargo test --locked -p larsal-autotype -p larsal-format` (same sandbox): 930 passed, 0 failed (larsal-autotype 106).
- **Swift.** `xcodebuild test-without-building … -skip-testing:LarsalUITests`, every view offscreen, private pasteboards: 328 tests, 326 passed (17 of them ran twice, because the run restarted its test process; see note 1). The 2 that failed passed when run alone, twice each (see SC-01 and the notes). The load average was 17 to 31 on 14 cores throughout.
- **Hidden launches.** 4 launches of the copy's Debug Larsal.app with `open -n -g -j --env LARSAL_TEST_HIDDEN=1 --env LARSAL_TEST_INSTANCE_DIR=<own folder>`. The front app was the same before and after each. Each process ended by itself or was stopped by its PID. A window list reader (`CGWindowListCopyWindowInfo`, window metadata only, no pixels or titles) read the sharing state.
- **Reference.** I read the reference source (commit 09e34ba8) for every row below. I did not run the reference app: the rows that still need it (the SN-02 redirect capture) wait for the owner's go.
- **Rule 10.** No window was shown, no key event was posted, nothing was written to the general pasteboard, and no permission prompt was shown.

### Rows that failed on 2026-10-29

| Row | Result | Proof |
|---|---|---|
| SF-12 | **verified** | Reference: the public id is added only by quick unlock (`Database.cpp` around line 1172), and its merge leaves public header data alone. Larsal: `merge.rs` `display_item` (line 197) merges only the NAME, COLOR and ICON items; `f_073_merge_leaves_the_public_id_alone` ok; the header tests `d50_fmt_03_23`, `d58_fmt_03_23` and `c51_fmt_02_29` ok. No code makes or reads the id: `settings.rs` `set_public` writes NAME, COLOR and ICON only, and there is no quick unlock code. E6-S3 must keep APP-04.8 when it is built. |
| SF-18 | **verified** | `f_072_key_file_name_is_cleaned`, `t40_app_06_18_*` (2), `t41_app_06_18_names`, `m06_texts_match_the_table` and `f039_key_file_version_text_in_error` ok. |
| SR-03 | **verified** | Reference: `qBound(1, clipboard()->secondsToClear(), 20)` (`DatabaseTabWidget.cpp:745`). Larsal: `f_078_seconds_left_follows_the_countdown` and `f_078_session_reports_the_clipboard_countdown` ok; Swift "F-078, APP-02.8: the app's lock on minimize waits for Rust's clipboard countdown" passed; LockSignalsTests passed (T16 to T25, quit locks all). |
| SR-06 | **Mac QA** | Reference: the password field checks Caps Lock (`PasswordWidget.cpp:81` to `:232`). Larsal: the 4 F-076 tests passed (wizard, vault settings, editor and unlock form; never on a repeat field), and SecureInputTests passed. AT-D05, the keystroke tap against real secure input, needs real keys (E13-S2 re-run: Mac QA). |
| SR-08 | **verified** | Reference: the search `is:expired-N` after the first unlock (`DatabaseWidget.cpp:1340` to `:1348`). Larsal: `f_077_expiry_notice_after_the_first_unlock` ok; Swift "F-077, APP-01.18 a, b" passed; AT-K04 passed in the E13-S2 re-run. |
| SR-10 | **verified** | Reference: the group `/AutoOpen` and the `IfDevice` list (`DatabaseWidget.cpp:2759`, `:2772`). Larsal: 8 `f_079_*` tests ok (4 larsal-ffi, 4 larsal-core). Hidden launch: our `larsal` tool made a.larsalvault, with a group AutoOpen holding an entry with URL `b.larsalvault` and b's password, and b.larsalvault. `Larsal --password-stdin a.larsalvault` then gave `"state.recent": [".../b.larsalvault", ".../a.larsalvault"]`, and after TERM `"state.open_at_quit": [a, b]` and `"state.last_active": ".../a.larsalvault"`. The state file is 0600. |
| SC-01 | **verified**; Mac QA note | Reference: selected text in the notes and labels goes through its clipboard with the clear (`DatabaseWidget.cpp:768` to `:780`). Larsal: `Session::copy_selection` (session.rs:939) does the same. CopySelectionTests "APP-03.7 LD-219 (4) F-081" passed alone 2 of 2 (1.9 s, 2.2 s): ⌘C and ⌘X go through Rust, AppKit's copy never runs, the concealed and transient markers are set, the text is cleared after 1 s, and the general pasteboard is untouched. The Rust clipboard tests (`countdown_clears`, `new_copy_restarts_countdown`, `countdown_leaves_newer_content`, `clear_only_while_still_ours`, `app_03_15_lock_close_and_quit_clear`) ok. In the full run, the ⌘X half failed after a 34 s wait at load 20, because another suite's field took the focus. HygieneFixesTests.swift was changed in the shared tree after my copy for that clash. The real general pasteboard stays with Mac QA. |
| SC-04 | **verified** | Reference: hide notes and hide one-time codes in the preview (`EntryPreviewWidget.cpp:95`, `:371` to `:374`, `:514`). Larsal: the 5 F-082 and F-084 tests passed (detail pane, editor, live code, the stored switches, dots for an empty password), and the 5 APP-08.8 Mask User Names tests and T16 (Mask Passwords) passed. |
| SD-01 | **verified** | Reference: after more than 2 failed saves it offers to turn off safe saving (`DatabaseWidget.cpp:2519`). Larsal: `f_087` and `f_089_safe_save_keeps_creation_date_tags_and_acl` ok; Swift "F-087 APP-05.14" passed. The link, mode, kill and full-disk checks of the first run stand (AT-I04 also passed in the E13-S2 re-run). |
| SD-03 | **verified** | `f_085` ok; Swift "F-085 APP-05.29" (both) passed; AT-I05 passed in the E13-S2 re-run. |
| SD-11 | **verified** | Reference: it watches the opened copy and asks to save it back (`EntryAttachments.cpp:255`, `EntryAttachmentsWidget.cpp:586`). Larsal: `f_086` ok; the 4 Swift F-086 tests passed; the manual lock now asks first (the F-122 tests, 6, passed); the automatic lock drops the changed copy by design (LD-227 (1)). |

### Rows that waited on 2026-10-29

| Row | Result | Proof |
|---|---|---|
| SG-05 | waits | The owner's go: the capture of a real breach check sends data off the Mac (rule 7). |
| SB-01 | waits | D7 (W-02), E14-S3. |
| SI-01, SI-02, SI-03, SI-04, SI-05, SI-10, SI-11, SI-12 | waits | E7, browser bridge (W-01, D4). |
| SR-04 | waits | E6-S3 needs a signing team (W-02, D7). The unlock screen's "Use Touch ID" is a disabled `.later` item. |
| SC-05 | **Mac QA** | E6-S5 is Done; ScreenProtectionTests passed. 3 hidden launches: both Larsal windows read `sharing=0` from their first listing; with `--allow-screen-capture` both read 1; at the next start both read 0 again. This is the reference's rule too: capture is allowed for the run only. AT-D04's real capture paths need a visible window (E13-S2 re-run: Mac QA). |
| SD-08 | **verified** | MOD-08: 48 tests ok; larsal-autotype: 106 ok. AT-G03 passed in the E13-S2 re-run (`red_g03_hostile_sequences`, slowest call 1.07 ms), which was the row's last open check. |
| SI-06 | **Mac QA** | E8-S2 and E8-S3 are Done. AutoTypeTests passed, including "AT-G01: a lookalike window gets the picker…" and the AT-G02 T90, T91 and T103 tests through the fake sink; larsal-autotype 106 ok. The reference stops on a focus change (`AutoType.cpp:350`). AT-G01 and AT-G02 need real windows and real typing. |
| SI-09, SI-13 | waits | E11 (W-15). |
| SI-14 | **Mac QA** | E8-S3 is Done. The reference asks for Accessibility and Screen Recording (`AutoType.cpp:440`, `AppKitImpl.mm:180`); Larsal asks for Accessibility only, and T94 passed through the fake permission. The real permission request needs the owner's go. |
| SN-04, SB-03 | waits | E14-S3: the release location is publishing (owner; LD-223 (4), F-095 to F-097). |
| SD-07 | **verified** | Reference: CSV, HTML and XML exports warn (`ExportDialog.cpp:42`, `DatabaseTabWidget.cpp:568`). Larsal: `sd_07_every_plain_export_warns` ok. ExportScreensTests passed all 3 tests: CSV and XML ask MSG-EXP-CONFIRM before the save panel, and No writes nothing; HTML shows the warning as its banner; the Passkeys report asks MI04-30 first. Files are written 0600. |
| SD-12 | **verified** | `f_088` ok; Swift "F-088 APP-05.33" passed. |
| SD-13 | **verified** | Reference: it previews HTML and Markdown as rich text (`TextAttachmentsPreviewWidget.cpp:139`, `:143`). Larsal: `sd_13_preview_decodes_images_in_rust_and_shows_markup_as_plain_text` ok, and the 2 Swift SD-13 tests passed (plain text inside Larsal; a link in HTML or Markdown is no link). |
| SN-02 | waits | Larsal's download for the selected entry passes: the `f_094_*` tests (5), `sn03_*` (3) and `mod_06_11_downloads` ok. The editor's and a group's downloads wait for the mockup (W-20). The extension's icon request waits for E7 (W-01). The reference's redirect capture needs its window (owner's go). |

### Notes for the lead (not filed)

1. **PlatformTests "APP-09.27-a, -b"** hit its 60 s time limit in the full run. About 47 s later the test process exited ("Restarting after unexpected exit, crash, or test timeout"), and xcodebuild ran the remaining suites in a new process. Alone it passed in 0.6 s and 0.003 s. The test sends SIGINT, SIGTERM and SIGQUIT to its own process, and its `defer` resets them to the default action. A signal that is still pending after the time limit can then end the whole test run. This is a timing test, so it is not filed. A bound inside the test, or a child process, would keep a slow run from taking the other suites with it.
2. **CopySelectionTests**' ⌘X half failed once under load (SC-01). Alone it passed twice. The HygieneFixesTests change made in the shared tree after my copy is aimed at this kind of clash.
3. **Matrix status cells.** I set the 14 verified rows to "verified 2026-10-30 (E13-S1 re-run …)". On the four Mac QA rows I noted "Mac QA open". The waiting rows keep their cells. SD-07 keeps the part m Verify status another agent set at 12:33 (security/parity/E13-S6m-fixes.md), with mine after it.

### Clean-up

My /tmp folders (`e13rr-verify-copy`, `-target`, `-dd`, `-logs`, `-home`, `-tmp`, `-scripts`, `-launch`) are deleted. No process of mine is running. The hidden Apps ended by themselves, and the auto-open one was stopped with TERM by its PID (31118).
