**The Mac app as built is safe to try with demo data: 0 Critical and 0 High findings are open. All 10 High findings are fixed and re-tested, and E13-S6 is Done (proof: section 2, and LD-253 in spec/decisions.md). The full project check of 2026-10-31 passed; its one known timing test passed when run alone (section 1).**

# E13-S7 Report to the owner

Story E13-S7 ([plan/epics.md](../../plan/epics.md), E13). As of 2026-10-31 00:51 CET: the board was read as saved at 00:49, spec/decisions.md as saved at 00:17, security/findings.md as saved at 23:50 on 2026-10-30 and the attack campaign as saved at 18:13 on 2026-10-30, after E13-S6 was signed Done (LD-253) and its part r was signed. Other agents work on E0-S7 step 3 in vendor/, crates/ and Cargo.lock now, so the E0-S7 lines can change after this time.
Writer: I did not build, check or verify any story in this report. Every number comes from a file named next to it. The five counting scripts and their output are in "Proof" at the end.

```
All 96   ████████████████████████▒░░░░░  78 done, 2 in progress, 16 to do

E0       █████████████████▒▒▒   6 of 7   (E0-S7 in progress)
E1       ████████████████████   9 of 9
E2       ████████████████████   7 of 7
E3       ████████████████████  11 of 11
E4       ████████████████████  15 of 15
E5       ██████████████████░░  11 of 12
E6       █████████████████░░░   6 of 7
E7       ░░░░░░░░░░░░░░░░░░░░   0 of 7
E8       ████████████████████   3 of 3
E9       ████████████████████   2 of 2
E10      ████████████████████   1 of 1
E11      ░░░░░░░░░░░░░░░░░░░░   0 of 1
E12      ████████████████████   1 of 1
E13      ██████████████▒▒▒░░░   5 of 7   (E13-S7 in progress)
E14      ███░░░░░░░░░░░░░░░░░   1 of 6

█ done   ▒ in progress   ░ to do
```

E13-S7 (this report) counts as in progress. The board still says "todo" for it until the lead signs it.

## 1. What was checked

| Story | What | How | Result | Proof |
|---|---|---|---|---|
| E13-S1 Parity sign-off | All 84 security features of the reference app, one row each | 8 Verify agents, one per group, read the reference source and ran App's tests and hidden launches. A second run came after the fixes. | Done 2026-10-30. 60 verified, 0 failed, 8 need a visible window (W-08), 16 wait for parked owner items. The first run had 11 failures. None fails now: 10 are verified and 1 (SR-06) needs a visible window. | [E13-S1-parity-signoff.md](E13-S1-parity-signoff.md), the group files E13-S1-SB.md to E13-S1-SR.md, [plan/security.md](../../plan/security.md); count script in "Proof" |
| E13-S2 Attack campaign | All 73 attacks in the catalog, groups A to K | The Red team ran each group on the tree, read only, with its own tools in /tmp; the re-run used a private copy. Nothing ran on your screen. A second run came after the fixes. | Done 2026-10-30. The 6 attacks that failed on 2026-10-29 pass now. Second run, 20 rows: 10 pass, 0 fail, 7 need a visible window, 3 wait (E6-S3, E5-S12). Whole catalog, both runs: 51 of 73 pass, 0 fail, 7 need a visible window, 15 wait. AT-J04 passes now: E14-S4's Verify proved two clean builds identical (LD-251 (3)). The 15: 8 browser attacks (group F) on E7; AT-K02, AT-K03 on E6-S3; AT-K05 on E5-S12; AT-E05, AT-J05 on signing (D7); AT-I07, AT-I08 on W-15. | [E13-S2-attack-campaign.md](E13-S2-attack-campaign.md), E13-S2-AT-A.md, -B, -E, -H, -I, -J; count script in "Proof" |
| E13-S3 Long fuzzing | 24 hours per fuzz target, 0 crashes | Not run. It keeps the Mac busy, so it waits for your go (W-09). | To do. Short runs of all 22 targets found 0 crashes. Earlier runs of 10 to 14.6 hours found 0 crashes (OD-05). | [E13-S2-AT-A.md](E13-S2-AT-A.md) (AT-A10), [spec/decisions.md](../../spec/decisions.md) OD-05 |
| E13-S4 Memory and process checks | Secrets left in memory after lock, debugger, crash reports, swap, logs (AT-C01 to AT-C06) | 12 memory dumps of release builds, each searched for 12 secrets | Done 2026-10-29. All 6 pass. After lock, none of the 12 secrets was found. The App.app parts wait for a visible window. | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) |
| E13-S5 Two-person review | Every `unsafe` block (60 items), crypto call (58) and secret conversion (53), plus 12 items the reviewers added | Two Checkers read every item on their own, then one merge compared them | Done 2026-10-29. No memory fault, no broken crypto, no secret an attacker can reach. 11 findings (1 Medium, 10 Low), all 11 fixed and re-tested. | [E13-S5-two-person-review.md](E13-S5-two-person-review.md) |
| E13-S6 Fix and re-test | Fix every finding until no Critical or High is open | Builders fix in parts a to r. A Checker and a Verify agent re-test each part. | Done 2026-10-30 (LD-253 (2)). Parts a to q are signed; no Critical or High is open. Part r came after Done, Low only: it fixed F-135 and F-136, its Verify signed both as re-tested on 2026-10-30, and LD-256 accepts F-135 (1). Part o fixed F-131 and re-tested F-081 (High); both rows read "fixed, re-tested (Verify 2026-10-30)". Part p fixed F-133; its second half is accepted (LD-252). Part q fixed F-134. Moved out: F-113 and F-114 to E0-S7 (re-tested in its step 1 Verify), F-095 to F-097 to E14-S3, with two small part o items (LD-253 (3)). | E13-S6a-fixes.md to [E13-S6q-fixes.md](E13-S6q-fixes.md) (part c: [E13-S6c-name-guard-verify.md](E13-S6c-name-guard-verify.md), E13-S6c-checker-r3.md), [E13-S6o-fixes.md](E13-S6o-fixes.md), [E13-S6p-fixes.md](E13-S6p-fixes.md), [E13-S6r-fixes.md](E13-S6r-fixes.md), [spec/decisions.md](../../spec/decisions.md) LD-251 to LD-253, LD-256 |
| E13-S7 Report to the owner | This page | Read and counted the files above | In progress | This file |

**Full project check.** scripts/check.sh on the shared tree, run 3 on 2026-10-31 from 00:17 to 00:42, after `cargo clean --profile dev` (LD-257). G1 static checks: PASS (unsafe count 368 in 11 crates). G2 tests: every Rust test passed (2,752 in the check's logs, 0 failed). 348 of 349 Swift tests passed. The one left was APP-01.27 c, the known timing test (load 7 to 16). It then passed alone 3 of 3 (load 11 to 13), so it counts as passed under your rule for timing tests (owner rule 2026-10-29, LD-250 (2)). The app09 tests, which the Swift step skips after a failure, passed alone, 18 of 18. deny: PASS. audit: PASS. Fuzz smoke: PASS (22 targets, 30 s each). Earlier runs, on 2026-10-30: 20:14 failed on F-135 and the F-127 test, both fixed in part r; 23:50 failed only on stale build files of removed packages (LD-257). Logs are in target/check/, which is not kept; their counts are in "Proof" (check logs).

## 2. What was found

The findings list has 136 rows, F-001 to F-136 ([security/findings.md](../findings.md), as saved at 23:50 on 2026-10-30).

| Status | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Fixed and re-tested | 0 | 10 | 32 | 75 | 117 |
| Fixed, waiting re-test | 0 | 0 | 1 | 8 | 9 |
| Accepted with a ruling | 0 | 0 | 0 | 7 | 7 |
| Open | 0 | 0 | 1 | 2 | 3 |
| **Total** | **0** | **10** | **34** | **92** | **136** |

- **Open (3).** F-095, F-096 (Low) and F-097 (Medium) need the release place, which is publishing, so they moved to E14-S3 (LD-223 (4)).
- **Re-tested since the 17:57 count (8).** F-081 (High) and F-131 (Low) in part o ([E13-S6o-fixes.md](E13-S6o-fixes.md)). F-133 (Low) in part p ([E13-S6p-fixes.md](E13-S6p-fixes.md)). F-134 (Low, new: a speed test that failed on a fast Mac) in part q ([E13-S6q-fixes.md](E13-S6q-fixes.md)). F-113 (Medium) and F-114 (Low) in the E0-S7 step 1 Verify ([E0-S7-step1.md](E0-S7-step1.md)). F-135 (Low, new: the accessibility walk with Caps Lock down) and F-136 (Low, new: Undo in a shown protected field could bring back the old value after another window closed in the middle of an edit) in part r ([E13-S6r-fixes.md](E13-S6r-fixes.md), Verify); both rows read "fixed, re-tested (Verify 2026-10-30)".
- **Waiting re-test (9).** F-054 and F-055 were in the old web screen layer, which no longer exists (LD-155, LD-156). F-022, F-023, F-030 and F-057 have no re-test on record. The lead fixed F-117, F-118 and F-132 and checked them himself, but nobody else has re-tested them. The full list is in "Proof".
- **Accepted (7), all Low.** F-021, F-024, F-032, F-033, F-035, F-059, F-116. Each row says why. F-035, F-059 and F-116 have a lead ruling (LD-226 (1); the lead, 2026-10-28; LD-225 (2)). F-032 and F-033 were accepted at the E2-S7 gate (plan/epics.md). F-021 and F-024 are by-design limits of the name guard. F-133's second half is also accepted (LD-252): a test run on a Mac where App has an attachment open removes that open copy; the attachment in the vault is unchanged. F-135's part (1) is also accepted (LD-256): the Caps Lock sign in the unlock screen's password field is AppKit's own, as in every Mac password field. F-135 counts as re-tested, because its part (2) is fixed.

The 5 most serious, all High:

1. **F-101: Save and Lock could freeze.** What: when someone put a special pipe file in place of the vault file, Save waited forever. Lock waits for Save, so the vault stayed unlocked. What we did: App now refuses any vault path that is not a plain file, before it opens it. Proof: [E13-S6g-fixes.md](E13-S6g-fixes.md) (Verify signed); [E13-S2-attack-campaign.md](E13-S2-attack-campaign.md), "Re-run after E13-S6": no call waits on a pipe.
2. **F-085: A password change made elsewhere could be lost.** What: when another window changed the vault's password and saved, App dropped that window's new entries and put the old password back. What we did: App now asks for the new password, then merges. Proof: [E13-S6e-fixes.md](E13-S6e-fixes.md); row SD-03 is verified in the re-run of [E13-S1-parity-signoff.md](E13-S1-parity-signoff.md).
3. **F-081: Copied note text stayed on the clipboard.** What: when you selected text in Notes and copied it, it went to the clipboard with no "secret" mark and was never cleared. What we did: this copy now goes through App's own clipboard code. It is marked secret and cleared after the countdown and on lock. Proof: [E13-S6o-fixes.md](E13-S6o-fixes.md) (Verify): CopySelectionTests passed 3 of 3, and with the old copy put back it failed 3 of 3; a probe showed lock and quit clear the copy. Its row reads "fixed, re-tested (Verify 2026-10-30)". The real key press in a visible window waits for W-08.
4. **F-025: Password bytes stayed in memory.** What: after a hash, all 20 of 20 password bytes stayed in memory that App no longer used. What we did: fixed in the crypto code. The Red team re-test found no password bytes left. Proof: row F-025 in [security/findings.md](../findings.md); E2-S7 on [plan/epics.md](../../plan/epics.md).
5. **F-036: A small bad file could use gigabytes of memory.** What: a hostile vault file of 761 KB made App use 4.9 GB of memory while reading it. What we did: each value is now built in one buffer that wipes itself. The same file now peaks at 0.89 GB. Proof: row F-036 in [security/findings.md](../findings.md) (LD-85).

The other 5 High findings are fixed and re-tested. F-001: the name guard skipped binary files. F-076: no Caps Lock warning in 3 password fields. F-077: no notice of expired entries after unlock. F-082: "Hide notes" and "Hide one-time codes" did nothing. F-086: edits to an opened attachment were lost. Proof: their rows in [security/findings.md](../findings.md).

## 3. What is left

1. **A test session with windows on your screen (W-08).** These checks wait for it: 8 parity rows (SF-03, SR-01, SR-02, SR-06, SR-07, SC-05, SI-06, SI-14), 7 attacks (AT-D01, AT-D04, AT-D05, AT-G01, AT-G02, AT-K01, AT-K06), the App.app parts of E13-S4 (debugger, a forced crash, swap, logs), E5-S12 (does every screen match the mockup), and every other case the W-08 row lists (a real key, real typing, the 11 E1-S5 card markers, F-047 on an SMB share, F-102 and the save panels in a visible window, a real Command-Q behind a slow save), now also the deferred-window order-in path, F-081's real key press (part o Verify) and F-136's steps (close Settings in the middle of an edit, then Show, type and ⌘Z in a shown protected field; part r Verify). Rows and attacks that already pass also have a part left for this session: SC-01, SC-02, SC-03, SC-07, SC-08, SF-15, SF-16, SR-05, SI-07, SI-08, and AT-A01, AT-D02, AT-D03, AT-E08, AT-H03, AT-H04 (the general pasteboard, real dialogs, a debugger, a real key, a Release app with its window), and SN-02, which also waits on W-20 and E7: the capture of the reference's redirects needs its window and your go. Code work goes on until then, as you said on 2026-10-29. Proof: [spec/decisions.md](../../spec/decisions.md) W-08, [plan/security.md](../../plan/security.md) ("Mac QA open" cells), [E13-S1-parity-signoff.md](E13-S1-parity-signoff.md) ("For the lead", line 133; SN-02 re-run row, line 184), [E13-S2-attack-campaign.md](E13-S2-attack-campaign.md) ("Mac QA and the owner's go" and the re-run), [E13-S6o-fixes.md](E13-S6o-fixes.md) (Verify: "the order-in path (Mac QA, W-08)", "The key press in a visible window is Mac QA (W-08)"), [E13-S6r-fixes.md](E13-S6r-fixes.md) (Verify: "Left for Mac QA (W-08): F-136's visible-window steps") and row F-136 in [security/findings.md](../findings.md).
2. **Work parked for your decisions.** E7 browser bridge (W-01, D4: 7 stories, 8 attacks, 8 parity rows). E11 shared groups and sync (W-15; attacks AT-I07, AT-I08). E6-S3 Touch ID (AT-K02, AT-K03) and E14-S3 signing (AT-E05, AT-J05) (W-02, D7). E14-S1, E14-S2 and E14-S5: name, license, audit (W-03; D1, D2, D6). E14-S6 publishing, with the release place that F-095 to F-097 need. Icon downloads (W-20), 12 mockup proposals, and your go for one breach-check test that sends data off this Mac (SG-05, rule 7). The 16 waiting parity rows and 14 of the 15 waiting attacks belong to these items; AT-K05 waits on E5-S12 (item 1). Proof: [E13-S1-parity-signoff.md](E13-S1-parity-signoff.md), "Rows that waited"; [E13-S2-attack-campaign.md](E13-S2-attack-campaign.md), "Every catalog row".
3. **Long fuzzing (W-09, E13-S3).** It needs 24 hours for each of the 22 targets in `fuzz/fuzz_targets/`, with the Mac busy all that time. It waits for your go. Proof: [spec/decisions.md](../../spec/decisions.md) OD-05 and W-09.
4. **Small items E13-S6 left for later.** The 9 rows that wait for a re-test (section 2) still need one, or a ruling. Two small part o items go to E14-S3 with F-095 to F-097: two Auto-Type panels are not deferred yet (one word each), and one code comment says "every 0.5 ms" where 0.5 ms is the pause between reads (LD-253 (3)). At E14, debug and test builds get their own folder for opened attachments (LD-252 (2)). F-131's residual is accepted: a window AppKit makes itself can list as shareable at 0x0 for about two reads, with no size and no content, never on screen (LD-253 (1)). F-135 (1) is accepted: the Caps Lock sign in the unlock screen's password field is AppKit's own (LD-256 (1)). None of these changes the security claim. Proof: [spec/decisions.md](../../spec/decisions.md) LD-252, LD-253, LD-256.
5. **E0-S7, App's own copy of every outside package.** Step 1 is signed: Verify passed it on 2026-10-30 and re-tested F-113 and F-114 ([E0-S7-step1.md](E0-S7-step1.md)). Step 2 cut the 38 stub packages that are never built on a Mac out of `vendor/crates-io` and both lockfiles. Checker 1 sent it back 3 times. The lead ruled (LD-254): take the last two fixes, then Checker 1 re-checks; it sent it back once more (section 17), then passed; `scripts/check-vendor.sh` is a tripwire, and the control against a rewritten copy is the review of each update. Step 2 is signed (LD-255; [E0-S7-step2.md](E0-S7-step2.md), Verify). Step 3 replaces packages with our own code in three batches, one after another, because each one rewrites Cargo.lock and vendor/crates-io (LD-255 (3)): 3a the zxcvbn copy (R1, R2, R3, R7, R11), 3b four packages (R4, R5, R6, R8), 3c three more (R9, R10, R12). As of the board saved at 00:49, 3a is built, passed both Checkers and is signed by Verify ([E0-S7-step3a.md](E0-S7-step3a.md)). 3b is built and its Checker is next: R4 and R6 are done; R5 and R8 are not built, because each stops at a rule, so they go to the lead ([E0-S7-step3b.md](E0-S7-step3b.md)). The board shows no 3c work yet. Steps 4 and 5 are left: trim the copies (R13 and R14 go with these trims), then the build tools. Proof: [spec/research/dependencies.md](../../spec/research/dependencies.md), sections 8 and 10; [spec/decisions.md](../../spec/decisions.md) LD-254, LD-255.

## 4. What you decide

None of these stops work today. Each one has the lead's pick.

1. **Two times on your Mac, and one test that leaves it.** W-08: a test session with windows on your screen. Pick: you choose the time. W-09: 24-hour fuzzing. Pick: overnight runs, with fewer targets at a time if needed (E13-S3). SG-05: one breach-check test sends data off this Mac (rule 7), so it needs your go. Pick (LD-251 (2)): yes, in the W-08 session, demo passwords only. It sends only the first 5 hex characters of each password's hash, so nothing secret leaves ([E13-S1-SG.md](E13-S1-SG.md), SG-05).
2. **12 mockup proposals** (W-04, W-05, W-06, W-10 to W-14, W-16, W-17, W-19, W-20), drawn in [design/option-a/proposals.html](../../design/option-a/proposals.html). Pick: OK them as drawn. W-07 (browser words) gets drawn when E7 starts.
3. **What is in the first release.** D4 and W-01, the browser extension. Pick: our own, right after the Mac app. W-15, E11. Pick: shared groups in, remote sync out for the first release. W-18, new wording for rules 3 and 4 of AGENTS.md (the W-18 row; LD-220, LD-194). Pick: take it. The code already follows it, so nothing waits on it.
4. **Money.** D7 and W-02, the Apple Developer account ($99 a year). Pick: buy it before E14. Until then, a free personal team (your Apple ID in Xcode) is enough for Touch ID. D6, an outside security audit before 1.0. Pick: yes.
5. **Release.** D1, the name. Pick: choose it before E14. D2, the license. Pick: GPL-3.0-or-later. D5, git. Pick: local git now, no remote until release. E14-S6, publishing. Pick: only on your go, after the name, license, audit and signing.

Proof: [spec/decisions.md](../../spec/decisions.md) "Waiting for the owner" (W-01 to W-20) and LD-251, and [README.md](../../README.md) "Owner decisions" (D1 to D7).

## 5. Your next step (2 minutes)

Send the lead one time slot when windows may open on your screen (W-08). That one answer unblocks 8 parity rows, 7 attacks, the mockup match (E5-S12), and the window parts of the checks that already pass (section 3 item 1).

## Proof

All five scripts run from the project root, read only, and change nothing.

**Findings count** (run 2026-10-31 00:48, over security/findings.md as saved at 2026-10-30 23:50:21). The draft's run at 17:59 over the 17:57 file gave 133 rows: 109 re-tested, 12 waiting, 7 accepted, 5 open. The run at 20:19 over the 20:07 file gave 134 rows: 115 re-tested, 9 waiting, 7 accepted, 3 open. Since 20:07, F-135 and F-136 were filed, and part r re-tested both (section 2).

```
python3 -I - <<'EOF'
import collections, re
def cells(line):  # split a table row on | outside `code`; \| is a literal pipe
    out, cur, tick, i, s = [], '', False, 0, line.strip().strip('|')
    while i < len(s):
        ch = s[i]
        if ch == '\\' and s[i+1:i+2] == '|': cur += '|'; i += 2; continue
        if ch == '`': tick = not tick
        if ch == '|' and not tick: out.append(cur.strip()); cur = ''
        else: cur += ch
        i += 1
    return out + [cur.strip()]
def bucket(status, proof):
    s, p = status.lower(), proof.lower()
    if s.startswith('fixed, re-tested'): return 'fixed and re-tested'  # a part accepted after it stays in the cell
    if 'accepted' in s: return 'accepted with a ruling'
    if s.startswith('open'): return 'open'
    if 'pending' in s or 'next verify' in s or 're-test at the' in s: return 'fixed, waiting re-test'
    if 're-tested' in s or s.startswith('verified') or re.search(r're-test|re-ran|re-run', p): return 'fixed and re-tested'
    return 'fixed, waiting re-test'   # fixed, but no re-test recorded
rows = [cells(l) for l in open('security/findings.md') if l.startswith('| F-')]
assert all(len(r) == 7 for r in rows) and len({r[0] for r in rows}) == len(rows)
t = collections.Counter((r[2], bucket(r[5], r[6])) for r in rows)
sev = ['Critical', 'High', 'Medium', 'Low']; bk = ['fixed and re-tested', 'fixed, waiting re-test', 'accepted with a ruling', 'open']
print('rows', len(rows), rows[0][0], 'to', rows[-1][0])
print('%-24s' % '', *['%8s' % s for s in sev], '   total')
for b in bk: print('%-24s' % b, *['%8d' % t[(s, b)] for s in sev], '%8d' % sum(t[(s, b)] for s in sev))
print('%-24s' % 'total', *['%8d' % sum(t[(s, b)] for b in bk) for s in sev], '%8d' % len(rows))
for b in bk[1:]: print(b + ':', ' '.join(r[0] + '(' + r[2][0] + ')' for r in rows if bucket(r[5], r[6]) == b))
EOF
```

Output:

```
rows 136 F-001 to F-136
                         Critical     High   Medium      Low    total
fixed and re-tested             0       10       32       75      117
fixed, waiting re-test          0        0        1        8        9
accepted with a ruling          0        0        0        7        7
open                            0        0        1        2        3
total                           0       10       34       92      136
fixed, waiting re-test: F-022(L) F-023(L) F-030(L) F-054(M) F-055(L) F-057(L) F-117(L) F-118(L) F-132(L)
accepted with a ruling: F-021(L) F-024(L) F-032(L) F-033(L) F-035(L) F-059(L) F-116(L)
open: F-095(L) F-096(L) F-097(M)
```

Rules: the Status cell decides. A cell that starts with "fixed, re-tested" is re-tested, even when it names a part accepted after that. This rule is new at 00:48 for F-135, whose cell reads "fixed, re-tested (Verify 2026-10-30); (1) accepted, LD-256". Without it, the same script moves F-135 alone to "accepted" (116 re-tested, 8 accepted), and no other row. Then "accepted" means accepted. A cell that starts with "open" is open. "pending", "confirm at the next Verify" or "re-test at the" mean waiting. "re-tested", "verified", or a re-test written in the fix proof cell means re-tested. Any other fix counts as waiting. That rule puts the lead's own fixes (F-117, F-118, F-132) in "waiting". F-081's Status cell now reads "fixed, re-tested (Verify 2026-10-30)" (part o Verify, LD-251 (1)), so the script counts it as re-tested. F-133's cell reads re-tested too; its accepted second half is in the row text and LD-252, not in its Status cell.

**Story count** (run 2026-10-31 00:51, over plan/epics.md as saved at 00:49:28; the run at 20:19 over the 20:12 board gave the same 78, 2 and 16; the draft's run at 17:59 over the 17:57 board gave 77 done, 3 in progress, 16 to do, before E13-S6 was signed Done):

```
python3 -I - <<'EOF'
import re, collections
stories, cur = [], None
for line in open('plan/epics.md'):
    m = re.match(r'\*\*(E\d+-S\d+)', line)
    if m or line.startswith('## E11'): cur = [m.group(1) if m else 'E11-S1', '']; stories.append(cur)
    elif line.startswith('## '): cur = None
    if cur: cur[1] += line
def state(sid, text):
    st = text.split('Status:', 1)[1].strip()
    if re.match(r'(done|\*\*Done\*\*)', st, re.I) or re.search(r'\*\*Done\*\* 2026', st): return 'done'
    if sid == 'E13-S7': return 'doing'          # this report is being written now
    return 'todo' if re.fullmatch(r'todo\W*(Epic checks.*)?', st, re.S) else 'doing'
def bar(d, p, n, w):
    a = round(d / n * w); b = round((d + p) / n * w) - a
    return '█' * a + '▒' * b + '░' * (w - a - b)
per = collections.defaultdict(collections.Counter)
for sid, text in stories: per[sid.split('-')[0]][state(sid, text)] += 1
tot = sum(per.values(), collections.Counter()); n = sum(tot.values())
print('All  %s  %d of %d done, %d in progress, %d to do' % (bar(tot['done'], tot['doing'], n, 30), tot['done'], n, tot['doing'], tot['todo']))
for e in sorted(per, key=lambda e: int(e[1:])):
    c = per[e]; k = sum(c.values())
    print('%-4s %s  %2d/%-2d' % (e, bar(c['done'], c['doing'], k, 20), c['done'], k) + ('  %d in progress' % c['doing'] if c['doing'] else ''))
print([s for s, t in stories if state(s, t) == 'doing'])
EOF
```

Output (trailing spaces cut):

```
All  ████████████████████████▒░░░░░  78 of 96 done, 2 in progress, 16 to do
E0   █████████████████▒▒▒   6/7   1 in progress
E1   ████████████████████   9/9
E2   ████████████████████   7/7
E3   ████████████████████  11/11
E4   ████████████████████  15/15
E5   ██████████████████░░  11/12
E6   █████████████████░░░   6/7
E7   ░░░░░░░░░░░░░░░░░░░░   0/7
E8   ████████████████████   3/3
E9   ████████████████████   2/2
E10  ████████████████████   1/1
E11  ░░░░░░░░░░░░░░░░░░░░   0/1
E12  ████████████████████   1/1
E13  ██████████████▒▒▒░░░   5/7   1 in progress
E14  ███░░░░░░░░░░░░░░░░░   1/6
['E0-S7', 'E13-S7']
```

E11 has no stories of its own on the board, so it counts as one story ("E11-S1" in the script). That makes 96. A status counts as done when it starts with "done", or when it carries a bold "Done" with a date later on (for example E5-S1: "built ... **Done** 2026-10-28"). A status of "todo" with built work after it (E0-S7) counts as in progress. E13-S7 counts as in progress while this report is written.

**Parity matrix count** (run 2026-10-31 00:48, over plan/security.md as saved at 2026-10-30 12:35:18, the same file as the 20:19 run). It gives the same 60, 0, 8 and 16 as [E13-S1-parity-signoff.md](E13-S1-parity-signoff.md) ("Re-run after E13-S6") and LD-249.

```
python3 -I - <<'EOF'
import re, collections
rows = {}
for l in open('plan/security.md'):
    if re.match(r'\| S[A-Z]-\d+ ', l): rows[l.split('|')[1].strip()] = l.rstrip().rstrip('|').rsplit('|', 1)[1].strip().lower()
# the sign-off counts these as Mac QA: SR-01, SR-02, SR-07 ("verified, Mac QA open") and SF-03 (first-run Mac QA)
macqa_rule = {'SR-01', 'SR-02', 'SR-07', 'SF-03'}
def bucket(k, s):
    if k in macqa_rule or 'mac qa open' in s and not s.startswith('verified'): return 'Mac QA'
    if s.startswith('verified'): return 'verified'
    if s.startswith('fail'): return 'failed'
    return 'waits'
b = {k: bucket(k, s) for k, s in rows.items()}
c = collections.Counter(b.values())
print('rows', len(rows), *('%s %d' % (x, c[x]) for x in ('verified', 'failed', 'Mac QA', 'waits')))
for x in ('Mac QA', 'waits'): print(x + ':', ' '.join(k for k in rows if b[k] == x))
EOF
```

Output:

```
rows 84 verified 60 failed 0 Mac QA 8 waits 16
Mac QA: SF-03 SR-01 SR-02 SR-06 SR-07 SC-05 SI-06 SI-14
waits: SR-04 SG-05 SI-01 SI-02 SI-03 SI-04 SI-05 SI-09 SI-10 SI-11 SI-12 SI-13 SN-02 SN-04 SB-01 SB-03
```

Rules: the Status cell decides, as the sign-off counts it. A cell that starts with "verified" is verified, and "built; Mac QA open" needs a visible window. The sign-off counts four rows as Mac QA by its own rule (its "Counts per group" note and its re-run): SR-01, SR-02 and SR-07 ("verified, Mac QA open" in the SR group) and SF-03 (a first-run Mac QA row whose cell says "todo"). SC-02, SC-03, SC-07 and SC-08 carry the same "verified, Mac QA open" cell, and the SC group counts them as verified. Every other cell ("todo") waits.

**Attack catalog count** (run 2026-10-31 00:48, over security/parity/E13-S2-attack-campaign.md as saved at 2026-10-30 18:13:48, the same file as the 20:19 run; the draft's run at 18:00 over the 12:15 file gave 50 pass and 16 wait, before the AT-J04 cell was set to pass, LD-251 (3)). A row of "Every catalog row" takes its result from the "Re-run after E13-S6" table when the re-run has it.

```
python3 -I - <<'EOF'
import re, collections
first, rerun, sec = {}, {}, ''
for l in open('security/parity/E13-S2-attack-campaign.md'):
    if l.startswith('## '): sec = l
    m = re.match(r'\| (AT-[A-K]\d\d) \| ([^|]*) \| ([^|]*) \|', l)
    if m and sec.startswith('## Every catalog'): first[m.group(1)] = m.group(3).strip()
    elif m and sec.startswith('## Re-run'): rerun[m.group(1)] = m.group(2).strip()
def bucket(s):
    s = s.lower()
    if s.startswith('pass'): return 'pass'
    if s.startswith('fail'): return 'fail'
    if 'mac qa' in s: return 'Mac QA'
    return 'wait'
res = {k: bucket(rerun.get(k) or v) for k, v in first.items()}
c = collections.Counter(res.values())
print('rows', len(first), 're-run', len(rerun), *('%s %d' % (b, c[b]) for b in ('pass', 'fail', 'Mac QA', 'wait')))
for b in ('Mac QA', 'wait'): print(b + ':', ' '.join(k for k in res if res[k] == b))
EOF
```

Output:

```
rows 73 re-run 20 pass 51 fail 0 Mac QA 7 wait 15
Mac QA: AT-D01 AT-D04 AT-D05 AT-G01 AT-G02 AT-K01 AT-K06
wait: AT-E05 AT-F01 AT-F02 AT-F03 AT-F04 AT-F05 AT-F06 AT-F07 AT-F08 AT-I07 AT-I08 AT-J05 AT-K02 AT-K03 AT-K05
```

Rules: the result cell decides. A cell that starts with "pass" or "passed" passes, even when a part waits for Mac QA (those parts are in section 3 item 1). "fail" fails. "Mac QA" alone needs a visible window. Every other cell waits.

**Check logs count** (run 2026-10-31 00:48, over target/check/ as the lead's run 3 left it; the next run of scripts/check.sh writes over these logs). It backs the numbers in "Full project check" (section 1).

```
bash <<'EOF'
cd target/check
stat -f '%Sm %N' -t '%m-%d %H:%M' unsafe.log test.log test-net.log test-release.log app09.log xcode-test.log deny.log audit.log
grep -E '^[a-z0-9_-]+: [0-9]+ unsafe' unsafe.log | awk '{s += $2} END {print "unsafe:", NR, "crates,", s}'
for f in test.log test-net.log test-release.log app09.log; do grep '^test result:' $f | awk -v f=$f '{p += $4; x += $6} END {print f ":", NR, "result lines, passed", p, "failed", x}'; done
cat test.log test-net.log test-release.log app09.log | grep '^test result:' | awk '{p += $4; x += $6} END {print "rust total: passed", p, "failed", x}'
grep -E '^✘ Test (run|"[^"]*" failed)' xcode-test.log
tail -1 deny.log
grep -c '^error' audit.log | awk '{print "audit error lines:", $1}'
ls fuzz-*.log | grep -vc fuzz-list | awk '{print "fuzz logs:", $1}'
grep -h '^Done [0-9]* runs' fuzz-*.log | awk '{print $5}' | sort -n | uniq -c | awk '{printf "%s at %s s; ", $1, $2} END {print ""}'
grep -l -E 'deadly signal|panicked|ERROR: libFuzzer' fuzz-*.log | wc -l | awk '{print "fuzz logs with a crash:", $1}'
EOF
```

Output (trailing spaces cut):

```
10-31 00:20 unsafe.log
10-31 00:25 test.log
10-31 00:25 test-net.log
10-31 00:25 test-release.log
10-31 00:03 app09.log
10-31 00:30 xcode-test.log
10-31 00:30 deny.log
10-31 00:30 audit.log
unsafe: 11 crates, 368
test.log: 102 result lines, passed 2439 failed 0
test-net.log: 3 result lines, passed 45 failed 0
test-release.log: 6 result lines, passed 250 failed 0
app09.log: 1 result lines, passed 18 failed 0
rust total: passed 2752 failed 0
✘ Test "APP-01.27 c: a change of selected entry restarts a running search clear countdown from full" failed after 16.755 seconds with 1 issue.
✘ Test run with 349 tests in 51 suites failed after 192.889 seconds with 1 issue.
advisories ok, bans ok, licenses ok, sources ok
audit error lines: 0
fuzz logs: 22
21 at 31 s; 1 at 32 s;
fuzz logs with a crash: 0
```

Notes: app09.log was written at 00:03, before run 3 began at 00:17. In scripts/check.sh (g2, lines 114 to 117) app09 runs only after xcode-test passes, so run 3 skipped it after APP-01.27 c, and this log comes from an earlier run. Its 18 are inside the 2,752. The 3 of 3 alone runs of APP-01.27 c and the load figures are the lead's record; these logs do not hold them. The audit log names one allowed warning (an unmaintained package), not an error.
