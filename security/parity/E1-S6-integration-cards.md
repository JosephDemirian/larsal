# E1-S6 Integration cards: Verify

Story: E1-S6 Integration cards, INT-01 to INT-10 (`spec/integrations/`).
Date: 2026-10-28. Role: Verify. I did not write or review these cards.
Read first: AGENTS.md, the E1-S6 line in plan/epics.md, spec/README.md (template and the Integrations list), the Review section of every INT card, spec/decisions.md LD-171 to LD-177, LD-189, LD-191, LD-215 and W-15, the Checker result (sample, then re-check after the fixes).

Reference access: the reference source only (develop, commit 09e34ba8), read for the INT-09 spot checks and for the overlap sweep. `$REF_SRC` below stands for that checkout; its path is kept outside this folder. The reference app and its command line tool were not run. No network, no clipboard, no window. My scripts lived in `/tmp/e1s6ver/` (deleted at the end); no process was left running.

**Verdict: signed.** All six checks pass: 10 of 10 cards follow the template; 389 rules, 785 test cases, 0 rules without a test case; a second Spec review is recorded for every card; names PASS; the Checker's sample passed and my own sweep finds no reference code; 18 of 18 INT-09 rules I compared with the source match what the cards say about the reference.

| Check (plan/epics.md S1 to S6) | Result |
|---|---|
| 1 Every card follows the template | PASS, 10 of 10 (§1) |
| 2 Every rule has an ID and at least one test case | PASS: 389 rules, 785 cases, 0 untested (§2) |
| 3 A second Spec agent reviewed it | PASS, 10 of 10 recorded (§3) |
| 4 Name guard | PASS (§4) |
| 5 Checker sample, no reference code | PASS (§5) |
| 6 Spot check of INT-09 against the source | PASS, 18 of 18 rules (§6) |

## 1. Template, by script

`python3 -I /tmp/e1s6ver/check_cards.py .` (run from the project folder). For each card it checks:
- the header: line 1 is `# <ID> <Title>`, and `Status:`, `Epics:` and `Parity rows:` lines follow;
- the template's seven sections are there, in order: What it does, Inputs and outputs, Rules, Edge cases and errors, Security notes, Test cases, How this was learned. Other sections may sit between them (Lead decisions is optional in the template);
- there is a Review section.

Output (section lists):

```
INT-01 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-02 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-03 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-04 What it does > Inputs and outputs > Rules > Edge cases and errors > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-05 What it does > Inputs and outputs > Rules > Edge cases and errors > Not on Mac > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-06 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-07 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > How this was learned > Review 2026-10-28
INT-08 What it does > Inputs and outputs > Rules > Messages > Edge cases and errors > Lead decisions > Security notes > Test cases > Owner summary > How this was learned > Review 2026-10-28
INT-09 What it does > Inputs and outputs > Rules > Edge cases and errors > Lead decisions > Security notes > Test cases > Owner summary > How this was learned > Review 2026-10-28
INT-10 What it does > Inputs and outputs > Rules > Edge cases and errors > Parity table > Security notes > Test cases > How this was learned > Review 2026-10-28
```

Every card: `header=ok order=ok review=yes`. INT-09 keeps its messages table as a `### Messages` part of Rules, and its decisions D-INT09-1 to D-INT09-9 have options, a recommendation and evidence. D-INT09-1 (E11's scope) says "Owner's call; facts in 'Owner summary'". It gives facts and a suggestion; it does not decide the scope.

## 2. Rule IDs and test cases, by script

The same script does the following:
- A rule is a line in the Rules section that starts with `<ID>.<n>`.
- A test case is a table row in the Test cases section, not counting the header and divider rows.
- A test case names a rule when the rule's ID is in its Case cell (the first column), or falls inside a range written there ("INT-0x.a to INT-0x.b"). Mentions in Given, When or Then do not count, so this test is stricter than reading the whole row.

```
INT-01 rules=42 tests=77 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-02 rules=32 tests=75 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-03 rules=19 tests=90 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-04 rules=55 tests=82 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-05 rules=47 tests=111 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-06 rules=44 tests=74 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-07 rules=33 tests=53 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-08 rules=40 tests=65 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-09 rules=30 tests=54 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
INT-10 rules=47 tests=104 untested=0 dup_rules=- dup_cases=- unknown_refs=- -> PASS
TOTAL rules=389 tests=785 cards_failing=0
```

These are the same counts the Checker got (389 and 785), from my own script.

Numbering, `python3 -I /tmp/e1s6ver/gaps.py .`: rules are numbered in order in every card. No rule line sits outside a Rules section. Only INT-01 has gaps: 16 to 19, 39 and 43. Its line 68 says they are retired. `grep -rnE "INT-01\.(16|17|18|19|39|43)\b" spec plan` finds them only on that line.

Cross references, `python3 -I /tmp/e1s6ver/xref.py .`. Every rule ID the ten cards cite (INT, FMT, MOD, APP, FEA, CRY) exists as a rule in spec/. So does every LD and W row (spec/decisions.md), every parity row (plan/security.md) and every attack (plan/attacks-and-checks.md). The only "unknown" IDs are INT-01's retired numbers on line 68. For remote sync, the rows exist: SI-13 (temp copy, commands without a shell), AT-I07 (planted commands), AT-I08 (hostile commands and downloads), AT-I06 (owner-only files) and AT-C06 (logs). SR-07 covers the copy's credentials.

## 3. Second Spec review, per card

| Card | Card's Review section | Decision row | Other records |
|---|---|---|---|
| INT-01 | "Second Spec review", line 420 | LD-191 (findings), LD-189 (decisions) | status line: "INT-01 to INT-03 second review 2026-10-28: done (28 fixes, 9 findings)" |
| INT-02 | line 333 | LD-191, LD-189 | same |
| INT-03 | line 295 | LD-191, LD-189 | same |
| INT-04 | line 565 (written for Checker F3) | LD-215 (recorded; R04-1 waits for the lead before E7-S5) | status line "F3 INT-04 second Spec review done (13 fixes …, LD-215)"; spec/README.md |
| INT-05 | line 503 | LD-177, LD-176 | status line "(27 fixes, 8 findings)" |
| INT-06 | line 433 | LD-175, LD-173 | status line "INT-06, INT-07 second review 2026-10-28: done (29 fixes, 9 findings)" |
| INT-07 | line 268 | LD-175, LD-173 | same |
| INT-08 | line 398 ("together with INT-09"; 12 fixes, R08-1 to R08-3, each marked fixed) | none; D-INT08-1 waits for W-15 | status line "INT-08 and INT-09 second review 2026-10-28: 27 fixes, 5 findings"; spec/README.md "27 fixes (INT-08 12, INT-09 15), 5 findings" |
| INT-09 | line 320 (15 fixes, R09-1 and R09-2, each marked fixed) | none; D-INT09-1 waits for W-15 | same two records |
| INT-10 | line 579 | LD-172, LD-171 | status line "INT-10 second review 2026-10-28: done (19 fixes, 4 findings ruled, LD-172)" |

The task text said INT-09 was not written and INT-08 had no recorded review. Both are out of date: INT-09 is written (30 rules, 54 cases), and the INT-08 and INT-09 review is recorded in three places.

## 4. Name guard

```
$ bash scripts/check-names.sh
Names: PASS (3097 files scanned, 15 vault files name-only)
exit=0
```

I ran it before my edits and again after them (this file, the five status lines, the E1-S6 line). The second run is in the Edits section.

## 5. Checker sample, and my own sweep for copied code

The Checker's re-check passed. Its proof is in the E1-S6 status line: "Checker sample 2026-10-28: passed (re-check after the fixes)". It compared 52 rules with the source, found F1 to F4 fixed, and found no copied code.

My own sweep, `python3 -I /tmp/e1s6ver/sweep.py "$REF_SRC" .`, took every comment, every string literal and every code line longer than 25 characters (white space removed) from the reference's `src/**/*.cpp` and `*.h`, with the licence header left out:

```
INT-01 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-02 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-03 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-04 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-05 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-06 comment-7gram hits: 0 string-7gram hits: 1 verbatim code lines: 0
INT-07 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
INT-08 comment-7gram hits: 0 string-7gram hits: 19 verbatim code lines: 0
INT-09 comment-7gram hits: 0 string-7gram hits: 16 verbatim code lines: 0
INT-10 comment-7gram hits: 0 string-7gram hits: 0 verbatim code lines: 0
```

- No card shares a run of 7 words with any reference comment.
- No card holds a reference code line.
- INT-06's one string hit is the W3C XML Schema instance namespace URI, a public standard name.
- Every string hit in INT-08 and INT-09 is a reference UI text in the "Reference (source)" column of the Messages tables. The card rules allow these. `python3 -I /tmp/e1s6ver/cols.py "$REF_SRC" INT-08… INT-09…` checked every MI row and found 0 hits outside that column.

## 6. INT-09 spot check against the source

I compared 18 INT-09 rules with the reference source at 09e34ba8. I read these parts: the settings store, the process wrapper, the handler, the settings page, the vault view's sync, unlock and message routines, the main window's menu builder and enable rule, the message widget's timer, and the custom data protected keys. The reference column of the card is what I checked. Larsal's own choices are design, not parity.

| Rule | What the card says about the reference | What I found in the source | Result |
|---|---|---|---|
| INT-09.1 | Vault-level custom data key; JSON members; 10,000 ms defaults | The key decodes from the card's hex to the source's constant (`bytes.fromhex(...)` in python3). The writer and reader use exactly the seven member names in the table. Both timeouts default to 10000. The key is in the protected key list. | match |
| INT-09.2 | Not JSON, or not an array: empty list. A non-object element becomes a sync with an empty name and the defaults. A number in a text member becomes its text. An empty name is kept. With duplicate names the last wins. Timeouts are taken as stored, and a decimal string is read. | The reader asks the document for its array (empty for an object or for bad JSON) and turns each element into a map (empty for a non-object). It converts members to text and timeouts to integers with the toolkit's conversion. It puts the sync into a table keyed by name directly, without the empty-name check that the add routine has. | match |
| INT-09.3 | Compact JSON, members sorted by name, the order of a name-keyed table, rewritten on every Apply | The writer makes compact JSON from a hash table's values. The toolkit's JSON object keeps its keys sorted. The page's save always calls the store's save, after the unsaved-changes question. | match |
| INT-09.5 | First row selected. Remove disabled when the list is empty. Selecting a row drops unsaved edits. Save under a new name adds a second sync. Remove goes by the Name field's text. Clearing sets the timeouts to 10. One-line command fields. | Matches each point: setting up the page, selecting a row (fields overwritten, changed flag reset), Save (adds by name), Remove (removes the name in the Name field), clearing the fields. Both command fields are one-line text fields. | match |
| INT-09.6 | The question "unsaved changes" with Save (default), Discard, Cancel | Same three buttons, Save is the default, and Cancel stops the Apply | match |
| INT-09.7 | Test runs only the download, with the fields on screen. An empty command gives a warning. The check is only "a non-empty file exists". The copy is left behind. | Test builds its values from the fields, refuses an empty download command, and runs the handler's download, whose check is "exists and is not empty". Nothing deletes the file. | match |
| INT-09.8 | Only an empty text counts as empty. White space only starts nothing and is reported as "did not finish in time". | The sync checks only whether the text is empty. With no words the wrapper starts nothing. Waiting then returns at once as "not finished", which reports the timeout text and kills. | match |
| INT-09.9 | Replaces in the whole text before splitting, in the command and the input | The wrapper replaces the placeholder first, then splits. The input goes through the same replace. | match |
| INT-09.10 | Copy named with the prefix, a UUID without braces and the extension; in the toolkit's temp folder; never deleted | The name is built that way in the toolkit's temp folder. No routine in the sync, test or handler removes it. | match |
| INT-09.11 | A start failure is reported as "did not finish in time". The working folder is Larsal's own. | Waiting for the start does not stop the flow. The wait for the end then fails, and that gives the timeout text. No working folder is set, so the child gets the parent's. | match |
| INT-09.12 | Input plus a newline is written, then the channel is closed. With an empty input, standard input stays open. | Writing and closing happen only when the input is not empty | match |
| INT-09.13 | Both outputs are kept whole and never shown | Both are read in full after the end into result fields marked "for future use". Neither is shown or logged by the sync. | match |
| INT-09.15 | SIGKILL to the program only | The timeout path calls the process kill on the child alone. There is no process group. | match |
| INT-09.16 | The file exists and is not empty | Same check after a status-0 download | match |
| INT-09.17 | Menu "Setup Remote Sync…", a separator, one item per sync in table order; enabled only while the vault view or the vault settings are shown | The menu builder and the enable rule match | match |
| INT-09.18 | An empty download fails and the upload is skipped. Any open error leads to the unlock dialog. Both are saved, the vault first, when the combined change list is not empty. The upload runs whenever the download worked and an upload command exists. | The sync routine and the upload step match each point. The failed vault save message has an empty reason, as INT-09.18 step 7 says. | match |
| INT-09.19 | Cancel gives "Remote database unlock cancelled." (not translated) | The unlock handler sets that text with no translation call | match |
| INT-09.23 | Success and failure messages both hide after 6 s. Failure texts quote the whole command. | Both go through the message routine with its default 6000 ms timeout. The handler's failure texts quote the command. | match |

INT-09.14 (ended by a signal is reported as an exit status) depends on how the toolkit fills in the exit code. The card marks it "check with Verify", and it stays open with the card's V-items. This needs a test build, not reading the source.

No rule I compared is a rewrite of reference code line by line. Each one describes the reference's behaviour in its own words, next to Larsal's own design.

## Edits

- Five card headers whose second review and lead decisions are both ruled said `Status: draft`. INT-05 and INT-10 were already marked reviewed. I set them to match:
  - INT-01, INT-02, INT-03: `Status: reviewed (LD-189, LD-191)`
  - INT-06, INT-07: `Status: reviewed (LD-173, LD-175)`

  Only line 3 changed in each card. The check scripts give the same results after the edit.
- Three cards stay `draft`, as their records say:
  - INT-04: finding R04-1 waits for the lead before E7-S5 (LD-215).
  - INT-08 and INT-09: they wait for the owner's E11 scope ruling (W-15).

  E1-S6's checks do not need "reviewed".
- This file is new, and the E1-S6 status line is updated.

Name guard after the edits:

```
$ bash scripts/check-names.sh
Names: PASS
```

## Open items (not blocking)

- 38 "check with Verify" markers are left in the INT cards: INT-01 1, INT-02 1, INT-03 1, INT-04 9, INT-05 6, INT-06 1, INT-07 6, INT-08 6, INT-09 7, INT-10 0. Most need a test build or hardware. They belong to the Verify of the building stories (E7, E8, E9, E10, E11), as the cards say.
- INT-08 and INT-09 have no LD row for their second review. The findings are fixed in the cards, and the open decisions are listed under W-15. The lead may add a row for the record. That is the lead's choice; I did not add one.
- From the Checker, optional: cite WHATWG HTML's "is a registrable domain suffix of or is equal to" inside INT-04.11 as well.
