# Team and process

Many agents work at once. Each one has one role per task. Roles keep the clean room intact and stop anyone from checking their own work.

## Roles

| Role | Does | May open the reference? | Never |
|---|---|---|---|
| Lead (one) | Plans sprints, assigns stories, keeps the board in [epics.md](epics.md), collects reports, talks to the owner | Yes | Builds or verifies its own work |
| Spec | Writes behavior cards in our words from the reference source and the reference app; fills parity rows | Yes | Writes product code; copies reference code |
| Builder | Writes code and tests from spec cards and public standards; Swift too for `macos/` stories, under the same clean room | No | Opens the reference source or runs the reference app |
| Checker | Reviews every change line by line against [AGENTS.md](../AGENTS.md), the Rust and Swift rules and [security.md](security.md) | No | Reviews code it wrote |
| Verify | Proves a story meets its cards: runs tests, interop with the reference CLI, black-box comparisons; signs parity rows | Yes, read only | Edits product code |
| Red team | Runs the attacks in [attacks-and-checks.md](attacks-and-checks.md), writes attack tests, files findings | Yes | Fixes its own findings |
| Mac QA | Builds and runs the app on this Mac with demo vaults, walks the QA scripts, compares with the mockup, takes screenshots | Only when a brief says to run the reference app side by side | Opens a real vault |

Separation rules:
- The Builder of a story is never its Checker or its Verify agent.
- A Spec agent who wrote a card does not build from it.
- Crypto, file format, `unsafe` and secret-handling changes get two Checkers.

## How a story moves

1. **ready:** the lead confirms the Definition of Ready and assigns a Builder and the files it owns.
2. **building:** the Builder writes code and tests, runs `scripts/check.sh`, reports.
3. **built:** the lead assigns a Checker (two for sensitive code).
4. **checked:** the Checker passes it, or sends it back with numbered issues.
5. **verified:** a Verify agent proves the acceptance checks and the spec cases, and updates parity rows.
6. **attacked:** for security stories, the Red team runs the attack groups for the area.
7. **qa:** for screen stories, Mac QA walks the scripts on this Mac.
8. **done:** the lead marks it Done when every step above has proof.

A failed step sends the story back to `building` with the findings attached.

## Working in parallel

- An active story owns a set of files. Two active stories never share a file. The lead writes the owner next to each active story on the board.
- Before each sprint the lead copies the whole folder to a snapshot outside it (for example `../larsal-snapshots/sprint-3/`), so any mistake can be undone.
- Git is authorized (decision D5, LD-342). After the baseline commit, use one branch per story and commit each checked change under the owner's name only. The four paused stories keep their private copies until their saved work is resumed after E14-S1.

## Reference access

The lead sets these from the owner's kickoff prompt. They are never written into any file in this folder.

| Variable | Points to | Used by |
|---|---|---|
| `REF_SOURCE` | The reference source folder | Spec, Verify, Red team |
| `REF_CLI` | The reference command line tool | Verify, Red team, the test data kit |
| `REF_APP` | The reference app | Verify, Red team, Mac QA side-by-side runs |
| `REF_TESTDATA` | The reference source's own test vaults | Verify |

## Brief template

The lead starts every agent with this brief.

```
Role: <Spec | Builder | Checker | Verify | Red team | Mac QA>
Story: <ID and title>
Read first: AGENTS.md, plan/<files>, spec/<cards>
You own these files: <paths>   (Builders only)
Do: <the task in numbered steps>
Done when: <the story's acceptance checks>
Never: <the role's "Never" column, plus the AGENTS.md rules>
Reference access: <variables this role may use, or "none">
Report: story ID, files changed, proof (commands and their result), open issues, next step
```

## Evidence

- `qa/<story>/`: Mac QA screenshots, screen recordings and notes. Demo data only.
- `security/findings.md`: one row per finding (see [attacks-and-checks.md](attacks-and-checks.md#findings)).
- `security/parity/<row>.md`: proof for a parity row when it does not fit in the table.
- Proof is command output, test names and file paths. "Looks fine" is not proof.

## Mac QA

- Builds the app on this Mac and runs it with demo vaults from `testdata/`.
- Drives it with the `LarsalUITests` suite (XCTest UI testing), computer use or macOS UI scripting, following `qa/scripts/`: unlock, browse, search, show and copy, edit, generator, reports, lock events, Touch ID, settings.
- Puts each screenshot next to the matching frame of [design/option-a/mockup.html](../design/option-a/mockup.html) and lists every difference ([BUILD-AND-VERIFY.md](../design/option-a/BUILD-AND-VERIFY.md)).
- Reports what it saw, not what it expected.

## Sprint rhythm

- **Planning (lead):** pick ready stories, assign roles, set file owners, take the snapshot.
- **During the sprint (lead):** update the board after every report; unblock; re-assign.
- **Review (owner):** the lead sends a short report: what works and how to try it, proof, findings, decisions needed. Mac QA screenshots attached.
- **Retro (lead):** lessons go into AGENTS.md or this file the same day.

## Talking to the owner

Short and plain. What works, what was checked, what is open, what needs a decision. Ask the owner only about product and commercial decisions in [spec/decisions.md](../spec/decisions.md) and about anything that costs money or leaves this Mac.
