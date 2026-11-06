# guarded_check

One command for the full check of one commit, offline, with demo data, under private homes and targets.

    Python -B -I guarded_check.py <git-commit-or-repo-top-folder> [--only static,rust,native,docs,fuzz]
        [--repo PATH] [--baseline FILE] [--waivers FILE] [--hold FILE] [--busy FILE]

Python is the pinned interpreter named in `gc_lib.py`. With `--repo` the first word is always a commit. Without it, a repo's top folder means its HEAD, and anything else is a commit in the current folder's repo.

## Results

| Overall | Exit | Means |
|---|---|---|
| PASS | 0 | A full run: every step passed, every gate held, every grant held, and the running tool equals the commit's `scripts/guarded`. Only this stands for a merge. |
| PASS (only ...) | 4 | The steps asked for passed. A part never exits 0. |
| FAIL | 1 | `summary.txt` lists each reason. |
| NEEDS_REVIEW | 3 | At least one grant was withheld, or the commit holds `scripts/guarded` and the running tool's bytes differ from it. This outranks PASS and FAIL. `summary.txt` names the files that differ, and lists each row under "grant withheld: needs review", and failures of a withheld row are labelled "caused by a withheld grant". The label is by row, not proved test by test. Native runs under one profile, so with any needs row withheld every native failure carries it, and one can have another cause. |

A failed test can never be waived. Tests lost or newly ignored against `--baseline` fail unless the lead's waiver file lists them with a reason. A full run without a baseline, or with one holding no tests of the rust, native or docs step, fails: nothing would catch a lost test. A baseline with no table of tests, a value that is no state word, or a full run's step missing is refused at the start, exit 1, with no root made and no run time spent. A baseline holding fewer than half of a step's tests in this run fails at the end. A doc test's key holds no line number, so an edit above it does not lose it; doc tests on one item are numbered in line order, so a lost one still shows, as the last number.

## What it does

Each run makes a new root, `/private/tmp/larsal-gc-<short commit>-XXXX`, and runs in this order, with no retry. A run keeps its root, about 20 GB; nothing removes it. Sealed folders are read only, so remove a root with `chmod -R u+rwx` first.

1. **Source.** Refuses a repository with replace refs or a shallow file; every git call ignores replace refs and grafts. Reads the pins, then exports exactly the commit's tracked files, by blob, under a sandbox whose one write root is the export. Checks the route table, and the running tool against the commit's `scripts/guarded`.
2. **Static.** check.sh's own G1, deny and audit bodies, under the outer guard (`g/`).
3. **Rust.** Builds, records the six lanes without running a test, reconciles, screens imports, reruns the byte checks, makes the plans, runs each program alone through the helper, reconciles after each lane (`r/`). app09 runs in step 4.
4. **Native.** Setup, then G (Swift lint), A (build), B (Swift tests, APP09), one outer sandbox per attempt, with its gates (`runs/`, `lane-out/`, source `s/`).
5. **Docs.** The three doc lanes.
6. **Fuzz.** Every route the commit lists, 30 s each, four at a time.
7. **Summary.** `summary.json`, `summary.txt`, `test-names.json`, built only from the root's files, every count recounted from raw output.

`--hold FILE`: before each heavy step, wait while that file exists, polled every 30 s, at most 30 minutes, not counted in the alarm. Only a stop signal or the 30 minutes end the wait, and then the step does not start; once the 30 minutes ran out, no later step waits on the file again. `--busy FILE`: exists only around each native attempt. `--baseline FILE`: an earlier run's `test-names.json`. Run the summary alone on a private copy of a run: `gc_summary.py <root>`. Parsers and compare: `gc_summary.py --self-test`.

## Grants follow reviewed content

Every row above base has one row in `tables/pins.json`: 37 Rust rows, 18 native needs rows. A row holds the paths its grant rests on, each path's git tree or blob hash at the reviewed commit, the review's name, why those paths, and its byte checks.

- At a run the tool asks git for each hash at the commit under test. On any difference the row runs at base with no grant: no profile above base, no class, no needs line. The sshd no-sandbox line is absent at base.
- At each run the build's bytes are read for every Rust row still holding a grant: R2b's byte checks, by name in `byte_checks`. A failed check withholds the row the same way.
- The grant also needs the program built from its pinned folder, `crates/<package>`: the source path in Cargo's JSON and the manifest folder in the capture are compared. A same-name package elsewhere runs at base and the run ends NEEDS_REVIEW. So does every row, needs rows too, with a pin on a crate the build took from another folder.
- A new program gets base and is listed. A row with no pin is withheld. No flag, waiver or environment variable overrides a pin.
- The pinned hashes come from one commit, and this round's proof compares each pinned path, file by file, with the source R2b and N1b read (`pins-vs-reviewed.json`, in its proof folder). No difference. The pins added later, own_agent's linked crates and the window rows' key event paths, hold the same hash at that commit and at the commit this tool landed on, and equal the source those reviews had; no review read them for this purpose.

**What a pin does not cover.** A crate outside a row's paths is not pinned, so a change in a dependency keeps the grant; the byte checks, and on a board or window row the guard, are what is left there. A key has no kind: a bin and a test of one crate and name both get the row. Pins are content, not behaviour: an unchanged tree can still act differently on another Mac or toolchain.

**own_agent, the row that leaves the sandbox.** It pins `crates/larsal-sshagent` and every workspace crate it links: `larsal-core`, `larsal-crypto`, `larsal-format`, `larsal-model`, `larsal-platform` and `log`. A change in one of them takes the row to base until the commit moves its pin. What truly remains on this row: `vendor/` with the third-party crates in its build, 134 packages by the proof run's build fingerprints, build scripts' own included, `Cargo.lock`, the root `Cargo.toml`, `.cargo/config.toml` and `rust-toolchain.toml` are in no pin here. Code from those keeps the sshd line and can read PASS, and it can start sshd with any config, outside the sandbox. The guard does not load on this row, because its profile has no board or window line. Only the string byte checks stand there, and the review of the commit's diff.

## What is contained, and what is not

**Runs under a sandbox:** the export, every static, doc and fuzz phase (the guard), every Cargo build and capture, each Rust test program and its children under its own profile, every native attempt. All are `(allow default)` with deny lists, so a service nobody listed stays reachable.

**Not contained, plainly:**

- The driver, the helper (until its last exec), the summary, `clang` in setup and `git` for the pins run unsandboxed as the owner. The kernel refuses a sandbox inside a sandbox, so the driver cannot sit in one.
- `sshd` and the login shell it starts leave the sandbox, for the one row `workspace:larsal-sshagent/own_agent`, while that row's pins, source path and byte checks hold. See R2b 2 below.
- Native has no `iokit` line (N1b 34). The window server line and the launch services line mean the profile does not itself stop xctest or Larsal from showing a window (N1b 7).
- The owner's home is readable by the export, except `.ssh` and `Library`, because it reads the repository there.

**Gates are per stage.** Reading them as run-wide would be wrong.

| Gate | Where it runs | Where it does not |
|---|---|---|
| Window watcher, about every 3 s; only the on-screen flag | native G and B | native A, Rust, static, docs, fuzz |
| Guard library, board requests | xctest; Rust rows holding the board or the window line | Larsal, static, docs, fuzz, every other Rust row, anything below |
| Kernel rows for sensitive grants | native | Rust, static, docs, fuzz |
| Test plan is the reviewed one (one bundle, real xctest host, no UI bundle) | after native A and before B | |
| Owner sentinels, a process left under the root | after each step and at the end | |
| Tool, profile and guard library custody | before each phase and at the end | |
| Source custody | `g/source` before each guard phase, `s` before each native attempt, both and the export at the end. `r/source`, which no lane can write, after each Rust lane | inside a phase: a step can change a later step's script in its own copy and put it back before the phase ends, and that reads clean |
| A new crash report of an own program fails | Rust and native | static, docs, fuzz: listed only |
| Total alarm, 3540 s of running time | everywhere | see below |

**What the guard does not reach in the Rust lanes, and why.** dyld strips `DYLD_*` for protected binaries, so the library loads through `/usr/bin/env` right after `sandbox-exec`, and from there it follows plain children.

- A `larsal` started through `/usr/bin/script` or `/bin/sh`: int10's `pty` and `spawn_ignoring_sigint` helpers. A forgotten private board there reaches the general board unseen under `cli-runtime.sb`. What holds: the pin on `crates/larsal-cli` and its review. Control: `c_forgotten_board`, case C.
- A row or child that clears its environment: none of the board rows does today. `env_clear` is only in `larsal-sshagent` tests, and in `larsal-ffi`'s `tests/ssh.rs`, which compiles the same helper by `#[path]`. Neither holds a board line.
- `/usr/bin/pbcopy` and `/usr/bin/pbpaste`, the system's clipboard tools. They are protected binaries, so the variable would not reach them: `/usr/bin/true` under the guard wrote no log. pbcopy itself was never run. A board profile has no process-exec line against them. What holds: the byte check `no-pbcopy`, which forbids both names in the 13 board rows' bytes at each run. A name built while the program runs passes it.
- A direct message to the service (N1b 31). The other routes N1b 4 and 31 name are narrower than they read: Carbon `PasteboardCreate` and a `dlsym` of `CFPasteboardCreate` end in a guarded call and are seen, and `-initWithName:` does not exist on this Mac.
- Hostile code: it can truncate its own log or clear its own environment. The guard is for the mistake, not for an attacker. An attacker is stopped, if at all, by the pin and its review.
- The Rust rows' guard, and the helper's lines that load it, are new in this tool and in no review's reading: R2b did not run with them. The helper's other lines are R2b's.

**The alarm is a flag, not a hard bound.** Log reads after it are cut to what is left with a floor of 5 s; each `ps` has its own 10 s to 30 s. Measured tails are under the 60 s it keeps back. A child in its own session is not named or signalled. SIGHUP or SIGKILL of the tool itself leaves children: SIGHUP stops the run in order, SIGKILL cannot be caught. Every stop signals only process groups the run started, through their handles.

**The tool cannot be rewritten by what it runs.** The generated profiles, the tool copy in `R/tool` and the guard library sit outside every write root, read only, with their hash compared before every use and at the end. A mismatch stops the steps left. The hashes are held only in the driver's memory. This holds for everything sandboxed; `sshd` on the own_agent row runs outside and can write wherever the owner can.

**The export.** Refuses `..`, an absolute name, an empty part, `.git`, a name below a file or link, names that fold together, submodules, odd modes, and a link pointing outside, by its text and, once every name exists, by resolving it inside the export, so a chain of links is refused too. Driver reads of paths a lane could write use `O_NOFOLLOW` and a regular-file check, so a lane cannot get a closed file copied into evidence and a FIFO cannot outlive the alarm.

**A lost gate fails.** `tables/routes.json` holds check.sh by whole hash and by each function's text, the step lists, the scripts its steps call, each fuzz route's bytes and each route's `[[bin]]` lines in `fuzz/Cargo.toml`. Any change is red with "check.sh differs from the tool's route: needs a table update and review", and no step runs. A step or route lost, emptied or pointed at another body is a failure, not a smaller total. What the table does not see is the crates a route's body calls: a change there is an ordinary code change. A new fuzz route needs no table change: it runs, and is listed.

## Limits the approvals recorded

**R2b** (candidate notes, limits 1 to 15; C2b-F1; C2b-F3; F1 and F2 of its proposed decision).

1. In-memory keys and private boards rest on source reading and denials. Still so, and now the pin and byte checks ask that the read code be unchanged.
2. sshd and what it starts run unsandboxed, as the owner. The session runs /bin/zsh as a login shell with the owner's HOME, so /etc/zprofile, ~/.zshenv and ~/.zprofile run unsandboxed (C2b-F3). While the throwaway sshd listens on loopback, any local process can sign in as the owner with demo key K1. Measured 34.5 s and 88 s. Still so. The line checks the path, not the arguments: any process under that profile may start sshd with any config. So the narrowing rests on own_agent's bytes, now pinned by tree and read at each run, not only by the hash of what was built. sshd's config has no PermitUserRC line, so the lane stops before that program if `~/.ssh/rc` exists. The signal line lets any process under that profile signal its own direct children.
3. Detached descendants are seen only if their image sits under the target or source, or if they are sshd, sshd-session or sshd-auth. Another sshd of this uid born in that window fails the run falsely. Still so.
4. A lane survives zero hung programs. Still so.
5. Stale folders: a program whose helper PID equals an old folder's number is refused, a false failure. Still so.
6. Session class over-grant. Still so.
7. Reads: `/var/folders`, other agents' `/private/tmp` roots and `/opt/homebrew/bin` are readable under every runtime profile. Still so.
8. 0.0.0.0 stays bindable under the loopback rule. Still so.
9. PATH stays as bound. Still so.
10. Leftover removal was by flag, to run only when no other Larsal run is live, because a PID can recur. **Now automatic** at the end of the Rust step (C2-F10). Its own-uid and birth-window proofs make a wrong removal need a PID to recur in about 2 s. Run one tool at a time.
11. Other Mach names stay open under allow-default. Still so.
12. The owner touching `~/.ssh` during own_agent fails the lane. Still so.
13. Launcher and driver are unsandboxed. Still so.
14. PTY rows may write to any terminal of this user. Their bytes hold no `/dev/ttys` or `TIOCSTI`: now read at each run.
15. That the test key stays in memory rests on source reading plus a negative log read at review. That log read is not repeated. The source is pinned.
- C2b-F1. The general-board guard on the 13 programs was source reading, 0 of 13 hold NSApplication. Now read at each run, and the guard library loads in those rows, with the reach stated above.
- The authorization was single use, for that source. These pins carry it only for paths equal to what R2b read; "What a pin does not cover" says what they do not reach.
- F1's key route and F2's sshd route keep their words. The import screen is narrow: three Security families, by `llvm-nm -u`. Objective-C calls are not seen by nm.
- Time caps stay: workspace 1200 s, sync 600, net 120, release 300, release-browser 120, app09 300. A program's cap is the lane's time left.

**N1b** (candidate notes, limits 1 to 37; words C2b-4, C2b-5, N1B-C1-03). Numbers that only described that private run are named and marked.

1. Private proof claim: described that run. 2, 3. The guard gate: the first frame after the guard must be one of two AppKit set-up frames; our frames lower down are counted, not failed. Still so, and the same gate reads the Rust rows.
4. The guard sees three general-board calls only. Still so.
5. The clipboard rule in xctest rests on the guard, and xctest has never run without it, because that would open the owner's clipboard. The guard does not reach Larsal; there the rule rests on the kernel's deny of the service. Still so.
6. Windows are sampled about every 3 s and a shorter one can be missed. Still so.
7. Larsal could ask launchservicesd to start something outside the sandbox; source rules stop that in a hidden launch. **Changed:** `process-outside-tree.json` is now a gate for a process naming this root or with an image under it, testmanagerd excepted. Only names on the interest list are looked at. Others are listed.
8. xctest can read the installed-apps list through lsd.mapdb. Keep evidence folders private. Still so.
9. NSIRD names and terminals opened during a run cannot get deny lines ahead of time. Still so.
10. Kernel rows can merge duplicates and mix other agents' rows in, by name. Still so.
11. W-15: a source root over 37 characters fails. Still so; the run root is fixed at that length.
12. Search clear margins can fail falsely under heavy load. Still so.
13. F-131's words in the findings table. Described the merge; done at merge.
14. testmanagerd is outside the sandbox. Still so.
15. Stage G covers only the Swift steps of G1. Still so; step 2 runs the rest.
16. SwiftLint and the guard library hashes: **now compared** against `tables/routes.json` and fail.
17. An empty folder from a hand run stayed in T; its rule is the same here: not named by an allow row, so left and listed.
18. Crash reports with a foreign name are listed, not read. Still so.
19. A word field changed after that run. Described that run.
20. The HOLD and BUSY marks were in a private wrapper. **Now in this tool.**
21. That run's private root size. Described that run; a run here keeps about 20 GB.
22. Stage C form: removed in this tool.
23. Caps: 3540 s total here, stall 900 s in A and 600 s in B.
24. F-131 in this route: two size checks cannot fire where no window has a size. M1's red rests on Larsal's reader reading sharing 1 (N1B-C1-03). The capturable time at 0 x 0 has no bound (C2b-5). The one window listed is inferred to be AppKit's, and a form where the only listed window is Larsal's passes every rule (C2b-4). Still so.
25. A child in its own session survives the group stop; a descendant that exec'd is seen by first image only. The lead stops a survivor by its PID. Still so.
26. Deny tail: `file-write-xattr` on an existing swbuild.tmp name stays allowed. Still so.
27. Driver soft points: the first killpg now catches PermissionError; setup compares its hashes. A crash in a step is a failure with its traceback. The telemetry frame match still ignores the offset.
28. Signing identifiers keep honest tools off and are not a boundary. **Narrowed:** a sampled process using a sensitive grant as xctest or Larsal must be that image. One the 0.1 s sampler misses is not covered.
29. Dead lines in the base profile. Still so.
30. Other tests with a fixed-sleep shape need a quiet CPU. Still so.
31. Unseen routes into the general board. Still so.
32. Group signal: the SIGKILL goes only with a descendant alive; needs three things at once to hit a foreign group. Still so.
33. A foreign process named xctest or Larsal inside the window passes the grant gate unless it is sampled. Still so.
34. The profile is allow-default, with no iokit line. Still so. N1b's reason was that nothing posts events: the two window rows now pin the code that decides that, so a change in it takes the window line out before native runs. Its reach is the named files: a new caller elsewhere in `larsal-ffi` moves the Rust rows, so the run reads NEEDS_REVIEW, and native has run that once with the window line open.
35. launchservicesd records the private app path; the crash reporter writes. Still so.
36. The owner's clipboard in Larsal: `Session.shared()` uses the general board, and only the kernel's deny keeps it off. Never relax that line. Pinned: `crates/larsal-ffi/src/session.rs` in the xctest board rows; Larsal holds no board row at all.
37. The bundle holds two counts; the gate compares the top level's. Still so.

**Limit stated at each run:** `summary.txt` names the crates with no yanked proof and the newest advisory date, because the route is offline.

## Where the profiles differ from the reviewed text

Same text with roots as parameters, except: the Cargo profiles hold the full deny list and `(deny appleevent-send)`, which R2b's did not; the guard's prefix list is the same full list; the native profile has no `R/profile.sb` copy, its 418 suffix lines are replaced by a per-attempt tail with no allow lines, and its file-link is narrowed to the 8 keep folders. Twelve Rust and three guard profiles are generated, plus the export's and the native one. Root text is asserted plain in every generator.

## The tables are data

`tables/programs.json`, `needs.json`, `native-expected.txt`, `pins.json`, `routes.json`. The seal covers code and tables. Once this tool lives in the project, a table change is part of a story's commit, and that story's C1 and C2 review it like any code. So a run takes the tool of the commit under test: if that commit holds `scripts/guarded` and the running bytes differ, the run ends NEEDS_REVIEW with that reason, which keeps tool and tables from drifting from the reviewed commit. That is the only way to move a pin, approve a route change or add a grant: adding a Swift test changes `native-expected.txt`, a change in a pinned crate changes `pins.json`, and neither is a flag.
