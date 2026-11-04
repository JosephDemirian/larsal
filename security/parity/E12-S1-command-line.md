# E12-S1 Every command in card INT-10: Verify proof

Story: E12-S1. Card: spec/integrations/INT-10-command-line.md (parity table, 50 rows). Verify, 2026-10-28.

Result: **signed** (re-check 2026-10-28, after LD-185).
- All 47 rows that run on a Mac pass: all 18 "same" rows match, and all 29 "App differs" rows differ as the card says (row C1 moved from "same" to "App differs" with LD-172). G8 and G10 are proven by the int10 tests only, and G13's hardware part waits for E10. The 3 "Not on Mac" rows are skipped.
- SC-07 holds. Exit codes are 0 and 1 only. Vaults move both ways between App and the reference CLI with the same content. The release hardening holds.
- Tests: `cargo test -p app-cli` passes (10 + 113) and `cargo test -p app-core --test mod11` passes (45, 4 release-only timed tests ignored).
- First pass, the same day: not signed, with C19 and C25 failing (F1 and F2 below). Both fixes were then proven black-box; see "Re-check".

## Re-check 2026-10-28 (LD-185)

- Fresh release build: `CARGO_TARGET_DIR=/tmp/v-e12b-target cargo build --release -p app-cli`, 44 s; deleted afterwards. Same setup as below (throwaway HOME, demo copies, reference CLI 2.7.11).
- **C25, now pass.**
  - `search big-10000.appvault is:weak`: App 10,000 lines in 0.98 s, byte-identical to the reference's 10,000.
  - `search option-a-personal.appvault is:weak`: App 6 entries, the same count as its `db-info` "Rated below Good: 6". The reference lists 6 live entries plus 2 in the bin.
  - The remaining difference is App's estimator (FEA-05.1, row C13), not the search. The entries rated across the 75-bit line differ: `/Work/Figma` App 77.439 bits (Good), reference 74.359; `/Work/Servers/Server root · web-01` App 70.918, reference 84.331.
  - `is:weak g:Social`: the same in both. rich-v3 and rich-v4 `is:weak`: the reference's list minus the bin.
  - `deleted` still gives M10-72 (bin never listed). `server`, `a`, `title:Ser*`, `pass:…`, `tag:demo`, `zzzz` and `is:expired` give the same results as before.
- **C19, now pass.**
  - The same m1 and m2 as the first pass (m2 = rich-v3 changed by the reference's `add` and `edit`). Results:
    - `-q -d -s`: no output.
    - `-d`: 3 lines, "is unchanged", file unchanged.
    - `-s` run 1: saved. Runs 2, 3 and 4: `m1.A.appvault is unchanged.` The reference: "not modified".
  - Merged content against the reference's: only the root group's modification time differs, through both exports (App's merge rules, MOD-11).
  - Self-merge of password-only (version 3): 8 of 8 runs "is unchanged" with the bytes unchanged; 12 of 12 `-d` runs "is unchanged". Self-merge of rich-v4 (3 runs) and option-a-personal (version 4): unchanged, bytes unchanged.
  - A plain version 3 copy merged into an App-saved target, 3 runs: unchanged each time.
  - `-s` with the wrong vault: M10-97, exit 1.
- **Spot checks, no regression.**
  - C1 `add` (New1 with fields; `"Server login"` refused; `Personal/` gives M10-26): the same content as before.
  - C21 `mv`: as before.
  - C26 `show --all -s` and `-a` with `uuid`: identical stdout, exit 1.
  - C18 `ls -R` (rich-v3) and `ls -R -f` (option-a-personal): identical apart from the empty-group marker.
  - C10 `db-info` rich-v4: the same counts.
  - C14 CSV: byte-identical.
- **Tests:**
  - `cargo test -p app-core --test mod11`: `ld185_version_3_settings_never_win_and_equal_settings_are_no_change ... ok`, `test result: ok. 45 passed; 0 failed; 4 ignored` (the 4: "timed: release only").
  - `cargo test -p app-core --test fea01 ld185`: `ld185_rates_names_is_weak_queries ... ok`.
  - `cargo test -p app-cli`: `ld185_c19_version_3_merge_settles ... ok`, `ld185_c25_is_weak_is_complete ... ok`, `test result: ok. 113 passed; 0 failed`, plus 10 unit tests.
- **Card:** row C1 now reads "App differs" and M10-26 is in the table. The "Counts" line under the parity table still says "Same 19 (… C1 …)" and "App differs 28 (… 17 C rows …)". It should say 18 and 29 (18 C rows). Wording only.
- **CPU, re-check:** about 10 CPU minutes: build 1.7, mod11 4.2, app-cli tests 4.1, the black-box runs under 1. The longest run took 44 s wall time.

## Failures and the smallest fixes (first pass; fixed by LD-185, see Re-check)

**F1, row C25: `search is:weak` drops results without a word.**
- `search` gives App's rating cache no ratings before the run (`crates/app-cli/src/commands.rs:498`, `find_paths`). So every `is:weak` check pays for a fresh estimate from the run's meter (LD-137 (2)). The meter runs out after a few entries.
- After that, every other entry counts as not matching. The command ignores `Found::invalid` and prints nothing about the limit (LD-126 (7) says the limit notice shows).
- Observed:
  - `printf 'demo-pass-7\n' | app search option-a-personal.appvault is:weak` gives `app: no entry matches is:weak.`, exit 1. App's own `db-info` on the same vault says `Rated below Good: 6`. The reference lists 6 live entries (bin entries aside), among them `sunshine2019`, rated 11.3 bits by App's own `estimate`.
  - On `big-10000.appvault`, App lists 9 entries with exit 0. App's `db-info` says `Rated below Good: 10000` (in 0.95 s), and the reference lists 10,000.
  - On rich-v3 (3 weak entries) the result is right, because only a few estimates are needed.
- Smallest fix: call `ratings.fill(v)` before `search::search` in `find_paths`. This is the pre-filled cache that LD-137 (1) gives the window session, and `db-info` shows it costs under 1 s on 10,000 entries. If `found.invalid` is still set afterwards, print FEA-01's limit notice on stderr instead of claiming no match. Add a test: `is:weak` on option-a-personal and on big-10000.

**F2, row C19: merging a version 3 source is never "unchanged", and a self-merge rewrites the file.**
- A version 3 file holds no `SettingsChanged`. The reader then sets it to the open time (FMT-10.10 row 25). In a same-vault merge, MOD-11.19 takes the source's settings group when its time is newer (`crates/app-core/src/merge.rs:1180`). So the source opened later always wins: one `Metadata:  (vault settings)` change line, and a save.
- Observed:
  - `merge -s m1 m2` run again with nothing new keeps printing `Metadata:  (vault settings)` and `m1… saved with the changes from m2…` (runs 2, 3 and 4). The reference prints "not modified".
  - `app merge -s s2.appvault s2.appvault` on a copy of password-only rewrites the file as version 4.0 in 8 of 8 runs. The card's edge case says "merge where SOURCE is VAULT: nothing changes".
  - With `-d`, 4 of 12 self-merges list the false change (it depends on whether the two opens fall in different seconds). That breaks MOD-11.18's "the same two vaults give the same result every time".
  - The int10 test misses this, because its m2 is saved by App first (version 4, time stored). With an App-saved m2, the second merge is "unchanged", as I also saw.
- Smallest fix: in `merge.rs:1180`, take the settings group only when the source file stored `SettingsChanged`. A time made up at open must never win. At the least, record no change when every value of the group is equal.
- Lead ruling needed: FMT-10's "open time if missing" also lets an old version 3 copy override newer local settings and the KDF in a merge. Add a test: twice-merge and self-merge with a version 3 source.

## Card points (not failures)

1. **C1 still read "same" (fixed in the card by LD-185)**, but LD-172 (R10-1) made `add` refuse an empty title. App refuses `add v Personal/` ("app: Personal/ gives no title for the new entry.", exit 1). The reference adds an untitled entry. The card's message table has no M10-26, and the C1 row and the counts were not updated.
2. **Group times.** The reference moves a group's modification and access time when an entry is added to it, moved into or out of it, or recycled into the bin. App does not: only changes to the group itself move them (MOD-02.25, SD-03). This is the only content difference after add, mv and rm.
3. **Version written.** App saves a changed version 3.1 vault as version 4.0 (FMT-16). The reference opens all of them.
4. **The reference's `attachment-export --stdout`** turns every byte from 0x80 up into U+FFFD: 256 bytes in, 512 out. App writes the exact 256 bytes, with the same SHA-256 as the vault's pool (INT-10.41). C3 could name this.
5. **Small wording.**
   - M10-57 and the word-list error print Rust's `entity not found`. Elsewhere App says `it does not exist`.
   - `generate -L` (no value) says `--length needs a value`, naming the long option.
   - F04 has no revision line (no git yet).

## Setup

- Release build: `CARGO_TARGET_DIR=/tmp/v-e12-target cargo build --release -p app-cli`, 40 s. Debug build, for the private pasteboard only: `cargo build -p app-cli`, 45 s. Both were deleted afterwards.
- The reference CLI is the installed 2.7.11. Every run of either tool had `HOME=/tmp/v-e12/home`, a throwaway home: the reference's real settings were never read, and App's settings folder does not exist there.
- Demo files only:
  - copies of `testdata/*.appvault` and `testdata/*.appkey` in `/tmp/v-e12/work`;
  - 20 of the reference's own test vaults and key files, copied under neutral names to `/tmp/v-e12/rx`: password, key-file, non-ASCII password, format 2, 3 and 4, compressed, protected strings, bin off, five key-file kinds, merge and sync, a version 1 file and a broken header.
- Content comparison:
  - Each changing command ran once with each tool, on two fresh copies (`wa`, `wr`) of the same vault.
  - Both results were exported with the reference's `export` and again with App's `export`. A script turned each XML into canonical lines: times decoded and new ones shown as `NOW`, new ids numbered, attachments as SHA-256, custom data sorted, and the reference's two changing custom data items (a last-modified stamp and a random value it rewrites on every save) left out. The two results were then diffed.
  - The baseline: rich-v3 exported unchanged by both tools differs in nothing but `SettingsChanged`, which App's export fills for a version 3 file.
- Pseudo-terminal runs: a small python3 `pty` driver (signals reset to default in the child), reading termios after the run.
- Rule 10: no window was opened. The reference's `clip` was never run, and the general pasteboard was never written; its change count was 10124 before and after all clip runs. App's `clip` ran only in the debug build with `APP_TEST_PASTEBOARD=1`; its private pasteboard `com.app.clipboard.<pid>.0` was read with `osascript -l JavaScript` and `NSPasteboard pasteboardWithName`.
- Rule 11: every process I stopped was stopped by the PID I started: the reference `rmdir` that hangs, the probe targets and the clip signal runs.

## Parity table

"Pass" for a "same" row: same stdout data, same exit code, same resulting content (App's words in its messages). "Pass" for an "App differs" row: the difference is the one the card names, and nothing else.

| # | Card status | Result | Proof |
|---|---|---|---|
| G1 | same | pass | `generate -L12`, `--length=12`, `-L 12`: 12 characters in both; `-ln -L 40`: 40 lower-case and digits in both; `-L 8 -L 20`: 20 (last value wins) in both; `ls v -R` (option after the argument) lists in both; `ls v -- -R`: "no group at -R", exit 1 in both |
| G2 | differs | pass | `generate --bogus`: App one line M10-02, exit 1; reference 18 lines. `app --bogus`: M10-02 with no command name, exit 1; reference usage on stdout, exit 0. `ls a b c`: App "unexpected argument c" |
| G3 | differs | pass | `show --help`, `ls v --help`, `ls -qh v`: App help on stdout, exit 0, no prompt; reference stderr, exit 1, `show --help` with "Missing positional argument(s)" |
| G4 | differs | pass | `add -p`: App `Entry password: ` on stderr, stdout only M10-40; reference "Enter password for new entry:" on stdout. `edit -p` the same. Piped `open`: reference stdout `Rich demo> `; App stdout holds only the listing |
| G5 | differs | pass | Pty, no password typed: App printed M10-61 (`clip … abc`), M10-31, M10-82, M10-30, M10-32, M10-62, M10-85, M10-77 and M10-75 with no prompt, exit 1. The reference prompted first for 7 of them (`edit` with nothing to change: "Not changing any field" after the unlock) |
| G6 | differs | pass | `ls -q` with a wrong password: App M06-06 text, exit 1; reference no output, exit 1. `mv -q`: App silent; reference prints its success line. `db-create -q -p`: App no prompts; reference prints both prompts. `db-edit -q`: reference prints its success line |
| G7 | differs | pass | Pty, signal at the prompt: App ended by SIGINT, SIGTERM, SIGHUP, SIGQUIT (2, 15, 1, 3) with echo **on** after; reference ended by SIGINT with echo **OFF** |
| G8 | differs | pass (by test) | `int10_10_a_controls_escaped_on_a_terminal_exact_in_a_pipe ... ok`. Black-box not reproducible: the writers of both tools drop C0, DEL and C1 characters (a title or user name with ESC, 0x7F or U+009B, made by the reference's `add` or App's `import`, comes back without them in both) |
| G9 | differs | pass | `ls -k password-only.appvault password-only.appvault`: App "This is the vault file itself, so it cannot also be its key file…", exit 1; reference wrong credentials |
| G10 | differs | pass (by test) | `int10_15_a_slow_unlock_needs_the_flag ... ok` (test hooks fix the memory size; no demo vault in the ask band can be made with the tools) |
| G11 | same | pass | Sweep of 74 App runs (successes and errors of every command, the shell, wrong passwords): distinct exit codes `0 1`. No error run wrote to stdout, and no error run was silent. The reference also gave only 0 and 1 in every run here |
| G12 | same | pass | `--no-password -k` on the hex64, xml-v2, binary32 (`--key-file=` form), hashed, xml-v1 and CLI-made key file vaults; password plus key file; CR LF line end; no final newline: same listing and exit in both. Trailing space and missing key part: wrong credentials, exit 1, in both. `-q` drops the early-key-file note in both. The 20 reference test vaults: `ls -R -f` the same in all 18 that open, and the XML content the same apart from the two kept differences in Card points and C14 |
| G13 | same | pass (E10 part waits) | `--hw-key 3`, `--hw-key 1:abc`, `-y 3`: M10-02 "not a slot (1 or 2) with an optional serial", exit 1. `-y 2`, `--yubikey 2` (aliases), `--hw-key 2`: "Your security key is not connected", exit 1. The reference fails the same way with no key present. The challenge itself is E10 |
| G14 | differs | pass | `ls --no-password password-only.appvault`: App M10-14 before any work; reference wrong credentials |
| C1 | differs (LD-172) | pass | `add V New1 -u u1 --url … --notes 'a\nb'`, `add V E2`, `add -p V "Work/New p"`, `add -g -L 12 -n`, `add -q`, `add V "/Server login"`: the new entries are the same in both (notes `a` LF `b`, no default user name, the same defaults); the only diff is the parent group's times (Card point 2). `add V "Server login"`, `add V Nogroup/X`, `-g -L 0`, `-g -p`: refused in both, files unchanged. `add V Personal/`: see Card point 1 |
| C2 | differs | pass | `analyze -H h.txt` (upper-case SHA-1 of `demo-entry-pass-1`, `:3`, CR LF): M10-86, then `Leaked password: Demo login (in the list 3 times)`, exit 0; the reference reports the same finding. `--hibp` alias works. `-q`: only the finding (the reference keeps its info line). No `-H`: M10-85 before the prompt (the reference prompts first). `--okon`: M10-02. Three hashes on rich-v3: the same two findings in both, counts once and 0. `zzzz:1`: parse error, exit 1, in both |
| C3 | differs | pass | No target: M10-58. `--stdout bytes.bin`: 256 exact bytes (reference 512, Card point 4). `-q --stdout`: the bytes. To a new file: mode 0600 (reference 0644, umask 022). Existing file, stdin a pipe: refusal, exit 1, file kept (reference overwrote it). `-f`: replaced (reference: unknown option `f`). Pty: `[y/N]` Return gives the refusal; `y` replaces, mode 0600 |
| C4 | same | pass | Existing name without `-f`: refused, also when FILE is missing (name checked first), in both. `-f` replace and a new name: same content in both. Missing file: refused in both |
| C5 | same | pass | `attachment-rm` of `notes.txt` and of a shared attachment: same content in both. Missing name: refused, exit 1, in both |
| C6 | differs | pass (App side) | Debug build on the private pasteboard: one item with `org.nspasteboard.ConcealedType`, `org.nspasteboard.TransientType` and `demo-entry-pass-2`; after 6 s empty, "The clipboard is empty again.", exit 0. Another write at t = 1: "other" kept, "…holds something else now…". Timeout 0: value kept. SIGINT or SIGTERM at t ≈ 1 of 30: pasteboard emptied, ended by the signal (130, 143). `-b "Old serv"`: M10-67; `-b e`: M10-66 with 7 paths on stderr, exit 1; `-a nothere`: M10-63 on stderr; `-t`: the code copied. Countdown on a terminal: `int10_29_a_countdown_on_a_terminal_pty ... ok`. The reference side is from the card (its `clip` is never run) |
| C7 | same | pass | `close` outside the shell: no output, exit 0, in both |
| C8 | differs | pass | `db-create` with no key part: refused, nothing made, in both. `-p` `pw-a`: mode 0600 in both; App writes version 4.0, root `Root`, empty name, Argon2id 64 MiB 36 iterations, 4 lanes; the reference writes 3.1 with AES-KDF. Different repeat, and empty then `n`: refused, nothing made; empty then `y`: made, opens with an empty line. `-t 99`, `abc`, `0`, `5001`: M10-77 before the prompt. `-t 100`: "tuned to about 100 ms … 4 iterations". Exists: M10-75 before the prompt. A new key file: XML 2.0, 278 B, mode 0400 (the reference makes 128 random bytes). An existing key file is left unchanged. The reference opens App's n2, e, n6, n7 and t100; App opens the reference's |
| C9 | differs | pass | No option: "Nothing changed", exit 0, bytes unchanged. Unset of a missing key file: M10-83. Unset of the only part: M10-84. `-p --unset-password`: M10-82 before the prompt (the reference prompts first). `--set-key-file`: XML 2.0, 278 B (the reference: 128 B); afterwards password alone fails and password plus key opens, in both. Unset password, then set a new one: works in both. Each tool opens the other's result |
| C10 | differs | pass | rich-v4 and rich-v3: the same counts in both: Groups 5, Entries 8, Past expiry 1, Different 5, Repeated 0, Most uses 1, Under 8 characters 0, Rated below Good 4, Skipped 1 (rich-v4) or 0, Length 15. App: no id line, `Created on: 2024-01-01T01:00:00+01:00` (00:00 UTC in local time), RFC 3339, passkey and one-time code rows. The reference prints a new random UUID on every run and the creation time "1/1/24 12:00 AM" |
| C11 | differs | pass | `passphrase -W 3` and `diceware -W 3`: 3 words; default 7. `-W 0`, `-W abc`, `-W 1001`: M10-35, exit 1 (the reference prints 1,001 words). Missing and empty list: error, exit 1 (the reference prints an empty line, exit 0). 3-word list: warning on stderr, works. `-W 1000`: 1,000 words |
| C12 | same | pass | `edit -t Renamed -u ""`, `edit -u demo-user` (no change), `edit -p`, `edit --url … --notes …`: the same content in both, history included. Nothing to change: refused, exit 1, in both |
| C13 | differs | pass | `estimate` with an argument: M10-92, exit 1 (`estimate -- -x` too); the reference rates it. `é`: `Characters 1` (the reference: length 2). Empty line: `Characters 0 Bits 0.000 Log10 0.000`. Pty: `Password to rate: ` with nothing echoed; the reference echoes `demo-secret-9`. Bits differ (App's estimator) |
| C14 | differs | pass | Warning M10-88 on stderr for every format, also with `-q` (the reference: none). `csv`: byte-identical to the reference. `CSV`, `HTML`: accepted. `xmlx`, `XMLX`: refused, exit 1 (the reference gives XML). XML content is the same as the reference's. App's XML has the attachment pool for version 4 vaults too; the reference's has none |
| C15 | differs | pass | Default: 32 characters; 300 runs used the same 53-character pool in both. `-L 10000`: works; `-L 10001`: M10-32, exit 1 (the reference prints it). Impossible options: M10-32 with the reason, exit 1 (the reference: exit 1) |
| C16 | same | pass | `help ls`: ls help on stdout, exit 0, in both. `help bogus`: the command list, exit 0, in both |
| C17 | differs | pass | `import -p x.xml`: mode 0600, version 4.0 (the reference: 3.1). A second run: MSG-XML-EXISTS before any prompt. No key part: MSG-XML-NOKEY, nothing made. rich-v3's XML imported by each tool: 0 diff lines, through both exports. A `Protected="True"` value: refused; a DTD: refused; `<x/>`: "No root group." The reference was not given those inputs (its card case is a crash, and a crash report must not appear on the owner's Mac). Each tool opens the other's result |
| C18 | same | pass | `ls`, `-f`, `-R`, `-R -f`, `Work/Servers`, `/Work/Servers/`, `Work/Servers/`, `/`, `""`, `Recycle Bin`, missing group, rich-v4, option-a-personal (33 lines), big-10000 (10,000 lines): stdout byte-identical except the marker `(empty group)`, same exits |
| C19 | differs | pass (re-check; first pass failed) | First merge `-q -d -s`: no output in both. `-d` with two password lines (target, then source): exit 0, file unchanged in both; App's lines carry no values. `-s`: the merged content is the same as the reference's apart from the root group time (MOD-11). `-s` with the wrong vault: M10-97, exit 1. First pass (**F2**): run again with nothing new, App printed `Metadata:  (vault settings)` and saved every time, and a self-merge of a version 3 vault rewrote it. Re-check: runs 2 to 4 "unchanged", and self-merges leave the bytes alone |
| C20 | differs | pass | `mkdir V Work/New`: the same content in both. Existing group: M10-23; missing parent: M10-21. `mkdir V /Top/`: App makes `Top`; the reference: "Group /Top not found", exit 1 |
| C21 | differs | pass | `mv V "Server login" Personal`: the entry content is the same in both, except the reference adds one history item and App adds none (L03-1); group times per Card point 2. Same group: M10-24. Missing group or entry: M10-21, M10-20 |
| C22 | differs | pass | Piped `printf 'demo-pass-4\nls\nquit\n' \| app open rich-v3.appvault`: the root listing on stdout, no prompt, exit 0; the reference prints only `Rich demo> `. Pty: `app (Rich demo)> `, listing, fields, M10-95 for `bogus` and `export`, `app> ` after `close`, `ls` gives M10-02, `quit` exit 0. Through a FIFO: `add S5` in the shell is in the file (the reference lists it) while the shell still runs. `open` of a second vault inside works. Line splitting: quoted and backslash forms find the entry; an unquoted title gives "unexpected argument demo" |
| C23 | same | pass | `rm V "Server login"`: to the bin; `rm V "Recycle Bin/Deleted demo entry"`: deleted for good with a deleted-object record; `rm` on password-only makes the bin: the same content in both apart from group times (Card point 2). Missing: refused in both |
| C24 | differs | pass | `rmdir Personal`, `Work/Servers`, a group inside the bin: the same content in both. `/` and `""`: M10-25. A crafted rich-v3 copy with the bin inside Personal (the reference's own `import` of an edited export): App deleted Personal, the bin and its content for good in 0.33 s; the reference was still running after 10 s, was stopped by its PID, and the file was unchanged |
| C25 | differs | pass (re-check; first pass failed) | Bin never listed: `deleted` gives M10-72, exit 1 (the reference lists 2 bin entries); `Demo`, `a`, `is:weak` on rich-v3: the reference's list minus the bin. `server` finds the Work entries although Work has search off. 12 other queries (`user:`, `url:`, `+demo`, `notes:`, `title:Ser*`, `pass:`, `attr:`, quoted, `tag:`, `is:expired` and others) give the same paths in both. First pass (**F1**): `is:weak` was cut short without a notice. Re-check: big-10000 gives 10,000 lines, identical to the reference; option-a-personal gives 6, matching App's `db-info` (the entries differ by App's estimator) |
| C26 | same | pass | `show`, `-s`, `--all`, `--all -s`, `-a` lists (with `uuid` giving M10-63 and exit 1 after the other values), `-s -a Password`, `--show-attachments`, three path forms, `/` (the untitled entry, Uuid `…0f`), a bin entry, `-t` (the same 6 digits in the same 30 s window): stdout identical except `(hidden)` and `Attached files:` |
| C27 | same | pass | `exit` in the shell: exit 0 |
| C28 | same | pass | `quit` in the shell: exit 0; pty Ctrl-D: exit 0; SIGTERM: ended by 15, echo on |
| T1 | same | pass | `app`: usage and 26 commands on stdout, exit 0 (no `diceware`) |
| T2 | same | pass | `-h`, `--help`: the same 32 lines, exit 0 |
| T3 | differs | pass | `--help-all`: the same as `--help` |
| T4 | same | pass | `-v`, `--version`: `0.1.0` alone, exit 0 (the reference: `2.7.11` alone) |
| T5 | same | pass | `--debug-info`: product and version, build type `release`, OS, CPU, kernel, features, crypto crates; no path, no setting; exit 0 |
| N1, N2, N3 | not on Mac | skipped | Windows help option, outside copy programs, Windows code pages: none exist on macOS |

## SC-07: no secret printed unless asked

- `show` without `-s` prints `Password: (hidden)` and `(hidden)` for `Demo PIN` and `otp`. `-s`, `-a Password` and `-s -a Password` print the value.
- **R10-2 masking**, on a copy of rich-v3:
  - "Full demo entry" set to notes `pw={PASSWORD} pin={S:Demo PIN} hint={S:Demo hint}`, URL `https://x.example/{PASSWORD}` and user name `{S:otp}`.
  - A new entry `Refs` with notes `ref={REF:P@I:…0A} user={REF:U@I:…0A}` and user name `{REF:P@T:Server login}`.
  - App without `-s`: `UserName: (hidden)`, `URL: https://x.example/(hidden)`, `Notes: pw=(hidden) pin=(hidden) hint=not protected`; in Refs, `UserName: (hidden)` and `Notes: ref=(hidden) user=(hidden)`. The unprotected `{S:Demo hint}` resolves in clear.
  - `-s` and `-a Notes -a URL -a UserName` print the full resolution.
  - The reference prints every one of those secrets in clear without `-s`.
- `add -g` and `edit -g -L 40`: the stored password (32 and 40 characters) is in neither stdout nor stderr.
- A wrong password typed is never echoed back. Prompts on a pty echo nothing (App and reference).
- `ls -R`, `search`, `db-info`, `show`, `show --all` and `show --show-attachments` on rich-v3: 0 hits for `demo-entry-pass-2`, `0000`, the one-time code secret and the vault password.
- Merge change lines hold names and ids, no values.
- `strings` of the release `app` finds 0 `APP_TEST` names, so a release build reads no test switch.
- Clip: marked, cleared only while still ours, cleared on a quit signal (C6 above).
- The general pasteboard was untouched: its change count was 10124 before and after.

## Exit codes and streams

- 74 App runs (`/tmp/v-e12/bin/sweep.sh`) gave exactly two exit codes, 0 and 1.
- No failing run wrote to stdout, and no failing run was silent.
- No stdout held a prompt. The one flag was `db-info`'s data label "Most uses of one password:", not a prompt.
- Every prompt seen in the comparisons went to stderr (G4).

## Vaults across the two tools

- The changing commands left App's file and the reference's file with the same content, read by **both** exports (C1, C4, C5, C12, C20, C23, C24: identical apart from the differences named in their rows). So the reference opens what App writes, and App opens what the reference writes.
- `db-create`, `db-edit` and `import` results open in the other tool (C8, C9, C17).
- App reads the 18 openable reference test vaults with the same content as the reference.
  - The version 1 file gets M06-02 in App and the reference's own refusal.
  - The broken-header file gives wrong credentials in both, with password `a`.

## Release hardening (SR-05, APP-11)

The probe is `attach.c` (`ptrace(PT_ATTACHEXC)` with a SIGSEGV handler) and `inject.dylib` (it records `RLIMIT_CORE` at load and 1 s later). The release `app` is linker-signed without the runtime flag, so the library loads. The shell set `ulimit -c unlimited`, and `app ls a.appvault` waited at its prompt on a FIFO that was never written.

```
shell core limit: soft=unlimited hard=unlimited
pid=64861 stderr-so-far=[Vault password for a.appvault: ]
attach -1 16 true
app still running after the attach attempt
loaded core soft=9223372036854775807 hard=9223372036854775807
after-start core soft=0 hard=0
ended by PID 64861 (SIGKILL), status 137
--- control: debug app (no hardening) at its prompt:
attach -1 1 false
after-start core soft=9223372036854775807 hard=9223372036854775807
files in /cores: 0
```

The release tool refuses the attach with EBUSY plus SIGSEGV and keeps running, and its core limit is 0/0. The debug control gets EPERM and keeps its inherited limit.

## Tests

`CARGO_TARGET_DIR=/tmp/v-e12-target cargo test -p app-cli`, run once:

```
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 111 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.05s
```

The tests include `int10_10_a…`, `int10_12_b…` (both), `int10_15_a…` to `int10_15_d…`, `int10_29_a…` to `int10_29_g…`, `int10_40_a_merge` and `int10_45_a…` to `int10_45_c…`, all `ok`.

## CPU

- About 9 CPU minutes in all: release build 1.7 min, debug build 4.3 min, the test run 2.5 min, the comparison runs about 1 min.
- The longest single run took 45 s wall time (the debug build). Nothing ran near 30 minutes.

## Next step

None for E12-S1. For the card owner: fix the stale "Counts" line under the parity table (see Re-check).
