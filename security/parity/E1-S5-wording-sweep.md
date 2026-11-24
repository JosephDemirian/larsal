# E1-S5 Wording sweep

Story: E1-S5 Larsal cards, the wording sweep listed under "Open, decided when the story starts" in [spec/decisions.md](../../spec/decisions.md).
Date: 2026-10-28.
Result: 23 copied or near-copied Larsal texts found in the cards and rewritten in our own words, plus 1 label lined up with the locked mockup. `crates/larsal-ffi/src/messages.rs` had no hits, so it was not changed. The locked mockup has 4 hits. The mockup was not edited; the hits are listed at the end for the lead, with wording to use instead.

## What was compared

Larsal texts (12,284 segments in all):
- every line of spec/app/APP-01 to APP-11 and spec/model/MOD-12, split into table cells. Text inside quotes was also checked as separate strings. This covers every message id: 35 `MSG-` ids, 37 `M06-`, 32 `M07-`, 9 `M09-`, 6 `M08-`, and the 7 `vault.msg.*` ids of MOD-12.10;
- the 76 string literals in `crates/larsal-ffi/src/messages.rs`;
- all 4,894 strings in `design/option-a/manifest.json` (91 frames);
- extra, report only: the string literals in every `crates/*/src` file and every Swift file under `macos/`.

Reference texts: 2,375 unique English UI strings from the reference source (commit 09e34ba8). They come from its English translation source file (every message source text), its UI form files (every string element) and every translation call in its C++ files, with joined literals put back together. The reference app was not started.

## Method

The overlap script is in `/tmp/e1s5/`, outside this folder: `ref.py` pulls the reference strings, `check.py` and `local.py` compare. Both sides are made comparable first: lower case, no HTML tags, no menu shortcut marks, and placeholders (`%1`, `{}`, `<file>`) turned into one token. The reference's own name becomes "Larsal". Word swaps a copier would make are undone, so they cannot hide a copy: "database" counts as "vault", "hardware key" as "security key", "username" as "user name". Five checks:

1. **Exact runs:** any run of 6 or more words, in order, shared by a Larsal segment and a reference string. Runs of exactly 5 words were listed for review.
2. **Near sentences:** a Larsal sentence of 5 or more words that matches a reference sentence with a word ratio of 0.70 or more and at least 5 shared words.
3. **Near copies inside long lines:** the words of a reference sentence appear in order, close together, inside a Larsal segment, with one or two words changed. The test: 6 or more shared words, at least 3 of them content words, within 1.5 times the reference sentence's length. A short reference sentence also counts when 5 shared words make up 70% of it.
4. **Whole strings:** a Larsal string of 3 to 12 words equal to a whole reference string, or 3 to 5 words with a ratio of 0.8 or more.
5. **The setting labels:** each APP-01 setting label set beside its closest reference string, read by hand.

Every hit was read by hand and sorted into: a copy (rewritten); a short generic UI phrase (kept, by the brief's rule); or a false hit (common words spread across a long line, or a file-format fact).

Counts (cards, messages.rs and the mockup):

| Check | Hits before | Hits after | What is left |
|---|---|---|---|
| Exact run, 6 or more words | 3 | 2 | 1 mockup hit; 1 time-format fact |
| Exact run, 5 words | 11 | 3 | 2 mockup hits; "did not finish in time" (generic, in card prose) |
| Near sentence | 17 | 9 | 3 mockup hits (each shown twice); "Move "Amazon" to the Recycle Bin?" (generic, 4 frames); 2 "could not be created" (generic) |
| Near copy in a long line | 32 | 15 | 3 mockup hits; 12 false hits (common words such as "a key file", "the vault", "could not be created") |

## Hits and fixes (cards)

"Ref" is the reference's English string. Product names in it are written as "[ref app]".

| # | Where | Larsal text before | Ref | Larsal text now |
|---|---|---|---|---|
| 1 | APP-01 S-FILE-01 label; also the APP-02 settings table, the APP-05 settings table and the APP-05.2 title | Save after every change | Automatically save after every change | Save changes as you make them |
| 2 | APP-01 S-ENTRY-02 label; MOD-04 quotes it twice (both updated) | Ask before moving entries to the recycle bin | Show confirmation before moving entries to recycle bin | Ask before moving to the Recycle Bin (the mockup's wording) |
| 3 | APP-01 S-ENTRY-07 label | Minimize after opening a URL | Minimize when opening a URL | Minimize the window when a link opens |
| 4 | APP-01 S-AT-08 label | Remember the last chosen entry for | Remember last typed entry for: | Preselect the previous choice for |
| 5 | APP-01 S-CONV-03 label | Hide passwords in the preview panel | Hide passwords in the entry preview panel | Hide passwords in the detail pane (the mockup's wording) |
| 6 | APP-01 S-CONV-04 label | Hide one-time codes in the preview panel | Hide TOTP in the entry preview panel | Hide one-time codes in the detail pane (the mockup's wording) |
| 7 | APP-01 S-BRW-13 effect | An "expired" mark is added to the title | Returns expired credentials. String [expired] is added to the title. | The entry's title carries an "expired" mark |
| 8 | APP-01 S-BRW-15 label | Never ask before giving credentials | Never ask before accessing credentials | Never ask before giving access (the mockup's wording) |
| 9 | APP-01 S-BRW-16 label | Never ask before updating credentials | Never ask before updating credentials | Update saved logins without asking |
| 10 | APP-01 S-BRW-22 label | Allow a limited list of all entries (ignores site access rules) | Allow limited access to all entries in connected databases (ignores site access restrictions) | Let the extension list every entry (skips site rules) |
| 11 | APP-01 S-BRW-22 effect | The extension may list title, URL and id of every entry in connected vaults | Allow [ref app]-proxy to list all entries with their title, URL and UUID in connected databases. | The extension can fetch the title, URL and id of each entry in every connected vault |
| 12 | APP-01 S-SHARE-03 label; INT-08 setting row and INT-08.26 (updated to match) | Only show warnings and errors | Only show warnings and errors | Hide sync success messages |
| 13 | APP-05 `MSG-DISK-NEW-KEY` and its summary in APP-05.29 | The file on disk cannot be opened with the current credentials. Enter the new ones. | Database file on disk cannot be unlocked with current credentials. Enter new credentials and/or present hardware key to continue. | This vault's password or key was changed elsewhere. Unlock the changed file to go on. (The "Reference" cell said "the same"; it now gives the meaning in our words.) |
| 14 | APP-05 `MSG-DISK-UNREADABLE` and its summary in APP-05.30 | The file on disk cannot be read. … | (the 5-word opening of #13's Ref) | Larsal could not read the file on disk. … |
| 15 | APP-06 M06-31, "When" cell | The chosen key file's name ends like a vault file | The chosen key file looks like a password database file. … | The key file's name has a vault file extension |
| 16 | APP-06 M06-32 "When" cell, APP-06.11 step 2, APP-07 M07-28 "When" cell, APP-07.14 | … is in an old format / An old format (…) | You selected a key file in an old format which [ref app] may stop supporting in the future. … | … is of an early kind / A key file of an early kind (…), the words the message itself already uses |
| 17 | APP-06, reference note under APP-06.12 | it offers once to retry with an empty password (default button: retry) | Do you want to retry with an "empty" password instead? | it offers once to try again with no password (default button: try again) |
| 18 | APP-07 M07-03 | … You can change the name and the description later in Vault Settings. | … Don't worry, you can change them later in the database settings. | … Name and description stay editable in Vault Settings. |
| 19 | APP-07 M07-05 | … You can change this later in Vault Settings. | (same as #18) | … Vault Settings › Security can change it at any time. |
| 20 | APP-07 M07-30, "When" cell | Writing the vault failed | Writing the database failed: %1 | The vault file cannot be written |
| 21 | APP-09 M09-04 | Larsal is not running. There is no open vault to lock. | [ref app] is not running. No open database to lock | No copy of Larsal is running, so there is nothing to lock. |
| 22 | APP-02, Windows and Linux note | "minimize to the tray" and "minimize instead of exit" (quoted labels) | Hide window to system tray when minimized; Minimize instead of app exit | settings that send the window to the tray when it is minimized or closed |
| 23 | MOD-12.10 step 1, `vault.msg.no_password` | (a vault without password is strongly discouraged) | … Using a database without a password is strongly discouraged! … | (Larsal advises against a vault with no password) |

Lined up with the mockup, below the threshold: APP-01 S-BRW-12 "Return only the best matches" is now "Offer only the best matches", as in the mockup. Ref: "Return only best-matching credentials".

`messages.rs`: no hits. Its one flagged string is M06-30 ("This is the vault file itself, so it cannot also be its key file. …"). That was a false hit: it shares only common words, spread out, with an unrelated command line help line. No code or test was changed, so `cargo test -p larsal-ffi` was not needed.

## Reviewed and kept

- **Short generic labels (2 to 4 words, a plain verb and its object):** S-VIEW-06 "Hide user names", S-VIEW-07 "Hide passwords", S-VIEW-03 "Show the group panel", S-VIEW-04 "Show the preview panel", S-AT-07 "Global Auto-Type shortcut", S-TIME-01 "Clear the clipboard after", S-START-04 "Minimize after unlocking", S-START-05 "Remember recently used vaults", S-FILE-02 "Save when locking". They match reference menu items or labels only as plain words that any Mac app would use for the same toggle (the brief's rule; LD-100 keeps plain action names). S-VIEW-06 and S-VIEW-07 were named in the brief. They are kept for this reason: two or three words with nothing that only the reference would say.
- **Menu items already ruled:** "Empty Recycle Bin…", "Check for Updates…", "Copy Username", "Remove from SSH Agent" (LD-100); the key list item format (LD-101).
- **Facts:** APP-05.20's backup name time format `dd_MM_yyyy_HH-mm-ss` is a file-naming format, not wording.
- **Generic phrases:** M07-30 "The vault could not be created: <reason>." and M09-06 "Larsal cannot start: the instance lock PATH could not be created (REASON)." The words "could not be created" are common; the reference line they matched is about something else. "Did not finish in time" appears in APP-02.20's prose; "Continue without password" is a button in MOD-12.
- **False hits:** 12 near-copy hits in long prose lines of APP-05, APP-06 and APP-07. Each shares only words like "a key file", "the vault", "version 2 or 3", spread across a sentence.

## Mockup hits for the lead (not edited)

| Frame (manifest) | Mockup text | Ref | Wording to use |
|---|---|---|---|
| list[38] `settings-settings-general` | Save after every change | Automatically save after every change | Save changes as you make them (card S-FILE-01) |
| list[41] `settings-settings-browser-integration` | Use a custom proxy location | Use a custom proxy location: | Use my own proxy program (the card S-BRW-23 label) |
| list[25] `editor-editor-browser` | Hide this entry from the browser | Hide this entry from the browser extension | Never offer this entry to browsers |
| list[24] `editor-editor-auto-type` | Auto-Type for this entry | Enable Auto-Type for this entry | Let Auto-Type use this entry |

Seen while checking, not a wording hit: list[40] `settings-settings-auto-type` "Do not type the same login again within" seems to say the opposite of S-AT-08. In the reference, the last chosen entry is preselected in the chooser for that many seconds. The lead should check it against INT-05 when that card is written.

## Follow-ups outside the card files

- `crates/larsal-ffi/src/instance.rs` line 19, `NOT_RUNNING`, still holds the old M09-04 text. It should become "No copy of Larsal is running, so there is nothing to lock." `tests/app09.rs` checks the constant, not the literal text, so no test text changes. This file belongs to E5-S1 and is not part of this sweep's files, so it is left to the lead. The old text in security/parity/E5-S1-to-E5-S4.md is recorded output and stays as it is.
- Extra scan, out of scope: `crates/larsal-core/src/import/csv.rs` and FEA-08.24 give the imported root group the notes "Imported from CSV file: <path>". That is the reference's own note text: 4 words and a path, below the threshold, in a card whose Checker already passed it. The lead may want our own words there too.
- Not compared: Larsal texts that are still unwritten (INT cards other than INT-04 and INT-08, Swift screens not yet built). The same script can be run again when they exist.
