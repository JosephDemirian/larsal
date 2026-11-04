# MOD-05 Attachments

Status: reviewed
Epics: E4-S4
Parity rows: SR-07, SD-04, SD-09, SD-11

## What it does

An entry can hold files, called attachments. Each attachment is a name and its content bytes. The user adds files from disk or by drag and drop, makes new text attachments, renames, edits text, previews, opens a file in another app, saves to disk and removes. Attachment changes are entry changes: they go into the entry's history (MOD-03).

This card owns the behavior. Other cards own the rest:

- how attachments are stored in the file, the shared pool, de-duplication, the protected flag byte, duplicate names in a file, broken references: FMT-13;
- the size limits that reading enforces: FMT-08.12 (one table for all limits);
- history snapshots and history size: MOD-03;
- SSH keys kept in attachments: INT-06; the command line syntax: INT-10; merge: MOD-11.

Words used here. **Editor draft**: the copy of the entry's attachments the entry editor works on; it reaches the entry only when the user commits (OK or Apply). **Sniffed type**: the media type guessed from the content bytes. It decides Edit (MOD-05.8) and whether Preview shows an image, text or a note (MOD-05.9). Only for text does Preview look at the name's extension, to pick plain, HTML or Markdown display.

## Inputs and outputs

| Item | Type | Limits |
|---|---|---|
| Attachment name | text, case-sensitive, compared exactly | not empty (Larsal, MOD-05.2); any other text allowed |
| Attachment content | bytes, may be empty | one attachment and all attachments: FMT-08.12 (Larsal, MOD-05.14) |
| Files from disk | paths chosen in a file dialog or dropped | regular files only |

Outputs: the entry's attachment set; files written to disk (save, open); messages.

## Rules

### The attachment set

MOD-05.1 **Model.** An entry (and each history item) holds a set of attachments keyed by name. Names are unique within one entry and compared exactly (case-sensitive: `a.txt` and `A.txt` are two names). Content may be 0 bytes. Lists show attachments sorted by name in UTF-16 code unit order (so `B.txt` comes before `a.txt`), with a size column in human units. There is no per-attachment option: the file's protected flag byte is ignored on read and always written as `01` (FMT-13.3), and Larsal keeps all content in `SecretBytes`.

MOD-05.2 **Names.** Larsal accepts any non-empty name, including names with `/`, `\`, `:` or a leading dot; it refuses an empty name everywhere it takes a name (add, rename, command line import), with the message that the name cannot be empty (lead decision L05-1). Reference: the command line tool accepts an empty name, but such an attachment reads back with 0 bytes, so its content is lost (FMT-13.12; observed). A file can still bring an empty name; FMT-13.12 says how it is read, and Larsal shows it as `(no name)` in lists while keeping the empty name in the file.

MOD-05.3 **Where attachments are managed.**

| Place | Actions |
|---|---|
| Entry editor, Advanced page | Add from disk, New text attachment, Rename, Edit (text only), Preview, Open, Save to disk, Remove, drag and drop |
| Main screen preview panel (read-only) | Preview, Open, Save to disk |
| Read-only view of a history item (MOD-03.12) | Preview, Open, Save to disk |
| Command line (INT-10) | import, export, remove |

Double-click on an attachment: Edit in the editor, Preview in read-only places.

MOD-05.4 **Editor draft and history.** In the editor, every attachment action works on the editor draft. Commit applies the draft to the entry inside the editor's edit session, so all attachment changes of one commit, together with other field changes, give one history item (MOD-03.2, MOD-03.4). Cancel and discard drops the draft. Applying a draft equal to the entry's current attachments is no change. Every later attachment change after Apply also goes through the draft (Larsal never applies attachment changes straight to the live entry; the reference does after Apply, MOD-03 edge cases).

### Adding

MOD-05.5 **Add from disk.** The file dialog allows several files and starts in the folder used last for attachments (Larsal remembers it per user, not in the vault; APP-01). For each chosen file, in order:

1. The attachment name is the file's last path component.
2. If the entry already has that name, Larsal asks whether to overwrite the existing attachment (Overwrite, No; default No). No skips this file.
3. If the file is larger than 5 MiB (more than 5,242,880 bytes), Larsal asks whether to add a big file, saying the vault may become very large and slow, and showing the size in MiB with one decimal, labelled "MB" (Yes, No; default No). No skips this file.
4. Larsal reads the whole file. If reading fails, Larsal collects "name - reason" and goes on with the next file.

Then Larsal adds every read file (an existing name gets the new content) and shows one message listing every failed file. If two chosen files have the same name (from different folders), the later one wins without a question (reference behavior, kept).

MOD-05.6 **Drag and drop.** Files can be dropped only on the attachment list of the entry editor (AT-E06): never on read-only places, never anywhere else in the window. Only local regular files are taken; folders, links that are not files, and non-file URLs are ignored. Symbolic links to files are followed. Larsal applies steps 2 and 3 of MOD-05.5 to dropped files too (lead decision L05-2). Reference: a drop adds files with no overwrite question and no size question, so it silently replaces an attachment of the same name.

MOD-05.7 **New text attachment.** Adds an empty attachment named `New Attachment.txt`, or, when that name is taken, `New Attachment_1.txt`, `New Attachment_2.txt` and so on (first free number). Larsal then starts renaming it (MOD-05.10). The base name follows the interface language, as in the reference.

### Viewing and editing

MOD-05.8 **Edit text.** Edit is available only in the editor, for one selected attachment whose sniffed content type is text: a media type starting with `text/` (HTML and Markdown included), `application/json`, `application/xml`, `application/soap+xml`, `application/x-yaml`, `application/protobuf`, or the empty-file type `application/x-zerosize`. It opens an in-app text editor; OK replaces the content in the draft, Cancel leaves it. The name cannot be changed there.

MOD-05.9 **Preview.** Preview shows one attachment inside Larsal, never through another app and never through a file on disk:

| Sniffed content type | Shown as |
|---|---|
| image | the image, with zoom |
| text (as in MOD-05.8) | text. The reference picks plain, HTML or Markdown display from the name's extension, and the user can switch |
| anything else | a note that the type cannot be shown |

Larsal renders HTML and Markdown attachments only as plain text or as sanitized markup with no scripts, no remote loads and no forms; links are not followed (lead decision L05-3). Reference: renders HTML and Markdown as rich text, and opens clicked links with the system handler. The preview updates if the attachment changes while it is shown. From the preview, the user can also Open and Save.

MOD-05.10 **Rename.** Rename edits the name in place. Larsal trims white space at both ends of the new name. If the result is empty, or equals a name the entry already has (exactly, so a change of case only is allowed), nothing changes and Larsal says why (the reference refuses silently). Otherwise the content moves to the new name. An open temporary copy of the old name is wiped and removed (MOD-05.12).

MOD-05.11 **Remove.** After the question whether to remove N attachments (Remove, Cancel; default Cancel), Larsal removes the selected attachments from the draft. Removing adds no deleted-object record (FMT-15.8). The content stays in the entry's history items (MOD-03.14). An open temporary copy is wiped and removed (MOD-05.12).

### Files on disk

MOD-05.12 **Open.** Open hands an attachment to the default app for its type. Reference behavior:

| Step | Reference |
|---|---|
| Where | the user's temporary folder (on macOS the per-user folder in `TMPDIR`) |
| File name | 12 random letters and digits, then the attachment's extension: a dot and the text after the last dot of the name, when the name has a dot (`report.final.pdf` gives `.pdf`; `notes` gives no extension; `.profile` gives `.profile`) |
| Permissions | owner read and write only (0600), set right after creating the file |
| Then | the system opens the file with its default app. The file is watched (MOD-05.13) |
| Opened again while the copy exists | the copy is overwritten with the attachment's current content (unsaved outside edits are lost), then opened again |
| Removal | the file is overwritten with random bytes in 128-byte blocks (file size ÷ 128, plus one block), then deleted. This happens when the attachment is removed or renamed, when the set of attachments holding it is replaced by different content (for example the entry is changed by an editor commit), when the editor closes (for copies opened from the editor), and when the entry is destroyed (vault locked, closed, reloaded, or the entry deleted for good) |
| Not removed | after a crash or a forced quit; copies the other app makes itself |
| Errors | writing the copy fails: "could not open" with the attachment name and the system's reason; the system cannot open the file: "cannot open file" with the attachment name only |

Larsal rules (lead decision L05-4, recommended option):

1. Larsal writes the copy into a private folder of its own, `Larsal/open-attachments` inside the per-user temporary folder, created with 0700, and the file with 0600, created exclusively (never following a link, never reusing an existing path).
2. Names as in the reference (12 random characters from larsal-crypto random, plus the extension).
3. Before opening a file whose extension can run code or commands when opened (for example `.app`, `.command`, `.terminal`, `.tool`, `.sh`, `.pkg`, `.mpkg`, `.dmg`, `.scpt`, `.applescript`, `.workflow`, `.webloc`, `.inetloc`, `.fileloc`, `.jar`, `.html`, `.htm`, `.svg`), Larsal asks the user to confirm, naming the risk.
4. Larsal removes the copy as the reference does, and also on quit, and removes any leftover copies in its folder at the next start.
5. Larsal says, in the help text for Open, that the file is decrypted on disk while open.

MOD-05.13 **Changes made in the other app.** Larsal watches each open copy, using file change events plus a content check (SHA-256 of the whole file) every 5 seconds. When the content changes, Larsal asks whether to save the changed attachment into the vault (Save, Discard; default Save). Only one question per file is shown at a time. Save reads the whole file and replaces the attachment's content:

- copy opened from the editor: into the editor draft (MOD-05.4);
- copy opened from the preview panel: Larsal runs an edit session on the entry, giving one history item (MOD-03.4). The reference writes into the live entry with no history item.

If the file cannot be read, Larsal says saving the changed attachment failed, with the system's reason.

MOD-05.14 **Save to disk.** Save asks for a folder (not a file name), starting in the last attachment folder, and creates it when missing. For each selected attachment:

1. The file name is the attachment name with every `/` and `\` removed (Larsal also removes `:` and refuses a result that is empty, `.` or `..`, reporting it as an error for that attachment; L05-1).
2. If a file with that name exists, Larsal asks whether to overwrite it: Overwrite or Cancel, plus Skip when several attachments are being saved (default Cancel). Cancel stops the whole save; Skip goes to the next attachment.
3. Larsal writes the content with owner read and write only (0600). Larsal creates new files with 0600 from the start and replaces an existing file in one step, without following a link at that path (AT-I04, AT-I06).

Errors are collected ("name - reason") and shown together at the end. Reference: opens the file for writing, then sets owner read and write; it follows links.

MOD-05.15 **Command line.** Import adds a named attachment from a file and refuses an existing name unless forced (message: the attachment already exists for the entry); export writes one attachment to a file or to standard output; remove deletes one by name (INT-10 owns syntax and messages). Import and remove are edit sessions (MOD-03.4). Export never changes the vault. Reference export overwrites an existing file without asking and uses default permissions (observed: 0644 with umask 022). Larsal's command line export writes with 0600 and asks before overwriting unless a force option is given (lead decision L05-5).

### Limits, storage and history

MOD-05.16 **Size limits.** The reference has no limit of its own beyond the 5 MiB question (MOD-05.5). Larsal never writes a vault it would refuse to read (FMT-08.12). So before adding or replacing content, Larsal checks it against the one attachment limit and the all attachments limit of FMT-08.12, counting each distinct content once (as the file stores it, FMT-13.16), and refuses the add with a message naming the limit. The save keeps its own check (FMT-08.12) as the last guard.

MOD-05.17 **Shared content.** Equal content is stored once in the file (FMT-13.16, FMT-13.17). Larsal also keeps one copy in memory for equal content held by an entry and its history items (reference counting over `SecretBytes`), so history does not multiply memory. This is invisible to the user: each entry and history item still has its own name-to-content set, and changing one never changes another.

MOD-05.18 **History.** Attachments are part of every history item (MOD-03.1). History size counts every item's attachments in full (MOD-03.7), so with the default 6 MiB limit an entry with a 4 MB attachment keeps about one history item (MOD-03 test 03-14). Removing an attachment does not remove it from history (MOD-03.14). Attachments of history items are read-only.

MOD-05.19 **Names on screen.** Attachment names are always set as text, never as markup (AT-E01). They appear in the list, in questions and in error messages.

## Edge cases and errors

| Case | Result |
|---|---|
| Two files `a.txt` from different folders chosen at once | One attachment `a.txt` with the second file's content |
| File of exactly 5,242,880 bytes | No size question. 5,242,881 bytes: question, shown as "5.0 MB" |
| Empty file | Added, 0 bytes |
| Rename `a.txt` to ` b.txt ` | Becomes `b.txt` |
| Rename `a.txt` to `A.txt` | Allowed |
| Rename to an existing name or to white space only | Nothing changes; Larsal says why |
| Edit on an image | Not offered (the Edit button is off for non-text content) |
| Command line import with name `dir/x.txt` | Accepted (observed). Save to disk writes it as `dirx.txt` |
| Command line import with an empty name | Larsal: refused. Reference: accepted, and the content is 0 bytes after reopening (observed) |
| Command line import over an existing name with force and equal content | No change, no history item (observed) |
| Opening the same attachment twice while the first copy is open | Reference: the copy is overwritten with the current content and opened again. Larsal: the same |
| Attachment named `x.terminal` (or another type of MOD-05.12 step 3) | Larsal asks before opening. Reference: opens it with no question |
| Editor closed while a copy opened from it is still open in another app | The copy is wiped and deleted; later edits in the other app are not saved back |
| Vault locked while a copy is open | The copy is wiped and deleted |
| Save to disk into a folder where the target name is a symbolic link | Larsal: written as a new file at that path, never through the link (MOD-05.14). Reference: writes through the link |
| A dangling or duplicate name read from a file | FMT-13.11, FMT-13.13 |

Not on Mac: the reference writes open copies into a per-app folder inside the sandbox data folder for its Linux snap and flatpak packages instead of the system temporary folder.

## Security notes

- Attachments are secrets (plan/security.md). Content lives in `SecretBytes`, is wiped when dropped, and never goes to logs, error text or crash reports (SR-07; AT-C01, AT-C04, AT-C06). Messages name the attachment, never show content.
- Open writes decrypted content to disk (MOD-05.12). On APFS and on SSDs, overwriting a file does not reliably destroy the old blocks, so the random overwrite is best effort only; the real protection is a private 0700 folder, 0600 files, short lifetime and clean-up at quit and start. A crash leaves the copy until the next start. Parity rows SD-11 (open, watch, wipe) and SD-09 (owner-only files).
- Opening an attachment can run code: some file types run commands when opened by their default app (MOD-05.12 step 3). A hostile vault (a shared group, INT-08, or a merged file) can bring such an attachment. Larsal asks first; the reference does not.
- Preview must not run scripts or load anything from the network (AT-E01, AT-E04). Links in previews are not followed (AT-E02).
- Saved and exported files are owner-only (AT-I06) and never written through a link (AT-I04). The reference command line export writes world-readable files (0644 under the usual umask).
- Drag and drop only adds files to the attachment list; nothing dropped is opened or run (AT-E06).
- Removing an attachment does not remove it from history (MOD-03.14); the user must delete history to erase it from the vault.
- A hostile vault can hold huge or many attachments; reading is bounded by FMT-08.12 and FMT-13.20 (AT-A06, AT-A08).

## Test cases

Demo vaults use the password `demo-pass`. Demo files are made in a scratch folder.

| Case | Given | When | Then |
|---|---|---|---|
| 05-01 sorted, case-sensitive (MOD-05.1) | Entry with attachments `b.txt`, `B.txt`, `a.txt` | Open the editor's Advanced page | Listed `B.txt`, `a.txt`, `b.txt`; three distinct attachments |
| 05-02 empty name refused (MOD-05.2) | Entry E | Command line import with name "" from a.txt ("hello"); rename an attachment to "" in the editor | Larsal: both refused with a message, nothing changes. Reference: the import succeeds and after reopening the attachment shows 0 B (observed) |
| 05-03 add, collision (MOD-05.5) | Entry with `f.txt` = "old" | Add from disk `f.txt` = "new", answer No; again, answer Overwrite | After No: `f.txt` = "old". After Overwrite: `f.txt` = "new" in the draft; after OK one history item holding "old" |
| 05-04 size question (MOD-05.5) | Files `s.bin` of 5,242,880 bytes and `t.bin` of 5,242,881 bytes | Add both from disk | No question for `s.bin`; a question for `t.bin` showing "5.0 MB"; No adds only `s.bin` |
| 05-05 read error (MOD-05.5) | Files `ok.txt` and `locked.txt` (no read permission) | Add both | `ok.txt` added; one message listing `locked.txt` with the reason |
| 05-06 drag and drop (MOD-05.6, L05-2) | Entry with `f.txt`; a folder `dir`, a file `f.txt` and a file `big.bin` of 6 MiB | Drop all three on the editor's attachment list | Larsal: `dir` ignored; overwrite question for `f.txt`; size question for `big.bin`. Reference: `f.txt` replaced and `big.bin` added with no question |
| 05-07 drop elsewhere (MOD-05.6) | Main window with an entry selected | Drop a file on the preview panel and on the entry list | Nothing is added or opened |
| 05-08 new text attachment (MOD-05.7) | Entry with `New Attachment.txt` and `New Attachment_1.txt` | New text attachment | `New Attachment_2.txt`, 0 bytes, in rename mode |
| 05-09 edit text (MOD-05.8) | Attachments `n.txt` ("a\nb"), `p.png` (a PNG) | Select each | Edit on for `n.txt`, off for `p.png`. Edit `n.txt` to "a\nc", OK, then OK in the editor: content "a\nc", one history item |
| 05-10 preview HTML (MOD-05.9, L05-3) | Attachment `x.html` = `<script>alert(1)</script><a href="https://evil.example">x</a><img src="https://evil.example/p.png">` | Preview | Larsal: no script runs, no network request is made (network capture), the link does nothing. Reference: rich text with a clickable link |
| 05-11 rename (MOD-05.10) | Attachments `a.txt`, `b.txt` | Rename `a.txt` to ` c.txt `; rename `c.txt` to `b.txt`; rename `c.txt` to `C.txt` | `c.txt`; refused with a message (name exists); `C.txt` |
| 05-12 remove (MOD-05.11) | Entry with `a.txt`, no history | Remove `a.txt`, confirm, OK | No attachment on the entry; one history item holds `a.txt`; deleted objects unchanged |
| 05-13 open, temp file (MOD-05.12, L05-4) | Attachment `report.final.pdf` | Open | A file named 12 letters and digits plus `.pdf` exists in `Larsal/open-attachments` under `TMPDIR`; folder mode 0700, file mode 0600; content equals the attachment |
| 05-14 open, clean-up (MOD-05.12) | The copy from 05-13 | Lock the vault | The file no longer exists |
| 05-15 open, leftovers (MOD-05.12) | A copy left in `Larsal/open-attachments` (Larsal killed with SIGKILL) | Start Larsal | The folder is empty |
| 05-16 risky type (MOD-05.12) | Attachment `run.terminal` | Open | Larsal asks first; No writes no file and opens nothing |
| 05-17 outside change (MOD-05.13) | `n.txt` opened from the editor | Change the copy outside, wait 5 seconds, answer Save, then OK in the editor | `n.txt` has the new content; one history item |
| 05-18 outside change from the preview panel (MOD-05.13) | `n.txt` opened from the main screen's preview panel; entry has 0 history items | Change the copy outside, answer Save | Larsal: new content and 1 history item. Reference (from source): new content, 0 history items |
| 05-19 save to disk (MOD-05.14) | Attachments `a/b\c.txt` ("x") and `ok.txt`; the folder already has `ok.txt` | Save both to the folder; answer Skip for `ok.txt` | `abc.txt` written, mode 0600, content "x"; existing `ok.txt` unchanged |
| 05-20 save, cancel (MOD-05.14) | As 05-19, but `abc.txt` exists too | Save both; answer Cancel at the first question | Nothing more is written |
| 05-21 save, link (MOD-05.14) | In the target folder, `ok.txt` is a symbolic link to `/tmp/spec-target.txt` | Save `ok.txt`, Overwrite | Larsal: `ok.txt` is now a regular file with mode 0600; `/tmp/spec-target.txt` unchanged |
| 05-22 command line import (MOD-05.15) | Entry E with `f.txt` = "hello" | Import `f.txt` from b.txt without force | Fails: the attachment already exists for entry E; vault unchanged (observed) |
| 05-23 command line export (MOD-05.15, L05-5) | Entry E with `f.txt` = "other" | Export `f.txt` to out.bin, with umask 022 | Larsal: out.bin mode 0600. Reference: 0644 (observed) |
| 05-24 limits (MOD-05.16) | Test limits lowered: one attachment 1 MiB, all attachments 2 MiB. Vault with 1.5 MiB of attachments | Add a 1.5 MiB file; add a 0.4 MiB file; add a copy of an existing 1 MiB attachment to another entry | First: refused, naming one attachment. Second: added. Third: added (equal content counts once) |
| 05-25 shared memory (MOD-05.17) | Entry with a 10 MiB attachment and 1 history item holding the same content | Measure Larsal memory for attachment content | About 10 MiB, not 20 |
| 05-26 history size (MOD-05.18) | Default limits, entry with a 4,000,000-byte attachment | Edit the title twice | 1 history item (MOD-03 test 03-14) |
| 05-27 names as text (MOD-05.19) | Attachment named `<img src=x onerror=alert(1)>.txt` | Show the list, remove it (question), save it into a read-only folder (error) | The name is shown literally in all three; nothing runs |
| 05-28 places (MOD-05.3) | Entry with attachment `n.txt`, and one history item | Look at the preview panel, the read-only history item view, and the editor; double-click `n.txt` in each | Preview panel and history view: only Preview, Open and Save; double-click opens Preview. Editor: all actions; double-click opens Edit |
| 05-29 draft (MOD-05.4) | Entry with no attachments and no history | Editor: add `a.txt`, Cancel, discard. Then editor: add `a.txt`, Apply, add `b.txt`, OK | After the first: no attachment, no history. After the second: `a.txt` and `b.txt`, 2 history items (before `a.txt`, before `b.txt`) |

## How this was learned

- Reference source, read only: the attachment container (set, remove, rename, clear, copy, size, open, the external-change signal, and the wipe-and-delete routine), the file watcher (events plus a timed checksum), the attachment list widget (add from disk, the overwrite and big-file questions, drag and drop, new text attachment naming, edit, preview, remove, save to disk, open, the external-change question), the attachment list model (sorting, size column, in-place rename rules), the edit and preview dialogs and their text and image widgets, the media type helpers, the entry editor's use of a draft copy and its relinking after Apply, the preview panel, and the command line import, export and remove commands.
- Reference tests: the modification tests that change attachments inside edit sessions, and the attachment widget tests.
- Installed command line tool 2.7.11, demo vault `/tmp/spec-mod03-04-05/m5.larsalvault` (password `demo-pass`): import collisions with and without force, equal-content import, empty and path-like names, the 0-byte empty-name attachment after reopening, export overwrite and its file mode.
- check with Verify:
  - every window behavior here (open, watch, wipe, preview, edit, drop, rename, save) was read from the source; the window was not run.
- Checked by Verify (Sprint 2):
  - the installed version 2.7.11 has the newer preview and edit dialogs and the open-copy watcher: its app binary holds the class names of the preview dialog, the edit dialog, the text and image attachment widgets and the file watcher, and the signal for an attachment changed outside the app (observed by searching the installed binary; not run);
  - the reference removes open copies when the vault locks (source re-read): locking replaces the vault object with a new locked one; when the old one is destroyed, every entry's attachment container clears itself, and clearing overwrites each open copy with random bytes and deletes it. This holds as long as nothing else still holds the old vault object.
- Lead decisions (decided: spec/decisions.md default rule, each takes the recommended option):
  - L05-1: names. Recommended: refuse empty names on add, rename and import; on save to disk also strip `:` and refuse `""`, `.` and `..`. The reference accepts empty names on the command line and then loses their content.
  - L05-2: drag and drop asks the same overwrite and size questions as add from disk (the reference asks neither). Recommended.
  - L05-3: preview of HTML and Markdown. (a) as the reference, rich text with clickable links; (b) plain text only; (c) sanitized markup, no scripts, no remote loads, links inert. Recommended (c), falling back to (b) where sanitizing is not available.
  - L05-4: Open. (a) as the reference: system temporary folder, wipe on close and lock; (b) no Open at all, only Preview and Save; (c) the MOD-05.12 Larsal rules: private 0700 folder, exclusive 0600 files, a question for risky types, clean-up at quit and start. Recommended (c).
  - L05-5: command line export writes 0600 and asks before overwriting unless forced (the reference: 0644, overwrites). Recommended.
  - The Larsal limit check of MOD-05.16 (the reference has none). Recommended, because Larsal never writes a vault it would refuse to read.
