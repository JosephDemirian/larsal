# FEA-08 Import formats

Status: reviewed
Epics: E4-S13
Parity rows: SF-17 (encrypted import files: OPVault, the encrypted JSON export, version 1), SC-04, SR-07, SF-02 (version 1 key stretching); one more proposed row in "Security notes"

## What it does

Import turns a file made by another tool into groups and entries. The reference offers seven import kinds in one assistant: a CSV file, the .1pux format, the OPVault format, a Bitwarden JSON export (plain or password-protected), a Proton Pass JSON export, a remote vault (INT-09), and the version 1 format (the older format with second signature `65 FB 4B B5`, FMT-01.4). Its command line tool adds one more: the plain XML document of our format (FEA-09.12). Each reader builds an import result: a temporary vault model with one root group. The assistant then puts the result into a new vault or into a group of an open vault.

Other cards: MOD-11 owns the merge used for a new vault (MOD-11.1, "import wizard" row). APP-07 owns the new vault assistant. INT-09 owns the remote kind. INT-10 owns command line syntax. FEA-04 owns one-time password parsing. MOD-07 owns tag parsing. MOD-04 owns the recycle bin. INT-04 owns passkey fields. FMT-10 to FMT-15 own the XML document.

## Inputs and outputs

| Kind ID | Shown as | Input | Credentials | Root group name of the result |
|---|---|---|---|---|
| IMP-CSV | CSV file | one text file | none | common first path part, else the default root name (FEA-08.24) |
| IMP-1PUX | .1pux export | one ZIP file | none | lead decision L08-9 (the reference uses its maker's name plus "Import") |
| IMP-OPVAULT | OPVault | a folder (a bundle on the Mac, chosen like a file) | password | folder name without `.opvault` (FEA-08.40) |
| IMP-BITWARDEN | Bitwarden JSON | one JSON file | password (used only if the file is encrypted) | `Bitwarden Import` |
| IMP-PROTON | Proton Pass JSON | one JSON file (already unzipped by the user) | none | `Proton Pass Import` |
| IMP-REMOTE | Remote vault | a download command | password, key file | INT-09 |
| IMP-V1 | Version 1 file | one file | password, key file | `Root` |
| (command line) | XML document | one XML file | the new vault's credentials | from the document |

Output: the import result, then either a new vault (unsaved, marked modified) or new groups inside an open vault. Messages: the IDs in "Edge cases and errors".

## Rules

### A. The assistant and placement

FEA-08.1 **Entry points and kinds.** Action ACT-IMPORT (File menu and welcome screen, APP-08) opens the import assistant with two steps, Select and Review. Select lists the kinds in this order: IMP-CSV, IMP-1PUX, IMP-OPVAULT, IMP-BITWARDEN, IMP-PROTON, IMP-REMOTE, IMP-V1. IMP-REMOTE is listed only once remote sync is built (INT-09.30, D-INT09-1); until then the list has the other six (F-112). The first is selected at start. Picking another kind clears the file, password and key file fields.

FEA-08.2 **Fields per kind.** IMP-CSV, IMP-1PUX, IMP-PROTON show only the file field. IMP-BITWARDEN and IMP-OPVAULT add a password field. IMP-V1 adds password and key file. IMP-REMOTE shows the INT-09 fields instead of the file field. Next is enabled once the file field is not empty (IMP-REMOTE: once the command is not empty). File chooser filters: IMP-CSV `*.csv` or all files; IMP-1PUX `*.1pux`; IMP-OPVAULT `*.opvault`; IMP-BITWARDEN and IMP-PROTON `*.json`; IMP-V1 the version 1 extension, bytes `2E 6B 64 62` (given as hex, name rule). The key file chooser shows all files and `*.larsalkey`.

FEA-08.3 **Where to.** Three choices: New vault (selected at start), Existing vault, Temporary vault (shown only for IMP-REMOTE, INT-09). Existing vault is enabled only while at least one vault is open and unlocked; otherwise it is disabled with a hint that no unlocked vault is open, and New vault is selected. Its list holds, for each unlocked vault in tab order: one row "<vault display name> (<root group name>)" for the root, then one row per group outside the recycle bin, shown as "  / A / B" (path without the root). The row of the vault on screen is preselected. The list is rebuilt when a vault locks or changes.

FEA-08.4 **Review.** Opening Review runs the reader. It shows the file path. On a reader error it shows the error banner with the reader's message and no table, and Finish stays disabled. Otherwise it shows "Entry count: N" (all entries of the result, recycle bin included, history items not) and a read-only, sortable table with one row per entry: Group (the entry's own group name), Title, Username, Password, URL. Larsal masks the Password column: a non-empty password shows as a fixed mask, an empty one as empty; the value never reaches the screen layer (lead decision L08-2; the reference shows passwords in clear here). IMP-CSV shows the CSV screen instead (FEA-08.13).

FEA-08.5 **Into a new vault.** After Finish, Larsal runs the new vault assistant (APP-07). If the user cancels it, nothing is created and the import result is wiped. Otherwise Larsal merges the result into the new empty vault (MOD-11, import wizard row: keep-newer, vault custom data skipped), then gives the new root group the result root's name and notes, shows the new vault and marks it modified. Cipher, key derivation and credentials always come from APP-07, never from the imported file.

FEA-08.6 **Into an existing vault.** The result's root group, with its name, notes, child groups and entries, becomes the last child of the chosen group. That vault comes to the front and is marked modified (APP-05 saves it). Larsal also copies into that vault every custom icon used by any moved group or entry (the reference copies only the moved top group's icon, so nested custom icons are lost there).

FEA-08.7 **No duplicate ids.** In FEA-08.6, an imported group or entry whose id already exists in the target vault gets a fresh random id; its history items take the entry's new id (lead decision L08-5; the reference keeps the file's ids, so importing the same OPVault twice gives duplicate ids).

FEA-08.8 **Trashed items.** Items a reader marks as trashed (only IMP-OPVAULT, FEA-08.39) go to the target vault's recycle bin, made per MOD-04.2 when missing; if the target vault's bin is off, they go into a normal group named like the bin, made as the last child of the moved import root (lead decision L08-6; the reference keeps them in the result's own "Recycle Bin" group, which becomes an ordinary group in the target at that same place: matches the reference, Verify, 2026-10-27; that group keeps the bin icon and has search and Auto-Type off, in Larsal too, LD-148).

FEA-08.9 **Common defaults.** Unless a kind's rule says otherwise: every created group and entry gets a fresh random id from `larsal-crypto`; each time an entry or group does not get from the file is the import time; expiry is off; history is empty; the "favorite" tag is `Favorite`; tags added by readers are added one by one and normalized per MOD-07.

FEA-08.10 **One-time passwords from a bare secret.** Where a kind says "TOTP value V": if V is empty, nothing is set. If V does not start with `otpauth://`, Larsal builds `otpauth://totp/` + E(title) + `:` + E(username) + `?secret=` + E(V), where E percent-encodes every byte of the UTF-8 text except `A–Z a–z 0–9 - . _ ~`, and title and username are the entry's values at that moment. The result is parsed per FEA-04; a parse that gives no secret sets nothing. Storing (this rule and every other place below that sets an entry's one-time password): the entry gets the fields FEA-04.16 writes for the form the settings were read in, not the source text. Form U or K: `otp` = the FEA-04.17 or FEA-04.18 text built from the parsed settings and the entry's title and username with placeholders resolved, protected. Form L (a bare secret, FEA-08.26 and FEA-08.41): `TOTP Seed` = the secret text as given, protected, and `TOTP Settings` = the FEA-04.19 text, `30;6` with the defaults. This is what the reference does.

FEA-08.11 **Extra URLs and name clashes.** Extra URLs go into custom fields `KP2A_URL_1`, `KP2A_URL_2` … in input order (INT-03). Where a kind says "suffix on clash": if the field name already exists on the entry (the five standard names always exist), Larsal appends `_` and 5 random lowercase hex digits.

FEA-08.12 **Readers run off the screen thread.** Every reader and every key derivation runs on a worker thread; the assistant shows progress and stays responsive. Cancel stops the reader and wipes everything it made.

### B. CSV

FEA-08.13 **CSV screen.** Controls and defaults (changing any of the first five parses the file again; the header check only renames columns):

| Control | Choices | Default |
|---|---|---|
| Encoding | UTF-8, Windows-1252, UTF-16, UTF-16LE | UTF-8 |
| Text qualifier | `"` `'` `:` `.` `\|` | `"` |
| Field separator | `,` `;` `-` `:` `.` TAB | `,` |
| Comment character | `#` `;` `:` `@` | `#` |
| Backslash escapes | on, off | off |
| `CSV-FIRST-ROW-NAMES` "Use the first row as column names" | on, off | on |
| `CSV-SKIP-ROWS` "Rows to leave out at the top" | number, minimum 1 when the line above is on, else 0; maximum max(minimum, rows − 1) | the minimum, reset on every parse |

An info line shows file size, number of parsed rows and number of columns. A preview table shows the parsed rows mapped to the 11 target fields (Larsal masks the Password column as in FEA-08.4).

FEA-08.14 **Decoding.** The whole file is read (limit FEA-08.67), then decoded with the chosen encoding. A leading byte order mark (`EF BB BF`, `FF FE`, `FE FF`) is removed and its encoding wins over the choice. UTF-16 without a byte order mark is read little-endian, as the reference: it uses the computer's byte order, which is little-endian on every Mac (matches the reference, Verify, 2026-10-27: its bundled decoder reads `61 00 62 00` as `ab` and `00 61 00 62` as U+6100 U+6200). Invalid sequences become U+FFFD. Windows-1252 uses the real Windows-1252 table. Then CR LF and lone CR become LF. Differences from the reference: the reference source and the installed 2.7.11 both turn CR bytes into LF before decoding, which damages UTF-16 text; the reference source's Windows-1252 choice silently keeps the previous decoder, while the installed 2.7.11 decodes Windows-1252 correctly (byte `80` gives `€`), as Larsal (Verify, 2026-10-27: source of both versions read, the installed app's bundled decoder run on these bytes).

FEA-08.15 **Records and plain fields.** A record is a list of fields separated by the separator and ended by LF or the end of input. At the start of a record, if the first character after any spaces and tabs is the comment character, the whole line is skipped. A field whose first character is not the qualifier is plain: it holds every character up to the next separator or LF, exactly as written (no trimming; a qualifier inside it is literal).

FEA-08.16 **Quoted fields.** A field starting with the qualifier is quoted: it holds the characters up to the next qualifier, LF included. Two qualifiers in a row stand for one literal qualifier. After the closing qualifier the next character must be the separator, LF or the end; otherwise Larsal records the error MSG-CSV-MALFORMED with the record number and continues, starting a new record at that character. The reference also records the error but drops that one character and starts the new record after it (source reading of its parser: the end-of-line check consumes the character); Larsal keeps it, so no text is lost (lead decision L08-7g). A quoted field still open at the end of input records MSG-CSV-UNCLOSED.

FEA-08.17 **Backslash mode.** With backslash escapes on, inside a quoted field a backslash makes the next character literal, the qualifier and the backslash included; a backslash as the last character of the input is kept as a backslash. A doubled qualifier is then not an escape: the first one closes the field. A field starting with a backslash is a plain field in Larsal (lead decision L08-7e; the reference reads it as a quoted field).

FEA-08.18 **Empty rows and padding.** A record whose fields are all empty is dropped (a field holding exactly one LF counts as empty). Shorter records are padded with empty fields to the length of the longest record. The column count is that length.

FEA-08.19 **Column names.** With `CSV-FIRST-ROW-NAMES` on, column i is named by row 1's field i, or "Column i" (i counted from 0) when that field is empty. Off: "Column 0", "Column 1" …. Each of the 11 target fields has a chooser listing "Not present" and the column names.

FEA-08.20 **Automatic mapping.** Targets in order: Group, Title, Username, Password, URL, Tags, Notes, TOTP, Icon, Last Modified, Created. Each target takes the first column whose name equals the target's English name or its label in the interface language, ignoring case. A target with no such column gets "Not present" when the column names changed since the last parse, else keeps its previous choice. So the header of FEA-09.3 maps all 10 of its columns by itself.

FEA-08.21 **Rows to entries.** The first N parsed records are left out, N = the `CSV-SKIP-ROWS` value; skipped comment lines and dropped empty rows do not count toward N. Every other record becomes exactly one entry, even when all its mapped values are empty.

FEA-08.22 **No title.** On Finish with Title on "Not present", Larsal asks MSG-CSV-NOTITLE with Continue and Cancel. Cancel returns to the CSV screen and imports nothing.

FEA-08.23 **Parse errors.** Recorded errors show in a banner: the first two messages, then MSG-CSV-MORE for the rest. The reference still lets the user finish with the rows parsed so far. Larsal requires the extra confirmation MSG-CSV-IMPORT-ANYWAY first (lead decision L08-3).

FEA-08.24 **Root group.** The result's root group gets the notes "Imported from CSV file: <full path>". Common root: for every imported record take its Group text up to the first `/` (the whole text when there is none). When every record gives the same text (case-sensitive) and that text is not empty, the root group takes it as its name. Otherwise, and with zero records or Group on "Not present", the root keeps the default name `Passwords` (in the interface language, as the reference).

FEA-08.25 **Group paths.** The Group text is split at `/`, empty parts dropped. When a common root was found and the first part equals it ignoring case, that part is dropped. From the root, each part selects the first child group with exactly that name (case-sensitive), or a new group with that name is made. The entry goes into the last group reached, or into the root when no part is left.

FEA-08.26 **Text fields.** Title, Username, Password, URL and Notes take the mapped text unchanged. Tags: the text is parsed per MOD-07. TOTP: a non-empty text is parsed per FEA-04 (any storage form); when that fails or gives no secret, the whole text is used as a bare secret with FEA-04's defaults, stored in form L (FEA-08.10).

FEA-08.27 **Icon.** A decimal integer text sets the standard icon. Larsal accepts only numbers of the standard icon set (MOD-06, 0 to 68) and leaves the default icon for any other text (lead decision L08-7b; the reference stores any integer, negative ones too).

FEA-08.28 **Times.** Last Modified sets the modified and last-access times; Created sets the creation time. Value forms:
- One or more ASCII digits only: a number v. v ≤ 2,147,483,647 means seconds since 1970-01-01 UTC; larger means milliseconds. A number too large for 64 bits counts as 0 (1970-01-01T00:00:00Z), as in the reference.
- Otherwise an ISO 8601 text: `YYYY-MM-DD`, optionally followed by `T`, `t` or one space and `HH:mm` or `HH:mm:ss` with an optional fraction (`.` or `,` and digits), then optionally `Z`, `z`, `±HH:mm`, `±HHmm` or `±HH`. `24:00` is 00:00 of the next day. No zone means the Mac's local time zone at import; a date alone means local midnight. (Every form above matches the reference's time library, run as bundled in the installed 2.7.11 and in a current release of the same library (Verify, 2026-10-27). Edge forms outside this list: 2.7.11 also accepts a space before the zone, trailing white space and a fraction mark with no digits, the current release accepts an hour without minutes, and both accept a one-digit zone hour such as `+2:00`; Larsal refuses all five, so the import time stays: a Larsal choice, LD-148.)
- Anything else, or an empty value: the import time stays.

### C. The .1pux format

FEA-08.29 **Container.** The file is a ZIP archive. Not a ZIP: MSG-1PUX-NOTZIP. It must hold the member `export.data` (name compared ignoring case): else MSG-1PUX-NODATA. `export.data` is JSON. Only the first item of its `accounts` array is read; other accounts are dropped. Each item of that account's `vaults` that has both `attrs` and `items` becomes a group under the root named `attrs.name`; when `attrs.avatar` is not empty and the member `files/<avatar>` exists, its bytes become a custom icon of that group. A JSON parse error gives MSG-JSON (the reference silently imports nothing).

FEA-08.30 **Items.** For each item of a vault, in order:

| Source (item) | Goes to |
|---|---|
| `overview.title` | Title |
| `overview.url` | URL |
| each `overview.urls[].url` that differs from URL | extra URL (FEA-08.11) |
| `overview.tags` (strings) | tags |
| `favIndex` equal to 1 | tag `Favorite` |
| `state` equal to `archived` | tag `Archived` |
| `details.loginFields[]` with `designation` `username` / `password` (ignoring case) | Username / Password; other login fields are dropped |
| `details.password` | Password, only when Password is still empty |
| `details.notesPlain` | Notes |
| `details.sections[]` | FEA-08.31 |
| `details.documentAttributes` | attachment (FEA-08.32) |
| `createdAt`, `updatedAt` (seconds) | created; modified and last access (UTC). A missing value counts as 0, giving 1970-01-01T00:00:00Z, as in the reference |

No expiry, no history.

FEA-08.31 **Section fields.** Prefix = the section's `title`, or 5 random hex digits when empty. Field name = prefix + `_` + the field's `title`, or its `id` when the title is empty. The field's `value` is an object; its first key in sorted order decides:

| Key | Result |
|---|---|
| `totp` | the first one on the entry: TOTP value (FEA-08.10); later ones: protected custom field `otp_1`, `otp_2` … (first free name) holding the built URI |
| `file` | attachment (FEA-08.32) |
| `date` | the number as seconds UTC, written as `YYYY-MM-DDTHH:mm:ssZ` (lead decision L08-7a; the reference writes a text date form) |
| `email` | `value.email.email_address` |
| `address` | street + LF + city + `, ` + state + ` ` + zip + LF + country |
| `concealed` | the text, as a protected field |
| any other (`string`, `phone`, `url`, `monthYear`, …) | the value as text; numbers as their decimal text (`monthYear` 202206 gives `202206`); objects and arrays give empty |

An empty result sets nothing. A field name that already exists is overwritten (no suffix).

FEA-08.32 **Attachments.** A `file` value or `documentAttributes` names `documentId` and `fileName`. The member `files/<documentId>__<fileName>` (two underscores) becomes an attachment named `fileName`. A missing member is skipped without error.

### D. The OPVault format

FEA-08.33 **Layout.** The chosen folder must exist and hold a readable `default` folder (else MSG-OPV-LAYOUT). In `default`: `profile.js` (required), `folders.js` (optional), `band_0.js` … `band_F.js` (each optional, read in that order), and attachment files. Each JS file is JSON with a wrapper removed: `var profile=` … `;`, `loadFolders(` … `);`, `ld(` … `);`. Larsal first trims trailing white space (lead decision L08-7f; the reference does not). A `profile.js` that is not a JSON object after that gives MSG-OPV-LAYOUT (the reference fails with no message).

FEA-08.34 **opdata01 blobs.** Layout: the 8 bytes `opdata01`; L, the plaintext length, 8 bytes little-endian; IV, 16 bytes; ciphertext; HMAC-SHA256, 32 bytes, over every byte before it. The ciphertext is AES-256-CBC without padding of (P random bytes, then the plaintext), P = 16 − (L mod 16), so P = 16 when L is a multiple of 16. Larsal checks in this order and fails on the first problem: header; total size equals 8 + 8 + 16 + L + P + 32 exactly (before any allocation); HMAC, compared in constant time; then decrypts and drops the first P bytes. (The reference allocates from L before any check.)

FEA-08.35 **Keys.** From `profile.js`: `salt` (base64), `iterations`, `masterKey` and `overviewKey` (base64 opdata01). PBKDF2-HMAC-SHA512 over the password's full UTF-8 bytes, the salt and `iterations` gives 64 bytes: encryption key = first 32, MAC key = last 32 (the reference passes only as many bytes as the password has UTF-16 units, so non-ASCII passwords fail there). Decrypting `masterKey` with these gives bytes K; SHA-512(K) gives the master encryption key (first 32 bytes) and master MAC key (last 32). The same with `overviewKey` gives the overview keys. A failed `masterKey` HMAC gives MSG-WRONG-PASSWORD.

FEA-08.36 **Item keys.** An item's `k` (base64) must be exactly 112 bytes: IV 16, ciphertext 64, HMAC 32. The HMAC-SHA256 over IV and ciphertext with the master MAC key must match; AES-256-CBC without padding with the master encryption key gives the item encryption key (first 32) and item MAC key (last 32).

FEA-08.37 **Items.** Each band object maps keys to items. An item needs `d`, `k` and `hmac`. The reference does not check the `hmac` value; Larsal verifies it and on mismatch skips the item and lists it in the import report (decided: spec/decisions.md LD-45). The check value is HMAC-SHA256 with the overview MAC key over every other member of the item in sorted key order, each key then its value as text (strings as they are, whole numbers in decimal, true `1`, false `0`; LD-146): proven on the reference's OPVault test folder, where all 8 items pass (one holds `trashed` true) and a copy with one flipped `hmac` byte skips that item (Verify, 2026-10-27). An item also needs a `uuid` of 32 or 36 characters; otherwise it is skipped. Entry id = the uuid read as hex. `o` (opdata01, overview keys) is JSON: `title` to Title, `url` to URL, each `URLs[].u` that differs from `url` to an extra URL, `tags` strings to tags. `d` (opdata01, item keys) is JSON: `notesPlain` to Notes; `password` to Password; each `fields[]` with `designation` `password` or `username` (exact) sets Password or Username, later ones winning; `sections[]` per FEA-08.41. `created` and `updated` (seconds UTC), when present, set created and modified; last access stays the import time (matches the reference, Verify, 2026-10-27). Any failure inside one item skips that item; the others go on.

FEA-08.38 **Folders.** Each object in `folders.js` is decrypted (`overview`, overview keys) and becomes a group under the root named by its `title`, id from `uuid`, created and modified from `created` and `updated`; for a smart folder its notes hold the hex of the base64-decoded `predicate_b64`, or a note that the predicate is missing. Items are never placed into folders. A folder that fails to decrypt stops the whole import with MSG-OPV-DAMAGED (the reference stops with no message).

FEA-08.39 **Categories and trash.** Before items are read, 18 category groups are made under the root, in code order:

| Code | Group | Code | Group | Code | Group |
|---|---|---|---|---|---|
| 001 | Login | 099 | Tombstone | 105 | Membership |
| 002 | Credit Card | 100 | Software License | 106 | Passport |
| 003 | Secure Note | 101 | Bank Account | 107 | Rewards |
| 004 | Identity | 102 | Database | 108 | SSN |
| 005 | Password | 103 | Driver License | 109 | Router |
| | | 104 | Outdoor License | 110 / 111 | Server / Email |

An item with `trashed` true is trashed (FEA-08.8). Else its `category` string selects the group with that code; an unknown, missing or non-string category puts it in the root. After all items, every child group of the root that is empty (categories and folders alike) is deleted.

FEA-08.40 **Root group.** Name = the chosen folder's name with every `.opvault` removed; id = profile `uuid` as hex; created and modified = profile `createdAt` and `updatedAt` (seconds UTC).

FEA-08.41 **Section fields.** A field needs `v`. Its name: when `n` starts with `TOTP_`, it is a TOTP field. Else, when the section's `title` is empty or `n` starts with `address`: `password` (in `n` or `t`, ignoring case) gives `Password`, `username` gives `UserName`, `url` in `n` or `t`, `hostname` in `n`, `server` in `t` or `website` in `n` give `URL`, otherwise the name is `t`. In all other cases the name is section title + `_` + `t`. Then:

| Case | Result |
|---|---|
| TOTP field, entry has no TOTP yet, `v` starts with `otpauth://` | add `digits=6` and `period=30` when missing, then parse per FEA-04 |
| TOTP field, entry has no TOTP, other `v` | bare secret with FEA-04 defaults |
| TOTP field, entry has a TOTP | protected custom field `otp_1`, `otp_2` … holding `v` |
| name starts with `expir` (ignoring case) | expiry on, expiry time = the date of `v` (below); an invalid date sets nothing |
| `k` is `date` or `monthYear` | custom field holding the date as `YYYY-MM-DD` (lead decision L08-7a; the reference uses the Mac's short locale form) |
| `k` is `address` | one custom field per key of the `v` object, named name + `_` + key, in sorted key order |
| anything else | custom field with `v` as text (non-text `v` gives empty), suffix on clash (FEA-08.11), protected when `k` is `password` or `concealed` |

Dates: `monthYear` reads the number as `YYYYMM` and means the 1st of that month, 00:00 UTC; otherwise `v` is seconds UTC (a number, or a text holding one). Because the standard names always exist, a section field resolved to `Password`, `UserName` or `URL` ends up as a suffixed custom field, as in the reference.

FEA-08.42 **Attachments.** For each entry, the files `<UUID>_*.attachment` in `default` (UUID = the entry id as 32 uppercase hex digits) are read. Layout: `OPCLDAT` (7 bytes); version 1 byte, 1 or 2; metadata length 2 bytes little-endian; 2 unused bytes; icon length 4 bytes little-endian; metadata JSON; icon (opdata01, item keys; must pass its HMAC, then ignored); the rest is the content (opdata01, item keys). Metadata with `trashed` true, or any failure, skips that attachment. The metadata `overview` (opdata01, overview keys) is JSON; its `filename` names the attachment, else the file name up to its first `.`. A name already on the entry gets 5 random hex digits and `_` in front.

### E. Bitwarden JSON

FEA-08.43 **Layout.** The file is one JSON object. Parse error: MSG-JSON. Groups come from `folders`, or from `collections` when `folders` is missing (organization exports). Without that array or without `items`, the result is empty, with no message, as in the reference.

FEA-08.44 **Folders.** Each folder's `name` is split at `/` (empty parts dropped) into nested groups under the root; an existing group path (case-sensitive) is reused, so folders with the same path share one group. The folder `id` maps to the deepest group. Larsal always maps to that deepest group (lead decision L08-7c; in the reference a name with a leading, trailing or doubled `/` maps to nothing and its items land in the root).

FEA-08.45 **Items.** Item group: `folderId`, or when empty the first of `collectionIds`; an unknown or empty id means the root. Items keep file order.

| Source | Goes to |
|---|---|
| `name`, `notes` | Title, Notes |
| `favorite` true | tag `Favorite` |
| `login.username`, `login.password` | Username, Password |
| `login.totp` | TOTP value (FEA-08.10) |
| `login.uris[].uri` | the first non-empty one to URL; each later one to an extra URL (FEA-08.11) |
| `login.fido2Credentials[]` | passkey fields (FEA-08.47) and tag `Passkey` |
| `identity` | FEA-08.46 |
| `card` | `card_cardholderName`, `card_brand`, `card_number`, `card_expMonth`, `card_expYear`, `card_code` (only `card_code` protected); empty values skipped |
| `fields[]` | custom field `name` = `value`, protected when `type` is 1; suffix on clash; boolean fields keep `true`/`false`, linked fields give empty |
| `creationDate` | created (ISO 8601, FEA-08.28 forms) |
| `revisionDate` | modified and last access |
| `passwordHistory[]` | history (FEA-08.48) |

Dropped: `type`, `reprompt`, `sshKey`, `secureNote` details, `organizationId`, `deletedDate`. Bitwarden exports hold no attachments and no expiry.

FEA-08.46 **Identity.** `identity_name` = the non-empty values of `title`, `firstName`, `middleName`, `lastName` joined by one space (always set, maybe empty). `identity_address` = the non-empty values of `address1` to `address3` joined by LF, then LF, `city`, `, `, `state`, ` `, `postalCode`, LF, `country` (always set). `identity_company`, `identity_email`, `identity_phone`, `identity_ssn`, `identity_passportNumber`, `identity_licenseNumber` when not empty; the last three are protected. `identity.username` goes to Username when Username is empty, else to `identity_username`.

FEA-08.47 **Passkeys.** For each credential (a later one overwrites an earlier one): `credentialId` with every non-hex character dropped, hex-decoded, then base64url without padding into `KPEX_PASSKEY_CREDENTIAL_ID` (protected); `keyValue` base64url-decoded, standard base64 between `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` (no line breaks) into `KPEX_PASSKEY_PRIVATE_KEY_PEM` (protected); `userName` into `KPEX_PASSKEY_USERNAME`; `rpId` into `KPEX_PASSKEY_RELYING_PARTY`; `userHandle` into `KPEX_PASSKEY_USER_HANDLE` (protected). INT-04 owns their meaning.

FEA-08.48 **Password history.** Each `passwordHistory` item with a non-empty `password` and a valid `lastUsedDate` becomes one history item, in file order: same id, Title, Username, URL and Notes as the entry, Password = the old password, created = the entry's created time, modified and last access = `lastUsedDate`. Custom fields are not copied into history items.

FEA-08.49 **Encrypted files: key.** A file with `encrypted` true is password-protected. Without `kdfType` or `salt`: MSG-BW-ACCOUNT (exports protected by the account key are not supported). The key K (32 bytes):
- `kdfType` 0: PBKDF2-HMAC-SHA256 over the password's UTF-8 bytes, salt = the UTF-8 bytes of the `salt` text exactly as written (not base64-decoded), `kdfIterations` rounds. Iterations ≤ 0: MSG-BW-KDF.
- `kdfType` 1: Argon2id, version 0x13, salt = SHA-256 of the `salt` text's UTF-8 bytes, iterations `kdfIterations`, memory `kdfMemory` MiB, lanes `kdfParallelism`, 32-byte output. Limits: FEA-08.68.
- Any other type: MSG-BW-KDF.

FEA-08.50 **Encrypted files: check and decrypt.** HKDF-Expand with SHA-256 (no extract step), key K, info `enc`, 32 bytes gives the encryption key; info `mac` gives the MAC key. `encKeyValidation_DO_NOT_EDIT` and `data` have the form `<type>.<iv b64>|<ciphertext b64>|<mac b64>`. For the validation value Larsal computes HMAC-SHA256(MAC key, IV ‖ ciphertext) and compares it in constant time with the MAC; a mismatch gives MSG-WRONG-PASSWORD. Larsal then checks the `data` MAC the same way (mismatch: MSG-BW-DAMAGED), decrypts `data` with AES-256-CBC and PKCS#7 padding, and reads the plaintext as the JSON of FEA-08.43. Larsal requires type `2` and three parts in both values (lead decision L08-8; the reference ignores the type and never checks the `data` MAC). Missing parts: MSG-BW-DAMAGED.

### F. Proton Pass JSON

FEA-08.51 **Layout.** One JSON object (MSG-JSON on a parse error). `encrypted` true gives MSG-PROTON-ENCRYPTED. Each key of the `vaults` object, in sorted key order, gives a group under the root: name = `name`, notes = `description`; its `items` become entries in file order.

FEA-08.52 **Items.** Common: `data.metadata.name` to Title, `data.metadata.note` to Notes, `pinned` true to tag `Favorite`. By `data.type` (ignoring case):

| Type | Mapping of `data.content` |
|---|---|
| `login` | `itemUsername` to Username; `password` to Password; `totpUri` TOTP value (FEA-08.10); `itemEmail` to Username when Username is empty, else custom field `login_email` (when not empty); `urls[]`: first non-empty to URL, later ones extra URLs |
| `creditCard` | `number` to Username; `verificationNumber` to Password; `cardholderName`, `pin`, `expirationDate` to `card_cardholderName`, `card_pin` (protected), `card_expirationDate`, each when not empty |
| `wifi` | `ssid` to Username; `password` to Password; `security` to `wifi_security` (always set) |
| `sshKey` | `publicKey` to `ssh_public_key`; `privateKey` to `ssh_private_key` (protected); both always set |
| `note`, `custom` | nothing more |
| any other | Notes become MSG-PROTON-UNKNOWN-TYPE + two LF + the old notes; each non-empty content value becomes custom field `content_<key>`, sorted by key |

The source keys above match the reference (Verify, 2026-10-27). Then each `data.extraFields[]`: name `fieldName` (suffix on clash), value `data.totpUri` when `type` is `totp` (stored as text, not as the entry's TOTP), else `data.content`; protected when `type` is `hidden` (both types match ignoring case, as in the reference; LD-148). `state` 2 (trashed): expiry on, expiry time = import time. `createTime` and `modifyTime` (seconds UTC): created; modified and last access (missing counts as 0). Passkeys and alias data are dropped.

### G. The version 1 format

FEA-08.53 **Header (124 bytes, little-endian).**

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 4 | signature 1 | `03 D9 A2 9A`, else MSG-V1-NOTVAULT |
| 4 | 4 | signature 2 | `65 FB 4B B5`, else MSG-V1-NOTVAULT |
| 8 | 4 | flags | value 8 set: Twofish; else value 2 set: AES; neither: MSG-V1-CIPHER. Values 1 (SHA-2) and 4 (ARC4) are not ciphers Larsal reads |
| 12 | 4 | version | value AND 0xFFFFFF00 must be 0x00030000, else MSG-V1-VERSION |
| 16 | 16 | master seed | |
| 32 | 16 | IV | |
| 48 | 4 | group count | |
| 52 | 4 | entry count | |
| 56 | 32 | content hash | SHA-256 of the whole plaintext |
| 88 | 32 | transform seed | |
| 120 | 4 | rounds | cost check FEA-08.68 |

A shorter file gives MSG-V1-DAMAGED. Larsal's open dialog detects this signature (FMT-01.4) and offers this import.

FEA-08.54 **Key.** Password bytes are tried in this order: Windows-1252, ISO-8859-1, UTF-8; a try whose bytes equal an earlier try is skipped, and so is a try whose encoding cannot hold every character (the reference turns such characters into `?`; its Mac build also lacks Windows-1252 and tries UTF-8 first: source reading, its own Windows-1252 test runs only on Windows). Key file data: an empty file is MSG-V1-KEYFILE; a 32-byte file is used as is; a 64-byte file of hex digits is hex-decoded; any other file gives SHA-256 of its bytes. Raw key: password only (an empty password included) SHA-256(password bytes); key file only: the key file data; both: SHA-256(SHA-256(password bytes) ‖ key file data). Transformed key = the version 3 AES-KDF of CRY-02 with the header's transform seed and rounds. Final key = SHA-256(master seed ‖ transformed key). The content (offset 124 to the end) is decrypted with AES-256-CBC or Twofish-256-CBC (CRY-01), the header IV and PKCS#7 padding. A padding error or a content hash mismatch moves to the next password try; when all fail: MSG-WRONG-CREDENTIALS. The content hash is compared in constant time.

FEA-08.55 **Records.** The plaintext holds group count group records, then entry count entry records. A record is a list of fields: type (2 bytes), size (4 bytes), data; type 0xFFFF ends the record. Larsal checks every size against the bytes left before reading (MSG-V1-DAMAGED). Text fields are UTF-8 ended by the first NUL byte (or by the end of the data). An unknown field type, a fixed-size field of the wrong size, or a group without both id and level gives MSG-V1-DAMAGED.

| Group field | Size | Use | Entry field | Size | Use |
|---|---|---|---|---|---|
| 0 | any | ignored | 0 | any | ignored |
| 1 | 4 | group id | 1 | 16 | entry id in the file (used only by FEA-08.58) |
| 2 | text | name | 2 | 4 | group id |
| 3 / 4 / 5 | 5 | created / modified / accessed | 3 | 4 | icon |
| 6 | 5 | expiry (sets expiry on) | 4 / 5 / 6 / 7 / 8 | text | Title / URL / Username / Password / Notes (FEA-08.59) |
| 7 | 4 | icon | 9 / 10 / 11 | 5 | created / modified / accessed |
| 8 | 2 | level | 12 | 5 | expiry (sets expiry on) |
| 9 | any | flags, ignored | 13 | text | attachment name |
| | | | 14 | any | attachment content; size 0 means no attachment |

Icons outside the standard set (MOD-06) become 0 (lead decision L08-7b).

FEA-08.56 **Packed times.** 5 bytes b0 to b4, UTC: year = b0 × 64 + (b1 >> 2); month = (b1 & 3) × 4 + (b2 >> 6); day = (b2 >> 1) & 31; hour = (b2 & 1) × 16 + (b3 >> 4); minute = (b3 & 15) × 4 + (b4 >> 6); second = b4 & 63. The value 2999-12-28 23:59:59 (`2E DF 39 7E FB`) means "never" and sets nothing; an impossible date sets nothing.

FEA-08.57 **Tree.** Groups in file order: level 0 goes under the root. Level n > 0 goes under the nearest earlier group with a lower level, which must have level n − 1; otherwise, or when there is no such group, MSG-V1-DAMAGED. Entries go to the group with their group id; an unknown id puts the entry in the root.

FEA-08.58 **Meta records.** An entry with an attachment named `bin-stream`, non-empty Notes, Title `Meta-Info`, Username `SYSTEM`, URL `$` and icon 0 is not imported. When its Notes are the marker `4B 50 58 5F 47 52 4F 55 50 5F 54 52 45 45 5F 53 54 41 54 45` (given as hex: the marker abbreviates a product name), the attachment is a 4-byte count n and then n records (group id 4 bytes, expanded flag 1 byte); the size must be exactly 4 + 5n, else the record is ignored; each known group gets its expanded state. With the marker `4B 50 58 5F 43 55 53 54 4F 4D 5F 49 43 4F 4E 53 5F 34` the attachment is: icon count, entry count, group count (4 bytes each); per icon a 4-byte size and PNG bytes (each becomes a custom icon); per entry a 16-byte file entry id and a 4-byte icon index; per group a 4-byte group id and icon index. Known items with a valid index get that custom icon. Any size that runs past the end stops reading that record. Other markers are ignored.

FEA-08.59 **Auto-Type lines in notes.** Notes are split at LF; CR is removed from each line, so every CR in the notes is lost, not only those on Auto-Type lines (matches the reference, Verify, 2026-10-27). A line `Auto-Type: S` (colon, one space, then S of at least one character, kept as it is with any further spaces; a line without that stays in Notes; matches the reference, LD-148) sets the default sequence S; `Auto-Type-<n>: S` stores sequence n (n is digits; a number above 2,147,483,647 counts as 0, as in the reference, LD-149); `Auto-Type-Window: W` and `Auto-Type-Window-<n>: W` add a window association with sequence n, or with an empty sequence when n is missing or unknown. Names match ignoring case. Recognized lines are removed from Notes, and so is an empty line right after one. Associations are added in ascending n (no number first), windows of one n in file order (INT-05). Larsal recognizes these lines only at the start of a line (lead decision L08-7d; the reference also takes them from the middle of a line).

FEA-08.60 **Result.** Root group name `Root`. Every group and entry gets a fresh random id (file ids are not kept). A top-level group named exactly `Backup` gets search and Auto-Type off (MOD-02). The file's key, cipher and rounds are not kept (FEA-08.5). Dropped: group flags, file entry ids, unknown meta records.

### H. The XML document (command line)

FEA-08.61 **Command line import.** `larsal import` (INT-10) reads a plain XML document of our format (FEA-09.12) and saves it as a new vault file with the given credentials and the version FMT-16 picks. It is not offered in the import assistant (as in the reference). It refuses an existing target path (MSG-XML-EXISTS) and a call with no credential (MSG-XML-NOKEY).

FEA-08.62 **Reading the document.** The FMT-10 to FMT-15 reading rules apply with no protected-value stream: ids, times, history, metadata, custom data, custom icons, deleted objects are kept. `ProtectInMemory="True"` sets the protected flag (FMT-09.18). A `Meta/Binaries` pool is read in every version and resolves `Ref` numbers (FMT-13). A value with `Protected="True"` stops the import with MSG-XML-PROTECTED (the reference command line tool crashes on it: observed, exit status 139). A DTD is refused (Extra hardening; the reference expands internal entities). A document without the root element of FMT-10.5 or without a root group gives MSG-XML-NOROOT.

### I. Another vault of our format

FEA-08.63 **No separate importer.** Taking content from another vault of our format is Merge (action ACT-MERGE, MOD-11), remote sync (INT-09), or the command line merge (INT-10). The import assistant has no extra kind for it, as in the reference.

### J. Limits and hostile files

FEA-08.64 **Errors leave nothing behind.** A reader that fails returns no result: no group or entry is added anywhere and every buffer it filled is wiped. A skipped item (FEA-08.37, FEA-08.42) is not an error.

FEA-08.65 **Never a crash.** Every reader treats its input as hostile (AT-A08 style): wrong JSON types read as empty or missing values, never as a crash; numbers that do not fit read as missing.

FEA-08.66 **Secrets.** Passwords, protected fields, attachment contents, passkey keys and TOTP secrets from any reader go into secret types at once (SR-07). The raw file bytes, decrypted JSON and derived keys are wiped when the reader ends. Nothing from an import file goes to logs or error texts; messages name at most a record number or a JSON offset.

FEA-08.67 **Size limits** (proposed numbers, in `limits.rs`; lead decision L08-4):

| Limit | Value |
|---|---|
| CSV, JSON, XML, `profile.js`, `folders.js`, one band file | 256 MiB each |
| One .1pux file | 2 GiB, the model limit (LD-146) |
| Attachments and custom icons together (icons at their base64 size) | 1 GiB, the FMT-08.12 total; each read or inflate is limited to what is left (LD-147) |
| One ZIP member after inflating (`export.data`, a `files/` member) | 1 GiB; `export.data` 256 MiB; inflate stops at the limit |
| One OPVault attachment file | 1 GiB |
| JSON nesting depth | 512 |
| JSON values in one file | 16,777,216 (LD-143) |
| CSV columns per record; CSV records | 10,000; 1,000,000 |
| One CSV field, one JSON text | 64 MiB (the FMT-08.12 text limit) |
| The import result | the FMT-08.12 limits (groups, entries, attachments, total), so the result can always be saved |

Passing a limit gives MSG-TOO-LARGE naming the limit.

FEA-08.68 **Key derivation cost** (lead decision L08-4). PBKDF2 (Bitwarden type 0, OPVault): iterations 1 to 10,000,000, else MSG-KDF-COST. Argon2id (Bitwarden type 1): iterations 1 to 100, memory 1 to 1,024 MiB, lanes 1 to 16, else MSG-KDF-COST (the reference passes these values on unchecked, silently replaces out-of-range ones with its own defaults and then reports a wrong password). Version 1 rounds: the AES-KDF estimate and ask rule of CRY-02.14 (ask above 10 s, with the cost shown). Every derivation runs before any other decryption and on a worker thread (FEA-08.12).

## Edge cases and errors

Messages (Larsal's own IDs; texts paraphrase the reference where it has one):

| ID | When | Text (paraphrase) |
|---|---|---|
| MSG-IMP-NOFILE | file or folder missing | Larsal can't find that file or folder. |
| MSG-IMP-OPEN | cannot open | The file is there, but Larsal can't read it: <system reason>. |
| MSG-IMP-TARGET-GONE | target vault locked or closed | The chosen vault is no longer open. |
| MSG-JSON | JSON parse error | This file isn't valid JSON. The problem starts at byte <byte offset>: <reason>. |
| MSG-WRONG-PASSWORD | Bitwarden or OPVault check fails | Wrong password. |
| MSG-WRONG-CREDENTIALS | version 1, every try fails | The password or key file is wrong, or the file is damaged. |
| MSG-CSV-MALFORMED / MSG-CSV-UNCLOSED | FEA-08.16 | Malformed field, possible unescaped qualifier / Missing closing qualifier; record <n>. |
| MSG-CSV-NOTITLE | FEA-08.22 | No column is set as Title, so every imported entry will be untitled. |
| MSG-CSV-MORE | FEA-08.23 | and <n> more problems (singular "problem" for 1) |
| MSG-CSV-IMPORT-ANYWAY | FEA-08.23 | The file had parse errors. Import the rows read so far? |
| MSG-1PUX-NOTZIP / MSG-1PUX-NODATA | FEA-08.29 | Not a valid .1pux file: not a ZIP archive / export data missing. |
| MSG-OPV-LAYOUT / MSG-OPV-DAMAGED | FEA-08.33, FEA-08.38 | Not a valid OPVault folder / The OPVault data is damaged. |
| MSG-BW-ACCOUNT | FEA-08.49 | Unsupported format; export with a file password. |
| MSG-BW-KDF / MSG-BW-DAMAGED | FEA-08.49, FEA-08.50 | Unsupported key derivation / The encrypted export is damaged. |
| MSG-PROTON-ENCRYPTED | FEA-08.51 | This export is encrypted. Export it again without encryption, then import that file. |
| MSG-PROTON-UNKNOWN-TYPE | FEA-08.52, written into the entry's notes | Unrecognized item type: <type>. Its content is kept in the content_ custom fields. |
| MSG-V1-NOTVAULT / -CIPHER / -VERSION / -KEYFILE / -DAMAGED | FEA-08.53 to FEA-08.57 | Not a version 1 file / Unsupported cipher / Unsupported version / Cannot read the key file / The file is damaged. |
| MSG-XML-EXISTS / -NOKEY / -PROTECTED / -NOROOT | FEA-08.61, FEA-08.62 | File already exists / No key set, nothing created / Encrypted values are not allowed in a plain XML document / No root group. |
| MSG-TOO-LARGE / MSG-KDF-COST | FEA-08.67, FEA-08.68 | Too large: <limit name> / Key derivation settings out of range. |

Other cases:
- CSV with zero data rows: Finish makes a result with an empty root group (named by FEA-08.24).
- CSV, Group path `A//B/`: groups A, then B (empty parts dropped).
- Two CSV group names that differ only in case (`Work`, `work`): two groups (exact-name lookup); but a common root is skipped ignoring case.
- A group name containing `/` cannot be expressed in CSV; FEA-09 export writes it unescaped, so a round trip splits it.
- .1pux item with two `totp` fields: first is the entry TOTP, second is `otp_1` (FEA-08.31).
- Bitwarden `login.totp` null or empty: no TOTP.
- Bitwarden two custom fields both named `PIN`: `PIN` and `PIN_xxxxx`.
- OPVault with a folder in `folders.js` but no items in it: the folder group is made and then deleted as empty.
- Version 1 attachment content before its name field: the attachment gets an empty name (as in the reference).
- Existing-vault target locked or closed between Select and Finish: Finish shows MSG-IMP-TARGET-GONE and returns to Select (the reference silently drops the import).

Not on Mac: on Windows and Linux the OPVault chooser is a folder picker; everything else is the same.

## Security notes

- Hostile import files must never crash, hang or exhaust memory (plan/security.md "Hostile file"; AT-A08 style; fuzz targets: `csv_import` from E4-S13, plus Larsal should add JSON, ZIP, OPVault and version 1 targets). Known reference weaknesses Larsal must not copy: the XML import crash on `Protected="True"` (FEA-08.62); opdata01 allocates from an unchecked length (FEA-08.34); version 1 field sizes up to 2 GiB are read before any check (FEA-08.55); ZIP members inflate without a limit (FEA-08.67); PBKDF2 and Argon2 settings come from the file unchecked (FEA-08.68, AT-A05).
- MAC and hash compares are constant time (FEA-08.34, FEA-08.36, FEA-08.50, FEA-08.54); MACs are checked before decrypting. The reference uses plain compares and never checks the Bitwarden `data` MAC.
- The preview never shows passwords (FEA-08.4, SC-04). Secrets live only in Rust secret types and are wiped (FEA-08.66, SR-07; AT-C01, AT-C06).
- Attachment names come from the file and may contain `/` or `..`; they are only names inside the vault. MOD-05 owns writing attachments to disk safely.
- Import never contacts the network (IMP-REMOTE is INT-09's and runs only the user's own command).
- The decryption half is parity row SF-17 (Larsal goes further: constant-time compares, bounded costs). Still proposed (not in plan/security.md yet): a row "Imports CSV, .1pux, OPVault, Bitwarden (also password-protected), Proton Pass and the version 1 format"; and an attack "AT-A13 Hostile import files" covering the cases in the first bullet.
- Crates: PBKDF2, HKDF and a ZIP reader are not in the approved crate list (plan/architecture.md). Rule 3 forbids writing them ourselves. Lead decision L08-1.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| 08-01 kinds (FEA-08.1, FEA-08.2) | Assistant open | Read the kind list; pick IMP-V1, then IMP-CSV | Order IMP-CSV, IMP-1PUX, IMP-OPVAULT, IMP-BITWARDEN, IMP-PROTON, IMP-REMOTE, IMP-V1 (IMP-REMOTE only once remote sync is built, INT-09.30); IMP-V1 shows password and key file; switching back clears both and hides them |
| 08-02 targets (FEA-08.3) | Vault "Demo" unlocked, root "Root", groups Work, Work/Sub, bin "Recycle Bin" with group Old; a second vault locked | Open Select | Existing list: "Demo (Root)", "  / Work", "  / Work / Sub"; no bin rows; the locked vault absent. With every vault locked: Existing disabled, New selected |
| 08-03 preview mask (FEA-08.4) | Bitwarden demo file: one login, password `demo-pw` | Review | "Entry count: 1"; Password cell shows the mask; the screen layer never receives `demo-pw` (command view check) |
| 08-04 new vault (FEA-08.5) | CSV result root "Personal", notes "Imported from CSV file: /tmp/a.csv" | Finish, complete APP-07 | New vault root named "Personal" with those notes; vault marked modified; KDF and cipher are APP-07's. Cancel in APP-07 instead: no vault, nothing kept |
| 08-05 existing vault, icons (FEA-08.6) | Version 1 demo file whose entry "E" in group "G" uses a custom icon; target vault group Work | Import into Work | Work/Root/G/E exists; E's custom icon is present in the target vault's icon list |
| 08-06 id clash (FEA-08.7) | Target holds an entry with id `00…01`; an OPVault demo item with uuid `000…001` | Import into the root | The imported entry has a new id ≠ `00…01`; its history items share the new id |
| 08-07 trashed (FEA-08.8) | OPVault demo with one item `trashed` true; target vault bin on, no bin yet | Import into existing vault | A bin is made per MOD-04.2; the item is in it |
| 08-08 defaults (FEA-08.9) | CSV row `Title` only, import at 2026-10-25T10:00:00Z | Import | Created, modified, accessed, location-changed = 2026-10-25T10:00:00Z; expiry off; no history |
| 08-09 bare TOTP (FEA-08.10) | Bitwarden item name `My Site`, username `a b`, `login.totp` `JBSWY3DP` | Import | Built URI starts `otpauth://totp/My%20Site:a%20b?secret=JBSWY3DP`; entry TOTP secret JBSWY3DP, 6 digits, 30 s (FEA-04); stored `otp` (protected) = `otpauth://totp/My%20Site:a%20b?secret=JBSWY3DP&period=30&digits=6&issuer=My%20Site` |
| 08-10 URLs and clashes (FEA-08.11) | Bitwarden uris `https://a/`, `https://b/`, `https://c/`; fields `Password`=`x`, `PIN`=`1`, `PIN`=`2` | Import | URL `https://a/`; `KP2A_URL_1` `https://b/`, `KP2A_URL_2` `https://c/`; custom fields `Password_` + 5 hex = `x`, `PIN` = `1`, `PIN_` + 5 hex = `2`; standard Password unchanged |
| 08-11 worker (FEA-08.12) | Bitwarden demo, PBKDF2 2,000,000 rounds | Import; click Cancel during derivation | Screen stays responsive; after Cancel nothing is imported |
| 08-12 CSV defaults (FEA-08.13) | Any CSV | Open the CSV screen | Encoding UTF-8, qualifier `"`, separator `,`, comment `#`, backslash off, `CSV-FIRST-ROW-NAMES` on, `CSV-SKIP-ROWS` 1 |
| 08-13 decoding (FEA-08.14) | Files: UTF-8 with BOM `EF BB BF` + `a,b`; UTF-16LE with BOM holding `č,d` + CR LF + `e,f` (Encoding left on UTF-8); Windows-1252 byte `80`; the bytes `61 00 2C 00 62 00` with Encoding UTF-16 (no BOM) | Parse | Rows `a`/`b`; rows `č`/`d` and `e`/`f` (BOM wins, no damage); with Windows-1252 chosen, byte 80 reads `€`; the last file reads `a`/`b` (little-endian, Verify 2026-10-27) |
| 08-14 plain and comments (FEA-08.15) | `  #one`, ` \t # two`, `useful,text #1!`, `A,,B"` | Parse | 2 rows: [`useful`, `text #1!`, ``], [`A`, ``, `B"`] (first row padded) |
| 08-15 quoted (FEA-08.16) | `ro,w,"end, of """"""row"""""` LF `2`; second file with qualifier `:` holding `:1` CR LF `2a::b:,:3` CR `4:` | Parse | Field 3 = `end, of """row""`; second: [`1`LF`2a:b`, `3`LF`4`] |
| 08-16 malformed (FEA-08.16, FEA-08.23) | Qualifier `:`, text `A,B,C` LF `:BM::,1,:2:` | Parse; Finish | Error MSG-CSV-MALFORMED for record 2; Finish asks MSG-CSV-IMPORT-ANYWAY first |
| 08-17 unclosed (FEA-08.16) | Qualifier `:`, `A,B` LF `:BM,1` | Parse | MSG-CSV-UNCLOSED |
| 08-18 backslash (FEA-08.17) | Backslash on, qualifier `X`: `Xone\"\\t\\\"w` LF `oX` | Parse | Field = `one"\t\"w` LF `o` |
| 08-19 empty and padding (FEA-08.18) | `1,2` LF `,,,,,,,,,a` LF `a,b,c,d` LF `""` LF `"` LF `"` | Parse | 3 rows, 10 columns; the `""` row and the row holding only LF are dropped; row 1 padded with 8 empty fields |
| 08-20 names (FEA-08.19, FEA-08.20) | Header `title,USERNAME,,Pass` | Parse | Columns `title`, `USERNAME`, `Column 2`, `Pass`; Title→`title`, Username→`USERNAME`, Password "Not present" |
| 08-21 skip (FEA-08.21) | `# c` LF `Title` LF LF `T1` LF `T2`; skipped set to 2 | Import | One entry `T2` (records: `Title`, `T1`, `T2`) |
| 08-22 no title (FEA-08.22) | Title mapped to "Not present" | Finish; Cancel | Question MSG-CSV-NOTITLE; nothing imported |
| 08-23 common root (FEA-08.24, FEA-08.25) | Group column: `Passwords/Work`, `passwords/Home`, `Passwords` | Import | First parts differ in case, so no common root: root named `Passwords`; child groups `Passwords` (holding Work and the third entry) and `passwords` (holding Home) |
| 08-24 root skip (FEA-08.24, FEA-08.25) | Group: `Personal/Work`, `Personal/Work/Sub`, `Personal` | Import | Root named `Personal`; groups Work and Work/Sub; third entry in the root |
| 08-25 text fields (FEA-08.26, FEA-08.10) | Row: Title ` T `, Tags `b, a;a`, TOTP `JBSWY3DPEHPK3PXP` | Import | Title ` T ` (spaces kept); tags per MOD-07 (`a`, `b`); TOTP secret JBSWY3DPEHPK3PXP with defaults, stored as `TOTP Seed` (protected) = `JBSWY3DPEHPK3PXP` and `TOTP Settings` = `30;6`, no `otp` |
| 08-26 icon (FEA-08.27) | Icon texts `5`, `69`, `-1`, `x` | Import | Icons 5, 0, 0, 0 |
| 08-27 times (FEA-08.28) | Last Modified: `1700000000`, `1700000000000`, `2147483648`, `2024-03-10T12:00:00+02:00`, `20240101`, `soon`; Created `2024-01-15 08:00` with the test zone Europe/Berlin | Import | Modified: 2023-11-14T22:13:20Z; 2023-11-14T22:13:20Z; 1970-01-25T20:31:23.648Z; 2024-03-10T10:00:00Z; 1970-08-23T06:15:01Z; import time. Accessed equals modified. Created 2024-01-15T07:00:00Z |
| 08-28 1pux container (FEA-08.29) | A text file renamed `x.1pux`; a ZIP without `export.data`; a ZIP whose `EXPORT.DATA` is `{bad` | Import each | MSG-1PUX-NOTZIP; MSG-1PUX-NODATA; MSG-JSON |
| 08-29 1pux items (FEA-08.29, FEA-08.30, FEA-08.31, FEA-08.32) | Reference .1pux test file (REF_TESTDATA) | Import | Group "Personal": entry "Login": Username `team@` + reference domain, Password `password`, Notes `Note to self`, `KP2A_URL_1` set, TOTP set, `otp_1` set, tags include `Favorite`; entry with one attachment named like its file; "Credit Card": field `Credit Card Fields_verification number` = `123`, protected; "Login Archived" has tag `Archived`; group "Shared" has a custom icon; "UUID 005 Password" Password `uuid005password` |
| 08-30 1pux times (FEA-08.30) | Item without `createdAt` | Import | Created 1970-01-01T00:00:00Z |
| 08-31 opv layout (FEA-08.33) | Folder `demo.opvault` without `default`; `profile.js` ending `;` + LF | Import | MSG-OPV-LAYOUT; the second reads fine |
| 08-32 opdata01 (FEA-08.34) | Blob with L = 5, 80 bytes total; same blob with L = 2^40; same blob with one ciphertext bit flipped | Decode | Plaintext 5 bytes; MSG-OPV-DAMAGED before any large allocation; MSG-OPV-DAMAGED (HMAC) without decrypting |
| 08-33 opv keys (FEA-08.35) | Reference OPVault test folder, password `a`; then password `b` | Import | Opens: PBKDF2-SHA512 (100,000 rounds) MAC key validates `masterKey` (336 bytes, L = 256, P = 16); `b`: MSG-WRONG-PASSWORD |
| 08-34 opv items (FEA-08.36, FEA-08.37, FEA-08.39, FEA-08.41, FEA-08.42) | Reference OPVault test folder, password `a` | Import | Group Login holds an entry with Password `opvault`, `KP2A_URL_1` set, TOTP set and one attachment with content `attachment`; "Expired Login" expired; "My Credit Card": `cardholder name` set, `Additional Details_PIN` = `1234` protected; "Complex Password": TOTP 8 digits, 45 s; "Trashed Password" in the recycle bin; every other root child is a non-empty category group |
| 08-35 opv folders (FEA-08.38) | Demo OPVault with folder "F" and items only in category 001 | Import | No group "F" in the result; group Login holds the items |
| 08-36 opv k size (FEA-08.36, FEA-08.37) | Demo item with `k` of 111 bytes; another with uuid of 31 chars | Import | Both skipped; other items imported |
| 08-37 opv root (FEA-08.40) | Folder `x.opvault.opvault`, profile uuid `E4F7…A4EE`, createdAt 1587218949 | Import | Root name `x`; root id E4F7…A4EE; created 2020-04-18T14:09:09Z |
| 08-38 opv section names (FEA-08.41) | Section title empty, field n `password`, k `concealed`, v `s3`; section "Extra", t `PIN`, v `1` | Import | Custom field `Password_` + 5 hex = `s3`, protected; `Extra_PIN` = `1` |
| 08-39 opv expiry (FEA-08.41) | Field t `expiry date`, empty section title, k `monthYear`, v 202506 | Import | Expiry on, 2025-06-01T00:00:00Z |
| 08-40 bw layout (FEA-08.43, FEA-08.44) | `{"items":[…]}` without folders; folders `A/B`, `A//B`, `/C` | Import | Empty result, no message; groups A, A/B, C; items of `A//B` in A/B, of `/C` in C |
| 08-41 bw items (FEA-08.45, FEA-08.46, FEA-08.48) | Reference Bitwarden test file | Import | "My Folder/Login Name": Username `myusername@gmail.com`, `KP2A_URL_1` `https://google.com`, `KP2A_URL_2` `https://gmail.com`, modified 2024-12-25T12:00:00Z, created 2024-12-01T12:00:00Z, one history item Password `oldpassword` modified 2024-12-01T12:00:00Z; "My Identity": `identity_address` = ` 1 North Calle Cesar Chavez ` LF `Santa Barbara, CA 93103` LF `United States `, `identity_ssn` protected; "Second Folder/Card Name": `card_code` protected, `card_number` not protected |
| 08-42 bw passkey (FEA-08.47) | Reference Bitwarden passkey test file | Import | `KPEX_PASSKEY_CREDENTIAL_ID` = `o-FfiyfBQq6Qz6YVrYeFTw`, `KPEX_PASSKEY_RELYING_PARTY` = `webauthn.io`, PEM starts `-----BEGIN PRIVATE KEY-----MIGHAgEA`; tag `Passkey` |
| 08-43 bw encrypted PBKDF2 (FEA-08.49, FEA-08.50) | Reference encrypted Bitwarden test file (kdfType 0, 100,000 rounds), password `a` | Import | K starts `9d1a914981dad5b0`; enc key starts `e05d98c318787571`; MAC key starts `80b149d20e614ec5`; validation and data MACs match; result opens. Password `b`: MSG-WRONG-PASSWORD |
| 08-44 bw vectors (FEA-08.49, FEA-08.50) | Password `demo-pass`, salt text `c2FsdA==`, kdfType 0, 5,000 rounds | Derive | K = `3f4717b796aa1719b2f074be9b8546b48713baa1952b33e186d3ddb6a41f6084`; enc = `52c30d8b3e3ceb1cde6ade1d2e0f3a5676421a7c0b0d503a1b8179e6d596a79d`; mac = `0bdbdb72da7019a5f97182b27155406027c9a9efdd1195612228eb344a00fb70`; kdfType 1 salt = `f0135775b8b1614b8076f40459c7fcb0aa7616b020a63d9d8b80cb2fefcb87b5` |
| 08-45 bw argon2 and damage (FEA-08.49, FEA-08.50) | Reference Argon2id test file (3 iterations, 64 MiB, 4 lanes), password `a`; a copy with one `data` ciphertext byte changed; a copy without `salt` | Import | Opens; MSG-BW-DAMAGED (data MAC) with no decryption; MSG-BW-ACCOUNT |
| 08-46 proton (FEA-08.51, FEA-08.52) | Reference Proton Pass test file | Import | "Personal/Test Login": Username `Username`, `KP2A_URL_1` `https://example2.com/`, TOTP set, `hidden field` protected, `second 2fa secret` = `TOTPCODE`; "Personal/Test Card": Username `1234222233334444`, Password `333`, `card_pin` protected; "My Deleted Note" expired; "Unknown Type": `content_attr1` = `value1`; group order Personal, Test |
| 08-47 proton encrypted (FEA-08.51) | `{"encrypted":true}` | Import | MSG-PROTON-ENCRYPTED |
| 08-48 v1 header (FEA-08.53) | First 16 bytes `03 D9 A2 9A 65 FB 4B B5 01 00 00 00 02 00 03 00`; another with version `02 00 04 00` | Import | MSG-V1-CIPHER (SHA-2 flag only); MSG-V1-VERSION |
| 08-49 v1 key (FEA-08.54) | Reference version 1 basic test file, password `masterpw` | Import | 6 groups, 7 entry records, rounds 713; decrypted content 2,345 bytes whose SHA-256 equals the header hash (verified with python and openssl) |
| 08-50 v1 key files (FEA-08.54) | Reference version 1 test files with binary, hex and hashed key files; the composite one with password `mypassword` and the hex key file; the Twofish one with `masterpw` | Import | Each opens; the single top group is named after the file's kind; Twofish file decrypts with Twofish-CBC |
| 08-51 v1 cp1252 (FEA-08.54) | Reference version 1 Windows-1252 test file, password `„password”` (U+201E, U+201D) | Import | Opens on the first try (bytes `84 … 94`) |
| 08-52 v1 records and tree (FEA-08.55, FEA-08.57, FEA-08.60) | Basic test file | Import | Root `Root`: Internet (icon 1) with Subgroup 1/Unexpanded/abc and Subgroup 2; eMail (icon 19). Internet entries: "Test entry" (Username `I`, URL `http://example.com/`, Password `secretpassword`, Notes `Lorem ipsum` LF `dolor sit amet`, attachment `attachment.txt` = `hello world` LF) and an empty-title entry; fresh ids |
| 08-53 packed time (FEA-08.56) | Bytes `1F 71 52 A8 00`; `2E DF 39 7E FB`; `1F 70 02 00 00` (month 0) | Decode | 2012-05-09T10:32:00Z ("Test entry" expiry, expiry on); nothing; nothing |
| 08-54 v1 meta (FEA-08.58) | Basic test file | Import | No "Meta-Info" entry; one custom icon (PNG) on entry "Custom Icon"; Internet and Subgroup 1 expanded, Unexpanded collapsed |
| 08-55 v1 auto-type (FEA-08.59) | Basic test file, group Subgroup 1 | Import | Entry 1: Notes `last line`, default sequence `{USERNAME}{ENTER}`, 5 associations in the reference test's order; entry 2: Notes `start line` LF `end line`. Extra demo line `see Auto-Type: x` stays in Notes (Larsal) |
| 08-56 v1 damaged (FEA-08.55, FEA-08.57) | Demo plaintext (re-encrypted with a demo key) with a field size of 2^31; another with levels 0, 2 | Import | MSG-V1-DAMAGED without a 2 GiB allocation; MSG-V1-DAMAGED |
| 08-57 xml import (FEA-08.61, FEA-08.62) | XML export of `rich-v3.larsalvault` (holds `Meta/Binaries`) | `larsal import` with a password | New vault; attachment `notes.txt` of "Full demo entry" = `demo attachment one` (same as the reference: observed) |
| 08-58 xml protected (FEA-08.62) | That XML with one value changed to `Protected="True"` and base64 text | `larsal import` | MSG-XML-PROTECTED, no file made (reference: crash, exit 139, observed) |
| 08-59 xml errors (FEA-08.61, FEA-08.62) | Target path exists; no `-p` and no key file; document `<x/>`; document with a DTD | `larsal import` | MSG-XML-EXISTS; MSG-XML-NOKEY; MSG-XML-NOROOT; refused (DTD) |
| 08-60 our format (FEA-08.63) | Assistant | Read kinds | No kind for a vault of our format; ACT-MERGE exists (MOD-11) |
| 08-61 failure clean (FEA-08.64, FEA-08.65) | Bitwarden file whose `items` is a number; OPVault with a broken folder | Import | Empty result, no crash; MSG-OPV-DAMAGED and no groups added anywhere |
| 08-62 secrets (FEA-08.66) | Debug build, import the Bitwarden demo with password `demo-pw`, cancel at Review | Dump memory, read logs (AT-C01, AT-C06) | `demo-pw` and the file password found nowhere |
| 08-63 limits (FEA-08.67) | ZIP whose `export.data` inflates past 256 MiB; JSON nested 600 deep; CSV with 10,001 columns | Import | MSG-TOO-LARGE naming the limit; memory stays flat |
| 08-64 kdf cost (FEA-08.68) | Bitwarden kdfType 0 with 10,000,001 iterations; kdfType 1 with 2,048 MiB; version 1 file with rounds 4,294,967,295 | Import | MSG-KDF-COST; MSG-KDF-COST; the CRY-02.14 question with the estimated time, and no derivation before the answer |

## How this was learned

- Read in the reference source: the import assistant (its two pages, the kind list, the target list and its fill routine, the review preview), the tab view's import finish handler (new, existing and temporary targets), the CSV parser and its table model, the CSV import screen and its layout file, each reader (.1pux, OPVault with its band, section and attachment parts and the opdata01 decoder, Bitwarden, Proton Pass, version 1), the XML document reader's string and binary routines, the vault's XML import routine and the command line import command, the merge routine's metadata part, the group move routine across vaults, the entry attribute container (default keys, set), the TOTP setter, the tag setter, and the tests for CSV parsing, CSV export, all importers and the version 1 reader.
- Ran the installed command line tool 2.7.11 in `/tmp/spec-fea08-09/` with demo vaults (password `demo-pass-1` and others): XML export and re-import of a 3.1 vault (attachments kept), import of a 4.1 export with an added `Meta/Binaries` pool (attachment restored), import with a `Protected="True"` value (crash, exit 139), import error messages.
- Checked by script, on the reference test data (read only): the Bitwarden PBKDF2 and HKDF chain and both MACs (python), the OPVault PBKDF2-SHA512 key and the `masterKey` HMAC and sizes (python), and the whole version 1 chain on the basic test file: header fields, AES-KDF with 713 rounds, final key, AES-CBC decryption and content hash (python with openssl), plus its records, packed dates and meta records.
- Not run: the reference's graphical CSV screen and import assistant (no window launch). CSV behavior comes from the source and its tests. The installed 2.7.11's CSV code was compared with the source (Verify, 2026-10-27): the same 11 target fields in the same order and the same parser; 2.7.11 differs only in that its automatic mapping matches the interface-language labels alone (the source also matches the English names, as Larsal, FEA-08.20) and in its working Windows-1252 decoder (FEA-08.14).
- Lead decisions (recommended option first):
  - L08-1: approve the RustCrypto `pbkdf2` and `hkdf` crates for `larsal-crypto` and a ZIP reader (`zip` with only its flate2 deflate backend) after AT-J03 review; or drop encrypted Bitwarden, OPVault and .1pux import.
  - L08-2: mask passwords in every import preview (reference: clear text).
  - L08-3: CSV parse errors need the extra confirmation (reference: import allowed at once).
  - L08-4: the size limits of FEA-08.67 and the KDF ranges of FEA-08.68.
  - L08-5: fresh ids for clashing imported ids (reference: duplicates).
  - L08-6: trashed imported items go to the target's recycle bin (reference: an ordinary group).
  - L08-7: small fixes: (a) ISO dates for .1pux and OPVault date fields; (b) icon numbers outside the standard set become 0; (c) Bitwarden folder paths normalized; (d) version 1 Auto-Type lines only at line start; (e) a leading backslash does not start a quoted CSV field; (f) OPVault files trimmed of trailing white space; (g) after a malformed quoted CSV field the next record starts at the offending character (reference: that character is dropped).
  - L08-8: Bitwarden: require type 2 and check the `data` MAC.
  - L08-9: the .1pux result's root group is named `1PUX Import` (the reference's name holds a banned word).
