# INT-08 Shared groups

Status: reviewed (checked against the reference in E11-S1, 2026-10-31; D-INT08-1 to D-INT08-10 taken by the default rule, D-INT08-3 by LD-61); built in E11-S2 to E11-S6
Epics: E11-S2 (share settings and containers: INT-08.1 to INT-08.6, INT-08.8 to INT-08.14, INT-08.28, INT-08.33, INT-08.35, INT-08.36, the secret types of INT-08.39), E11-S3 (import, export and the safety rules: INT-08.7, INT-08.15 to INT-08.20, INT-08.31, INT-08.32, INT-08.34, INT-08.37, INT-08.38, INT-08.40), E11-S4 (Option A frames: INT-08.20 to INT-08.26, INT-08.31), E11-S5 (screens: INT-08.20 to INT-08.26, INT-08.31, MI08-23), E11-S6 (Verify and Red team: the parity rows below). Not built: INT-08.29, INT-08.30 and every "option b" part (D-INT08-1 (a)); remote sync (INT-09) is out (LD-262 (6))
Parity rows: SI-09, SD-01, SD-03, SD-06, SD-09, SR-14, SF-02

## What it does

A shared group copies one group of a vault to a separate file, the **container**, and reads changes back from it. Other people (or the user's other vaults) point one of their own groups at the same container. The container is a normal vault file protected by a **share password**, or a zip archive that holds that vault file plus a signature.

Each shared group has a **mode**:

| Mode | Reads the container | Writes the container |
|---|---|---|
| Inactive | no | no |
| Import | yes: merged into the group when the vault opens, when the share settings change and when the file changes | no |
| Export | no | yes: rewritten after every save of the vault |
| Synchronize | yes, as Import | yes, as Export |

Two app settings switch the whole feature: allow import and allow export. Both are off by default.

Shared groups are not server sharing (E18): the two features never call each other, and the screens use different words. This card's screens say "a group of your vault, shared as a file"; server sharing says "a vault shared through your server" (spec/research/sync-server.md P24).

Other cards: MOD-11 owns the merge (kind "Shared-group import", MOD-11.1; synchronize-mode erase scope MOD-11.15, D-11-9). FMT-14 owns the custom data item that holds a group's share settings (FMT-14.20). FMT-13.17 owns the attachment namespace of shared entries. FMT-15.11 and FMT-15.12 own the deleted-objects list on import and export. MOD-08 owns references (the export's reference rule is here, INT-08.13; a reference inside a share group finds only entries inside it, MOD-08.32). MOD-02.18 defines "shared" for a group and its subtree. MOD-06 owns the badge images. APP-05 owns saving and the change-on-disk watcher. APP-01 lists the settings below. FEA-02 owns the generator button on the share password field.

Notation: id(xx) is a 16-byte id with every byte 0xxx (as in MOD-11). V is a demo vault at `/tmp/spec-int08/v.appvault`, password `demo-v`. T0 = 2026-01-01T00:00:00Z, T1 = 2026-02-01T00:00:00Z, T2 = 2026-03-01T00:00:00Z.

## Inputs and outputs

- In: the open vault; each group's share settings item; the two allow settings; the container files on disk; the share passwords.
- Out: the merged group (import); container files (export); messages; badges and labels.
- Limits: a container is read with the same limits as any vault file (FMT-08.12, LD-22); a zip container is read only up to those limits (INT-08.36). Paths are text of any length the file system accepts.

## Rules

### Share settings

INT-08.1 **Shared group.** A group is a **share** when its own custom data holds the item with key `4B 65 65 53 68 61 72 65 2F 52 65 66 65 72 65 6E 63 65` (stored encoded, name rule) (FMT-14.20). The group and everything below it are "shared" (MOD-02.18). The root group may be a share: then the whole vault is shared.

INT-08.2 **Item value.** The value is standard base64 (with `=` padding, no line breaks) of a UTF-8 XML text. The reference reads it leniently: characters outside the base64 alphabet are skipped before decoding.

INT-08.3 **XML layout.** One root element, name `4B 65 65 53 68 61 72 65` (stored encoded, name rule), with these children:

| Element | Content | Meaning |
|---|---|---|
| `Type` | empty child elements `Import` and/or `Export` | Import only = Import mode; Export only = Export mode; both = Synchronize; none = Inactive |
| `Group` | base64 of 16 bytes | An id made when the settings were first created. It is not the group's id. The installed version uses it as the attachment namespace of the shared subtree (FMT-13.17); the source build does not use it except to notice changes (INT-08.15) |
| `Path` | base64 of the UTF-8 path text | Container path, absolute or relative (INT-08.5) |
| `Password` | base64 of the UTF-8 share password; empty element for an empty password | Share password, stored readable inside the vault document (Security notes) |
| `KeepGroups` | `True` or `False` | Keep group structure (INT-08.12) |

Writing (reference and App): the declaration `<?xml version="1.0"?>`, with no encoding attribute (confirmed in E11-S1: the reference 2.7.11 writes its signature entry with the same XML writer, and that entry starts with exactly these 21 bytes, the root element right after; the reference writes a share item only from its group editor, which needs its window, so the share item itself and the empty `<Password></Password>` are from the source), then the root, children in the order above, `Import` before `Export`, empty elements written as `<Import/>`, no whitespace or line breaks anywhere, an empty password as `<Password></Password>`.

Reading:
- The first element must be the root named above (exact, case-sensitive); otherwise the settings are invalid (INT-08.4).
- Children may come in any order; unknown children are skipped with their content.
- Inside `Type`, `Import` and `Export` set their flag; reading of `Type` stops at the first other child.
- `KeepGroups` is true only for the exact text `True`. A missing `KeepGroups` means false (old files). New settings made in the editor start with true (INT-08.21).
- A missing `Group` gives a new random id on every read (reference). Because the change check of INT-08.15 step 2 compares that id, every change of the vault then sets such a share up again and imports it again (source). App keeps 16 zero bytes in memory for a missing `Group` and writes a random id the next time it writes the item.
- Where the id comes from (reference, source; the installed version the same): a share made in the group editor starts from one empty-settings value that the app makes once per run, so every share created during one run of the reference carries the same `Group` id, and so does a share whose item was unreadable and is set again in the editor. App gives each new share its own random id (CRY-03 randomness, `app-crypto::random`). The reference half is from the source only and stays open (T65): it needs the reference window, owner's go (rule 10, W-08).

INT-08.4 **Valid, importing, exporting.** Importing = the Import flag is set and the path is not empty. Exporting = the Export flag is set and the path is not empty. Valid = mode is not Inactive and the path is not empty. An item that decodes to nothing usable (bad root, empty text, bad base64 giving no root) is **invalid**: the group still counts as shared (it has the key), it never imports or exports, and its label says the reference is invalid (INT-08.24).

INT-08.5 **Path.** A relative path is resolved against the folder of the vault file; an absolute path is used as is. `~` is not expanded. A vault that has no file yet resolves against the app's working folder in the reference; App refuses to run any share of a vault that has no file yet (no message, the editor shows MI08-17). Conflicts (INT-08.18) compare the path text as stored, not the resolved path.

INT-08.6 **Share key.** A container is opened and written with a composite key that has exactly one part: the share password (FMT-04). The password part is always present, also when the share password is empty: an empty share password gives the "empty password" part `SHA-256("")` = `e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855` (FMT-04.2), never "no password". No key file, no hardware key. Confirmed in E11-S1: the reference command line tool opens a container the reference made with an empty share password when given an empty password, and refuses it with no password (T08).

INT-08.7 **App settings.** Stored by App, not in the vault (APP-01):

| ID | Meaning | Default |
|---|---|---|
| `share.allow_import` | Imports may run | off |
| `share.allow_export` | Exports may run | off |
| `share.quiet_success` | Hide sync success messages; problems still show | on (App, D-INT08-10) |
| `share.signer_name` | Signer name written into signed containers (only with D-INT08-1 option b: not built) | the macOS account name |

Reference (source, confirmed in E11-S1): the success-message setting has stored default "show success"; its box is ticked in the page's screen definition, the page never loads the stored value and stores the box on OK. The page is made once per main window, so within one run the box keeps the user's last choice when the page opens again. After a restart it shows ticked whatever is stored, and the next OK on any app settings page stores "quiet". So "show success" stays on only until the reference restarts and its settings are saved again (T10, open: it needs the reference window). App shows and keeps the stored value (D-INT08-10, T09).

### Containers

INT-08.8 **Unsigned container.** A vault file of our format (FMT-01 to FMT-16), nothing else.

INT-08.9 **Signed container.** A zip archive with two entries, written in this order:

| # | Entry name (exact bytes) | Content |
|---|---|---|
| 1 | `container.share.signature` | The signature text (INT-08.10), Latin-1 |
| 2 | `63 6F 6E 74 61 69 6E 65 72 2E 73 68 61 72 65 2E 6B 64 62 78` (stored encoded, name rule) | The unsigned container bytes (INT-08.8) |

Both entries use deflate (method 8). Exact layout of the reference's zip (confirmed in E11-S1 from the bytes of two reference 2.7.11 containers, T14): flags `0x0002` (strongest compression), file time and date 0, no data descriptor. Every local header has version needed 45 and carries a 20-byte ZIP64 extra field (id `0x0001`, data length 16) whose 16 bytes are zero; the local size fields hold the real sizes. The central directory (version needed 20, made by 0, no extra fields, real sizes) and the plain 22-byte end record carry no ZIP64 data; there is no ZIP64 end record and no ZIP64 locator. Readers use the central directory and must skip any local extra field by its length; a reader that took sizes from that extra field would read 0 bytes. app-core's ZIP reader (LD-142 (2)), unchanged, reads both reference containers (T66), so it needs no ZIP64 support for them (LD-267 (5)).

Reading (reference): the file is a zip if it opens as one; then only the entry whose name equals entry 2 exactly (case-sensitive) is used; every other entry, the signature included, is ignored; if two entries have that name, the last one wins; if none has it, the vault read fails with an empty input. A file that is not a zip is read as an unsigned container. Confirmed in E11-S1 with crafted zips: an extra member is ignored (T15), the last of two vault entries wins (T16), a bad signature is ignored (T45).

App reads by content: first bytes `03 D9 A2 9A` (FMT-01) mean unsigned; first bytes `50 4B 03 04` mean zip; anything else fails with MI08-04. App takes entry 2 as the reference does, but a second entry with the same name is an error (MI08-04), because no writer makes it.

INT-08.10 **Signature text.** The signature file is XML in the INT-08.3 style (declaration without an encoding attribute), stored as Latin-1 (below), same root element, children:

| Element | Content |
|---|---|
| `Signature` | `rsa|` followed by the signature in lowercase hex. The signature is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017) over the exact bytes of entry 2. A 2048-bit key gives 512 hex digits. |
| `Certificate` | two children: `Signer` (the signer name as text) and `Key` (base64 of the public key blob below) |

Public key blob: four parts, each a 32-bit big-endian length followed by the bytes: the 7 ASCII bytes `ssh-rsa`; the exponent e, unsigned big-endian, minimal length, no sign byte; the modulus n, the same way. This is not the standard SSH key form: the standard form adds a 00 byte before a number whose top bit is set, the reference does not. For e = 65537 and a 2048-bit n the blob is 278 bytes, starts `00 00 00 07 73 73 68 2D 72 73 61 00 00 00 03 01 00 01 00 00 01 00`, and its base64 is 372 characters starting `AAAAB3NzaC1yc2EAAAADAQABAAABA`.

The signer name comes from the `USER` environment variable, then `USERNAME`, so it is the maker's account name, in plain text, readable by every member. It is converted to Latin-1 before zipping; characters outside Latin-1 become `?`. When the reference has no usable key, or the signer name is empty (`USER` and `USERNAME` unset or empty), it counts the certificate as missing, writes an empty signature entry (0 bytes) and still writes the zip (seen in E11-S1, T66).

Confirmed in E11-S1 from a container the reference 2.7.11 signed: the signature text starts `<?xml version="1.0"?>`, then `rsa|` and 512 lowercase hex digits; the `Key` is 372 base64 characters starting `AAAAB3NzaC1yc2EAAAADAQABAAABA`, its blob is 278 bytes with the parts 7, 3 and 256 bytes long and no 00 byte before the modulus (top byte `A3`); RSASSA-PKCS1-v1_5 with SHA-256 over entry 2's bytes verifies (T18).

INT-08.11 **Which kind is written.** Reference: a signed container when the resolved path ends with `2E 6B 64 62 78 2E 73 68 61 72 65` (stored encoded, name rule), compared case-sensitively; otherwise unsigned, whatever the extension (confirmed in E11-S1: the signed suffix in capitals gives a plain vault file, T19). App: always unsigned, whatever the suffix (D-INT08-1 (a), INT-08.28).

INT-08.12 **Container content.** Built from the share group G of the source vault:
1. A new vault: recycle bin setting off, name = G's name, other metadata at new-vault defaults (MOD-12).
2. Root group = a copy of G with G's id, fields and times, without the share item.
3. G's entries, copied with id, every field, times and full history.
4. Keep group structure on: every group below G, with id, fields, times and custom data, and their entries as in step 3, in stored order. Off: no groups below G and none of their entries.
5. Each custom icon used by a copied group or entry (MOD-06), with its id.
6. The whole deleted-objects list of the source vault (FMT-15.12).
7. References: INT-08.13.

Reference (confirmed in E11-S1, T11 to T13): the copied groups keep their custom data, so a share nested inside G exports its own share item, path and password included; the whole deleted-objects list is copied. App strips the share item from every copied group (D-INT08-5). App also leaves out the recycle bin and recycled objects when G is the root (D-INT08-8).

INT-08.13 **References on export.** App puts no value from outside the share into a container (decided: spec/decisions.md LD-279 (1), F-140): every field of every copied entry, its history items and its custom fields keep their text as written, field references and placeholders included, with their protection flags. A reference to an entry outside the share stays as its `{REF:...}` text; in a member's vault it finds nothing outside the share group (INT-08.16, MOD-08.32, LD-279 (2)). App adds no history item and keeps the entry's modification time (T20). Reference behavior: each standard field whose whole value is a `{REF:...}` that finds no entry inside the container is replaced with the value the source vault resolves for it, and the entry gets one new history item and the export time as its modification time (E11-S1, kept file a); App does not do this, because it would put a value the user never shared into every member's copy.

Reference (confirmed in E11-S1): it replaces the field inside an update of the container's copy of the entry, so that copy gets one new history item that holds the old `{REF:…}` text, and its modification time becomes the export time; the source vault is not changed. That history item tells every member the id of an entry outside the share, which App's rule avoids.

INT-08.14 **Encryption of a container.** Reference: AES-256 (CRY-01), AES-KDF with 1,000,000 rounds (CRY-02), gzip, and the file version FMT-16 picks: version 3.1 when the content needs nothing newer (confirmed in E11-S1: 3.1 for plain content, 4.0 when a copied group holds custom data such as a nested share item, T21). App (D-INT08-6): the cipher and KDF settings of the source vault (same algorithm and costs, fresh seed or salt, CRY-03), gzip, version 4 by FMT-16.19 to FMT-16.21. This holds also when the source vault's KDF settings lie in the ask band of CRY-02.14, because a save never asks; an importer refuses such a container with no question (INT-08.36; decided: spec/decisions.md LD-281 (1); T67). Unsigned containers are written atomically (APP-05, without a backup) in both apps; a failed write gives MI08-03 with reason MI08-07. The reference writes signed containers straight into the target file (not atomic); App writes them atomically too.

### When it runs

INT-08.15 **Import triggers.** For each open, unlocked vault, while `share.allow_import` is on:
1. When the vault is unlocked or opened: every importing share is imported, in group tree order.
2. When any change of the vault (an edit, a group added or removed, a merge) leaves a group whose share settings differ from those seen last time (mode, path, password or `Group` id; `KeepGroups` alone is not compared): that share is set up again and, if importing, imported at once.
3. When a watched container changes: imported 100 ms later. A second change while one is pending is folded into it.
4. When an allow setting changes: as step 1 for the new state; turning both off stops every watcher. Reference (source): it sets the shares up again only when both settings were off before; turning import on while export was already on imports nothing until a container changes or the vault is opened again.

Watching (each valid share, any mode but Inactive): operating-system file change notices, plus a check every 30 seconds. A change counts only when the SHA-256 of the first 5 KiB (5,120 bytes) differs from the last value seen. A rewrite of a vault always changes its first bytes (CRY-03), so this catches every save.

Changes made by an Export-only share's file are ignored.

Reference at runtime (E11-S1, run hidden): step 1 confirmed (a container's entry was in the vault after unlock) and step 3 confirmed (another process rewrote the container 5 s after start; its new entry was in the vault, through the system's file notice). Not run, still from the source: steps 2 and 4, which need an edit or a settings change in the reference window (owner's go, rule 10, W-08); the 30-second check, the 5 KiB hash and the 100 ms delay, which were not timed (App's own rule: T24, T25).

INT-08.16 **Import steps.**
1. Read the container (INT-08.9); a missing or unreadable file is an error with the system's reason (MI08-02).
2. Open the vault inside with the share key (INT-08.6). Any read error is an error carrying the reader's message (MI08-02).
3. Merge: source = the container's root group, target = the share group, synchronize mode, vault custom data skipped (MOD-11.1, MOD-11.15). App limits the merge to the share group (decided: LD-61, INT-08.32).
4. Changes made: success (MI08-01). No changes: nothing is reported.

References in the share group (decided: spec/decisions.md LD-279 (2), F-142): a field reference in an entry inside a share group finds only entries inside that share group, for every use: fill, Auto-Type, Copy, display and export (MOD-08.32). So a reference that a container brings in as written (INT-08.13) never reads an entry of the member's vault outside the share; the share's own references, such as T20's Alias, still work (T68).

INT-08.17 **Export triggers.** After every successful save of the vault, while `share.allow_export` is on: every exporting share is written, even when its content did not change, in path text order. The watcher of each path is paused during its write and restarted after, so a share never imports its own export. Before any write, INT-08.18 runs; one conflict blocks every export of that save. Reference: export at save confirmed in E11-S1 (the containers were written at the vault's save); the conflict messages of INT-08.18 are from the source (they show in the reference window).

INT-08.18 **Path conflicts.** Among the shares of one vault, by stored path text:

| Case | Reference | App |
|---|---|---|
| Two or more exporting shares, same path | Export blocked for all shares; error MI08-06 per path, listing the group names | Same |
| Two or more importing shares, same path | Warning MI08-05. Every import of that path goes into one of them (the last set up), whichever share asked | Warning MI08-05; the path is imported into none of them until the conflict is fixed (D-INT08-7) |
| One share imports and another exports the same path | Only the editor warns (MI08-13) | Same |

INT-08.19 **Paused during a manual merge.** Sharing for the target vault pauses while the merge dialog of MOD-11.27 is open: no import, no export, no watcher fires. When the dialog closes, App runs step 1 of INT-08.15 for that vault. Reference (source): the pause is only a flag read at the next change of the vault; a container change before that still imports, the first change stops every watcher, and after the dialog closes sharing stays stopped until the next change of the vault, which then sets every share up again and imports it. This reference part stays open: it needs the reference window, owner's go (rule 10, W-08).

INT-08.20 **Messages.** All results of one pass go into one banner, one line each: success lines first, then warnings, then errors. The banner type is error if any error, else warning if any warning, else success. Success lines are left out when `share.quiet_success` is on. See the message table. The reference's banner and its quiet behaviour are from the source and stay open: they need the reference window, owner's go (rule 10, W-08).

### Screens

The reference's screens (INT-08.21 to INT-08.26) and their texts are from the source; seeing them stays open: it needs the reference window, owner's go (rule 10, W-08).

INT-08.21 **Group editor, Sharing page.** Fields:
- Type: Inactive, Import, Export, Synchronize (in this order).
- Path, with a Browse button.
- Password, masked, with the generator button (FEA-02); secure input while focused (APP-10).
- Keep group structure, ticked by default.
- Clear: removes the share item and empties the fields.
Path, Browse, Password and Keep group structure are enabled only when Type is not Inactive. Every field change writes the item into the group being edited; it takes effect when the group edit is accepted. Turning a group into a share on this page is the user's approval of it (INT-08.31).

INT-08.22 **Browse.** The chooser opens in the folder last used for shares. Import: an open-file chooser. Export, Synchronize: a save-file chooser. Filters: unsigned container, signed container, all files. If the chosen name ends with none of the container extensions (case-insensitive), App adds `.appvault` (reference: its own vault extension, `2E 6B 64 62 78`, stored encoded, name rule), adding the dot only if the name does not end with one.

INT-08.23 **Editor warnings**, first match only, shown only while Type is not Inactive (cases 1 to 4 also need a path; the reference the same, source):
1. Path ends with no supported extension (case-insensitive): MI08-10. App's supported extensions: `.appvault`, `.appshare` (D-INT08-2), `2E 6B 64 62 78` and `2E 6B 64 62 78 2E 73 68 61 72 65` (stored encoded, name rule).
2. Another group of this vault exports the same path, and this one exports: MI08-11 (error).
3. Another group imports the same path, and this one imports: MI08-12.
4. One of the two imports and the other exports the same path: MI08-13.
5. Both allow settings off: MI08-14; only import allowed: MI08-15; only export allowed: MI08-16; both on: no message.

INT-08.24 **Indicators.**
- Badge: a share group that is not expired gets the "share active" badge when it imports with import allowed, or exports with export allowed; otherwise the "share inactive" badge (MOD-06). Only the share group itself gets a badge, not its subgroups.
- Label under the entry list, when the selected group is a share or inside one (the nearest share below the root counts; a root share shows no label): MI08-24 for the share's mode, then a line MI08-16 when the share imports and import is off, and a line MI08-15 when it exports and export is off. An invalid or inactive share shows MI08-25 instead (the reference has an inactive-share text it never reaches, because it counts an inactive share as invalid).
- Group preview: a Share tab, present only on a share group, with the mode name and the path.

INT-08.25 **Vault settings, Shared groups page** (MOD-12.1). A read-only table, one row per share group in tree order: group path without the root, joined by ` > `; mode; path. The reference also has two columns (last signer, certificates) that are always empty; App shows them only with D-INT08-1 option b (signer and trust state).

INT-08.26 **App settings, Shared groups page.** Allow import, Allow export, Hide sync success messages. Signer name, key fingerprint and a Generate button appear only with D-INT08-1 option b (INT-08.30).

### Signatures and trust

INT-08.27 **Reference: no checking.** Neither the source nor the installed version checks signatures, and neither has a trust list. Import ignores the signature file entirely (INT-08.9). The reference still makes a signing key (RSA-2048) the first time its sharing settings are shown or a signed container is written, names the signer after the account name, and writes signatures (INT-08.10). Its settings still define a key for a foreign-certificate list, never read or written. Older reference versions (before 2.7.0) had a trust list: per container path and signer certificate, Trusted or Untrusted, missing meaning Ask; the ask dialog offered Not this time (default), Never, Always, Just this time; an unsigned container always asked, with a warning; the user's own certificate was trusted silently; a bad signature refused the import. Those versions also wrote the signer's full private key into the `Key` element of every signature file. Its user guide still says that signing makes sure the data comes from the expected signer, which the current code does not check.

INT-08.28 **App: signatures** (D-INT08-1, decided: option (a), by the default rule; (b) and (c) are not built). Options:
- (a) No signatures (the decided option). App reads signed containers by taking entry 2 and ignoring the signature, as the reference does, and always writes unsigned containers, whatever the path suffix. The reference reads such a file at any path, because it tries zip first and falls back to a plain vault. Trust comes from INT-08.31 instead. No new crate.
- (b) Verify and sign. App verifies every signed container and applies INT-08.29; writes signed containers for paths ending in `.appshare` or the reference's signed suffix (case-insensitive). Needs an RSA crate (not in the approved list; the common one carries a timing advisory for private-key use, so `cargo audit` needs a reviewed exception, AT-J03), a Keychain item for the private key and the screens of INT-08.25, INT-08.26 and INT-08.29.
- (c) Ed25519 signatures of our own (approved crate) and reference RSA signatures treated as unsigned. Not recommended: a second signature format nobody else reads.

D-INT08-2 (decided, default rule): App's own extensions are `.appvault` (unsigned) and `.appshare` (signed, used only with option b). Placeholders for the rename pass (AGENTS.md naming).

INT-08.29 **Trust list (only with D-INT08-1 option b: not built).**
- A record is (resolved container path, signer key fingerprint) → Trusted or Untrusted. No record means Ask. Unsigned containers use an empty fingerprint. Records live in App settings (`share.trust`), never in the vault.
- Fingerprint: SHA-256 of the public key blob (INT-08.10), shown as 32 uppercase hex pairs joined by `:`.
- A signature that is present but fails, or a `Key` that is not a valid public key blob, refuses the import: MI08-20, no question.
- A `Key` that holds a private key (containers from reference versions before 2.7.0) is treated as unsigned, with MI08-21, because every reader of the file holds that key.
- App's own key is trusted without a record.
- Ask: a non-blocking banner on the share (MI08-22) with Trust always, Trust this time, Not this time, Never. Nothing is merged until the user answers. Not this time and Trust this time are not stored. A new fingerprint for the same path asks again.

INT-08.30 **Signing key (only with option b: not built).** RSA-2048 with e = 65537, made from `app-crypto::random` when the first signed container is written or on Generate. The private key is kept in the Keychain (service `com.app.vault`, this device only), never in a settings file and never in the vault. Generate replaces it after a confirmation; old trust records elsewhere then no longer match.

### App safety rules

INT-08.31 **Approval of share settings** (D-INT08-4, decided). App keeps, in App settings (`share.approved`), one record per approved share: (vault id = the root group's id, as in INT-09.20; group id; SHA-256 of the mode and resolved path). A share that has no matching record never imports, exports or watches; the group shows MI08-18 with an Approve action that shows mode and full path. Creating or changing a share in App's group editor approves it. This covers share settings that arrive by merge (MOD-11.6), by import from another share, or from another app editing the vault.

INT-08.32 **Import stays inside the share** (D-INT08-3, decided: LD-61; the container's own recycle bin: LD-130). The share import's merge matches, moves, updates and erases only entries and groups inside the share group's subtree. A container object whose id belongs to an entry or group outside that subtree (the recycle bin included) is skipped and gets a Conflict record (LD-61, MOD-11), and the import shows warning MI08-19 naming the count. A recycle bin inside the container is an ordinary group of the share; nothing moves to or is made in this vault's own bin (LD-130). Reference: the merge looks ids up in the whole vault (MOD-11.4), so a container can move any entry of the vault into the share group (newer location time) or overwrite it in place (newer modification time); its erase pass also reaches the whole vault (MOD-11.15).

INT-08.33 **No nested share items** (D-INT08-5). App writes no share item into a container (INT-08.12) and drops every share item found below the root of an imported container before the merge.

INT-08.34 **Path guard.** A share whose resolved path is the vault's own file, or the file of any vault open in App, never exports or imports; the editor shows MI08-17. The reference has no such check, so an export there overwrites the vault with the container.

INT-08.35 **Recycle bin** (D-INT08-8). A share group inside the recycle bin is inactive. A root share's export leaves out the recycle bin and recycled objects. Reference: shares inside the bin keep importing and exporting, and a root export carries the bin.

INT-08.36 **Hostile containers.** Every container is untrusted (AT-A08). The vault inside is read with the limits of FMT-08.12; the zip is parsed only within the vault file limit (FMT-01.31), and its vault entry never inflates past that limit (AT-A06). A KDF cost in the ask band or above a refuse rule of CRY-02.14 is refused without asking, because imports run without the user (AT-A05; LD-281 (1), T58, T67). The zip reader and the share settings parser are fuzz targets (AT-A10).

INT-08.37 **Import before export** (D-INT08-9, decided). Before writing a Synchronize share, App imports its container if the file changed since the last import. Reference: the export overwrites the file, so another person's export made since the last import is lost from the file until that person saves again (it stays in their vault).

INT-08.38 **Work off the main thread.** Imports and exports run in the background; the vault stays usable. A save during a running export queues one more export.

INT-08.39 **Share password handling.** The share password is held in secret types (SecretString) after the item is decoded. It is never logged and never part of a message. An empty or weak (below Good, FEA-05) share password on a share App creates gives warning MI08-23 in the editor; it is still allowed, for parity.

INT-08.40 **Command line tool.** Shares never run from the command line tool (INT-10), as in the reference. Its saves do not export.

## Messages

App's own wording (final; review R08-3); the reference's texts are given for comparison, read in its source (names of the reference app and its parts replaced by ‹…›). ‹path› is the path as stored in the share settings; ‹full path› is the resolved path (INT-08.5). Banner lines (INT-08.20) start with the path, so the lines of one pass line up. The words follow the mode names of the Sharing page: import, export, sync. The reference's texts were read in its source, not seen on screen: that needs the reference window, owner's go (rule 10, W-08).

| ID | Kind | Rule | App text | Reference (source) |
|---|---|---|---|---|
| MI08-01 | success line | INT-08.16 | ‹path›: changes imported. | Imported from ‹path› |
| MI08-02 | error line | INT-08.16 | ‹path›: import failed. ‹reason› | Import from ‹path› failed (‹reason›) |
| MI08-03 | success / error line | INT-08.17 | ‹path›: exported. / ‹path›: export failed. ‹reason› | Export to ‹path› / Export to ‹path› failed (‹reason›) |
| MI08-04 | error line | INT-08.9 | ‹path›: import failed. It is not a share file (unknown file kind / the archive holds no vault / the archive holds two vaults). | none: a file that is not a zip is read as a vault and fails with the reader's text in MI08-02's form; a zip without the vault entry fails as an empty input |
| MI08-05 | warning line | INT-08.18 | ‹path›: imported by several groups (‹group names›), so none of them is updated until only one imports it. | Multiple import source path to ‹path› in ‹groups› |
| MI08-06 | error line | INT-08.18 | ‹path›: exported by several groups (‹group names›), so nothing was exported. Give each group its own file. | Conflicting export target path ‹path› in ‹groups› |
| MI08-07 | reason in MI08-03 | INT-08.14 | The file could not be written: ‹system reason›. | Could not write export container. (signed containers; an unsigned one gives the save's own text) |
| MI08-10 | editor warning | INT-08.23 | App cannot share this kind of file. Use a name that ends in ‹list›. | Your ‹reference app name› version does not support sharing this container type. Supported extensions are: ‹list›. |
| MI08-11 | editor error | INT-08.23 | Another group in this vault already exports to ‹path›. Choose another file. | ‹path› is already being exported by this database. |
| MI08-12 | editor warning | INT-08.23 | Another group in this vault already imports from ‹path›. While both do, neither is updated. | ‹path› is already being imported by this database. |
| MI08-13 | editor warning | INT-08.23 | One group in this vault exports to ‹path› and another imports from it. | ‹path› is being imported and exported by different groups in this database. |
| MI08-14 | editor info | INT-08.23 | Sharing is turned off. Turn on import or export in App's settings, Shared groups. | ‹feature name› is currently disabled. You can enable import/export in the application settings. |
| MI08-15 | editor info; label line | INT-08.23, INT-08.24 | Export is turned off in App's settings. | Database export is currently disabled by application settings. Label: Export is disabled in settings |
| MI08-16 | editor info; label line | INT-08.23, INT-08.24 | Import is turned off in App's settings. | Database import is currently disabled by application settings. Label: Import is disabled in settings |
| MI08-17 | editor error | INT-08.5, INT-08.34 | This file cannot be used for sharing. Save this vault to a file first. / This file cannot be used for sharing: it is the file of a vault open in App. | none |
| MI08-18 | warning on the group, with Approve | INT-08.31 | Sharing is paused for this group: its settings were not made on this Mac. ‹mode›: ‹full path› [Approve] | none |
| MI08-19 | warning line | INT-08.32 | ‹path›: ‹n› items were not imported because they belong outside this shared group. | none |
| MI08-20 | error line (option b) | INT-08.29 | ‹path›: import failed. Its signature is not valid. | none in the studied source (no check since 2.7.0) |
| MI08-21 | warning line (option b) | INT-08.29 | ‹path›: signed with a key that is no longer secret, so it counts as unsigned. | none |
| MI08-22 | question (option b) | INT-08.29 | Trust ‹signer› (‹fingerprint›) for ‹path›? / ‹path› is not signed. Import it anyway? [Never] [Not This Time] [Trust This Time] [Trust Always] | none in the studied source (an ask dialog existed before 2.7.0, INT-08.27) |
| MI08-23 | editor warning | INT-08.39 | The share password is empty or weak. Anyone who gets the share file may be able to open it. | none |
| MI08-24 | label | INT-08.24 | Shared: imports from ‹path› / Shared: exports to ‹path› / Shared: syncs with ‹path› | Imported from ‹path› / Exported to ‹path› / Synchronized with ‹path› |
| MI08-25 | label | INT-08.24 | Sharing is off for this group: its settings are inactive or cannot be read. | Invalid sharing reference (its "Inactive share ‹path›" is never reached) |

## Edge cases and errors

- Paths outside Latin-1: the reference hands the zip library the path converted to Latin-1 (other characters become `?`), both when it writes a signed container and when it tries to read a file as a zip (source). Latin-1 bytes are not the UTF-8 that the Mac file system uses, so on a Mac a signed container whose path holds any character outside ASCII (`é`, `ж`, an emoji) is written under a wrong name or not at all, and is never read as a zip (the plain-file read then fails, MI08-02). App passes paths as they are (UTF-8 file names on macOS).
- Path case: the reference picks signed or unsigned writing by an exact-case suffix, but warns about extensions without case. A path ending in the signed suffix in capitals gets an unsigned vault in the reference. App: D-INT08-1.
- Container missing at import: error MI08-02 with the system reason (the reference shows this as an error, not a warning). App: same; while the file stays missing, App reports it once per unlock, not on every 30-second check.
- Group deleted while an import is pending: the import is dropped.
- Entry moved out of a share group: no deleted object is made, so it stays in every other copy of the share; in the reference it keeps being updated from the container wherever it now sits (the reference user guide says so). App: it is no longer touched (INT-08.32); the container's copy then shows up again in the share group as a new entry only if it has a different id, which it does not, so it is skipped with MI08-19.
- Two share groups in one vault, one nested in the other: each runs on its own; the outer export includes the inner group's entries (App without the inner share item).
- Share settings item edited outside App to hold a huge value: limited by FMT-14 and FMT-08.12; decoding failures make the share invalid (INT-08.4).
- Export of a share whose group has no entries: a container with an empty root is written.
- Allow export turned off: existing containers stay on disk unchanged.
- Locked vault: no imports or exports; watchers stop and restart with an import pass at unlock (INT-08.15 step 1).

Not on Mac: on Linux the reference watches network file systems by polling only. Windows paths use backslashes. Nothing else differs.

## Lead decisions

Decided 2026-10-31 (E11-S1): D-INT08-1 to D-INT08-10 take the recommended option of each row below, by the default rule of spec/decisions.md; D-INT08-3 is LD-61 (with LD-130 for the container's own recycle bin). So App writes no signatures (D-INT08-1 (a)); INT-08.29, INT-08.30 and every "option b" part of this card (the signer name of INT-08.7, the two extra columns of INT-08.25, the signer fields of INT-08.26, MI08-20 to MI08-22, T47 to T51) are not built. (These IDs were D-08-n in the first draft; renamed in the second review because MOD-08 already uses D-08-1 to D-08-11.)

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT08-1 | Signatures on containers (INT-08.27 to INT-08.30) | (a) none: read a signed container by taking its vault entry, always write unsigned; (b) verify and sign as the reference writes (RSA, PKCS#1 v1.5 with SHA-256), with a trust list per path and signer; (c) Ed25519 signatures of our own | (a) for the first E11 build. The reference itself has checked no signature since 2.7.0 (INT-08.27), so (a) loses no parity; (b) needs an RSA crate outside the approved list, and the common Rust one carries advisory RUSTSEC-2023-0071 (a timing side channel on private-key use), which AT-J03 would have to accept, plus a Keychain item (LD-49) and three more screens; (c) is a format no other app reads. Trust comes from INT-08.31 instead |
| D-INT08-2 | App's own container extensions (INT-08.22, INT-08.23) | (a) `.appvault` unsigned, `.appshare` signed (signed only with D-INT08-1 (b)); (b) `.appvault` only | (a). It mirrors the reference's pair of a plain vault extension and a signed suffix (INT-08.11); both are placeholders for the rename pass (AGENTS.md Naming) |
| D-INT08-3 | Reach of a share import (INT-08.32) | (a) only inside the share group; (b) the whole vault, as the reference | Decided: spec/decisions.md LD-61 (and LD-130 for the container's own recycle bin) |
| D-INT08-4 | Share settings that arrive from outside (INT-08.31) | (a) a share runs only after an approval record outside the vault matches its mode and resolved path; (b) as the reference: active as soon as the item is in the vault | (a). Share settings can make App read from, or write over, a path someone else chose (AT-I04). Proven practice for settings that travel with shared data, as in D-INT09-3: VS Code Workspace Trust runs nothing from a folder until the user trusts it (https://code.visualstudio.com/docs/editing/workspaces/workspace-trust); direnv blocks an `.envrc` until `direnv allow`, keeps the approval outside the folder and blocks it again after a change (https://direnv.net/man/direnv.1.html) |
| D-INT08-5 | Share items inside a container (INT-08.33) | (a) never write them, drop them on import; (b) as the reference: a nested share travels with its path and password | (a). A nested item hands its share password to every member and can point each importer at a path the exporter chose (AT-I04), which D-INT08-4 would then have to catch; the reference's user guide does not mention nested shares. No outside source |
| D-INT08-6 | Encryption of a container (INT-08.14) | (a) the source vault's cipher and KDF settings with a fresh seed; (b) as the reference: AES-256 with AES-KDF 1,000,000 rounds, version 3.1 | (a). A container holds the same secrets as the group it copies, so it should cost an attacker as much as the vault does; OWASP's Password Storage Cheat Sheet recommends a memory-hard function (Argon2id) over iterated rounds (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). The reference reads version 4 containers, so members on the reference lose nothing |
| D-INT08-7 | Two importing shares on one path (INT-08.18) | (a) warn and import into none of them until it is fixed; (b) as the reference: warn and import into the last one set up, whichever share asked | (a). With (b) changes meant for one group land in another without notice. No outside source |
| D-INT08-8 | Shares in the recycle bin, and the bin in a root export (INT-08.35) | (a) a share in the bin is inactive; a root export leaves the bin and recycled objects out; (b) as the reference | (a). Moving a group to the bin is a delete; App already leaves bin items out of its features (MOD-04.14), and recycled data should not travel to members. No outside source |
| D-INT08-9 | A Synchronize export when another member wrote the file since the last import (INT-08.37) | (a) import first when the file changed, then write; (b) as the reference: overwrite | (a). With (b) the other member's changes vanish from the file until that member saves again. No outside source |
| D-INT08-10 | Default of "hide sync success messages" (INT-08.7) | (a) on, and the screen shows and keeps the stored value; (b) as the reference: stored off, while its screen shows it ticked after every start | (a). The reference's users see it on after every start (INT-08.7), so (a) matches what they see and then keeps their choice |

Outside practice (AGENTS rule 9; review R08-2). D-INT08-2, D-INT08-5, D-INT08-7, D-INT08-8, D-INT08-9 and D-INT08-10 are App's own choices, made for the reasons in each row (safety, no silent data loss, clear settings). No comparable outside practice exists for them: groups shared through a plain file exist only in the reference, and the password managers that share (for example Bitwarden organizations and Proton Pass shared vaults) do it through their own servers, which keep the members and their rights, so there is nothing of their kind to follow. "No outside source" in a row means this.

## Security notes

- **What the reference does not protect (SI-09).** Signatures are written but never checked; any holder of the share password who can write the file location can change what every importer gets. App: INT-08.31 approval plus, with option b, verification and trust per signer (INT-08.29).
- **Merge reach.** In the reference a container can move or overwrite any entry of the importing vault whose id it carries, and erase entries anywhere in it (MOD-11.15). Ids leak to every share member (they are in every container). This must never happen in App: INT-08.32 and D-11-9.
- **Settings arriving from outside.** A share item copied in by a merge or by another container becomes active at once in the reference: it can import from, or export the group to, a path someone else chose, overwriting any file the user can write (AT-I04); confirmed in E11-S1: a share item that arrived inside a container the reference made ran an import in the same run. App: INT-08.31, INT-08.33, INT-08.34.
- **Share password storage.** The password sits base64-encoded (readable) in the group custom data inside the vault, not as a protected field (FMT-14.17), and the reference copies nested share passwords into containers. App never exports it (INT-08.33) and holds it in a secret type (INT-08.39); it must never reach logs (SR-14, AT-C06).
- **Deletion history leak.** Every container carries the whole deleted-objects list of the source vault, so members learn when unrelated items were deleted (FMT-15.12, accepted). The Sharing page says so in one help line.
- **Hostile container.** A KDF cost bomb, decompression bomb or crafted document must not hang or crash App (AT-A05, AT-A06, AT-A08, AT-A10). The reference runs imports on its main thread, so a slow container freezes it; App does not (INT-08.38).
- **Old signed files.** Reference versions before 2.7.0 published the signer's private key in every signature file. App never treats such a key as proof of anything (INT-08.29) and never writes a private key into a container.
- **Signing key storage.** The reference keeps the RSA private key unencrypted in its settings file (twice). With option b, App keeps it only in the Keychain (INT-08.30).
- **Text from containers.** Group names, entry fields and paths are untrusted text shown as text only (AT-E01).
- **File writes.** Containers are written atomically with owner-only permissions (SD-01, SD-09, AT-I06); the reference writes signed containers non-atomically, so a reader can see half a file. Reference file modes (E11-S1): unsigned containers 0600 (atomic save), signed containers 0644 (written straight onto the path under the umask), so other accounts on the Mac can read a signed container. App writes every container 0600 (T11).

## Test cases

V holds root(01) → Team(20) → Mail(0A) {title `Mail`, user `ann`, password `pw-1`, Mod T0}, Bank(0B) {password `pw-b`, Mod T0}; Team → Sub(21) → Wiki(0C). Share password `demo-share-1`. Container path `team.appvault` (resolves to `/tmp/spec-int08/team.appvault`). Both allow settings on unless a case says otherwise. "Reference" cases run the reference app with a throwaway settings folder (LD-34); the rest run App.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-08.1 | V with the share item on Team, none on Sub | Ask which groups are shared | Team and Sub are shared; root, Mail's group parent root not; Team is the share group |
| T02 INT-08.2, INT-08.3 | Share: Synchronize, Group id 16×0x11, path `team/shared.appvault`, password `demo-share-1`, keep on | Write the item, base64-decode the value | Text equals `<?xml version="1.0"?>` + root (`4B 65 65 53 68 61 72 65`) + `<Type><Import/><Export/></Type><Group>EREREREREREREREREREREQ==</Group><Path>dGVhbS9zaGFyZWQuYXBwdmF1bHQ=</Path><Password>ZGVtby1zaGFyZS0x</Password><KeepGroups>True</KeepGroups>` + root end tag; no whitespace |
| T03 INT-08.3 | Item: Import only, Group 16×0x22, path `../in.appvault`, password empty, keep off | Write, decode | `<Type><Import/></Type>`, `<Group>IiIiIiIiIiIiIiIiIiIiIg==</Group>`, `<Path>Li4vaW4uYXBwdmF1bHQ=</Path>`, `<Password></Password>`, `<KeepGroups>False</KeepGroups>` |
| T04 INT-08.3 | XML with children in order Password, Path, Type, an unknown `<X><Y/></X>`, no KeepGroups | Read | Same password, path, mode as written; keep group structure off; X ignored |
| T05 INT-08.3, INT-08.4 | Root element named `Share` instead of the encoded name | Read | Invalid: group shared, never imports or exports, label MI08-25 |
| T06 INT-08.4 | Mode Export, path empty | Save V | Nothing exported; not importing, not exporting, not valid |
| T07 INT-08.5 | Path `team.appvault`, V at `/tmp/spec-int08/v.appvault` | Export | File `/tmp/spec-int08/team.appvault` written; with the folder `/tmp/spec-int08/~` made first, path `~/team.appvault` writes `/tmp/spec-int08/~/team.appvault` (reference; App the same); without that folder the export fails with MI08-03 and the system's reason |
| T08 INT-08.6 | Share password empty, export to `team.appvault` | Open the container in App's tool with "empty password", then with "no password" | Empty password opens it; no password gives `NoCredentials` before the KDF (LD-13, FMT-04.16). Reference-made (E11-S1): kept file e opens in App's tool with an empty password and lists Em1 |
| T09 INT-08.7 | Fresh App settings | Read the three settings | allow import off, allow export off, quiet success on |
| T10 INT-08.7 (reference) | Fresh reference settings folder | Open the sharing settings, untick "only warnings", press OK, reopen in the same run; quit, start again, open the page, press OK | Same run: still unticked. After the restart: ticked; after that OK the stored value is quiet. Open: needs the reference window, owner's go (rule 10, W-08) |
| T11 INT-08.8, INT-08.12 | Team share Export, keep on | Save V; open `team.appvault` with `demo-share-1` | Vault name `Team`; root id(20) named Team without the share item; Mail, Bank with ids, passwords and history; Sub(21) with Wiki; recycle bin off; the file's mode is 0600 (SD-09). Reference: the content is confirmed in E11-S1 (the vault entry of kept file a); its file modes differ (Security notes, File writes) |
| T12 INT-08.12 | Same, keep off | Save V; open container | Root holds Mail and Bank only; no Sub, no Wiki. Reference: confirmed in E11-S1 (kept file c, its own demo vault: P1 only, no subgroup) |
| T13 INT-08.12, INT-08.33 | Sub also holds a share item (Import, path `x.appvault`, password `p`) | App export of Team | No group in the container holds the share item. Reference export: Sub in the container carries Sub's item with password `p` (confirmed in E11-S1, kept file a) |
| T14 INT-08.9 | Reference-made signed containers: kept files a and b, rebuilt from their hex | List the zip | Two entries in order: `container.share.signature`, then the encoded vault entry name; both deflated, flags `0x0002`, time and date 0, no data descriptor; each local header has version needed 45, a 20-byte ZIP64 extra field (id `0x0001`, 16 zero bytes) and the real sizes in its own fields; the central directory has version needed 20, made by 0 and no extra fields; one plain 22-byte end record; no ZIP64 end record or locator (confirmed in E11-S1) |
| T15 INT-08.9 | Zip with entries `a.txt` and the vault entry holding V's container | App import | Imports; `a.txt` ignored |
| T16 INT-08.9 | Zip with the vault entry twice | App import; reference import | App: MI08-04, nothing merged. Reference: second entry used (confirmed in E11-S1) |
| T17 INT-08.9 | File starting `25 50 44 46` (a PDF) at the share path | App import | MI08-04; Team unchanged |
| T18 INT-08.10 | Demo RSA-2048 key made with `openssl` in `/tmp/spec-int08/`, e = 65537 (App builds no signature, D-INT08-1 (a): this case checks the layout facts with `openssl` and python only, not App code) | Build the blob and the signature text for a demo container | Blob 278 bytes starting `00 00 00 07 73 73 68 2D 72 73 61 00 00 00 03 01 00 01 00 00 01 00`; `Key` base64 372 chars starting `AAAAB3NzaC1yc2EAAAADAQABAAABA`; `Signature` = `rsa|` + 512 lowercase hex digits; `openssl dgst -sha256 -verify` with that key accepts it over entry 2's bytes. Reference-made (E11-S1): kept file a's signature text has this layout and verifies over its entry 2 the same way; kept file b (empty signer name) has a 0-byte signature entry |
| T19 INT-08.11 (reference) | Path ends with the signed suffix in capitals | Reference export | Plain vault file (starts `03 D9 A2 9A`), not a zip (confirmed in E11-S1: kept file d) |
| T20 INT-08.13 | Team → Alias(0D) password `{REF:P@I:0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B}` (in scope); Team → Alias2(0E) password `{REF:P@I:` + id of an entry Home(0F) outside Team (password `pw-h`) + `}` | Export Team | Container: Alias keeps the reference; Alias2 keeps `{REF:P@I:0F0F…}` as written, still protected; their history and modification times unchanged; Home and `pw-h` are not in the container (LD-279 (1)). Reference (E11-S1, kept file a): Alias2 password `pw-h` plus one new history item holding the `{REF:P@I:0F0F…}` text, modification time = export time; the source vault unchanged |
| T21 INT-08.14 | Reference export of a Team share with no 4.x content | Read container header | Version 3.1, AES-256, AES-KDF 1,000,000 rounds, gzip (confirmed in E11-S1: kept files c, d and e; the vault entry of kept file a is 4.0, because a copied group holds custom data) |
| T22 INT-08.14 | V uses Argon2id 64 MiB, 3 iterations, parallelism 4, ChaCha20 | App export | Container 4.x, ChaCha20, Argon2id with the same costs, salt not equal to V's |
| T23 INT-08.15 | Import share in V; container has Mail with password `pw-2`, Mod T1 | Unlock V | Mail password `pw-2`, history holds `pw-1`; MI08-01 shown only when quiet success is off |
| T24 INT-08.15 | V open, share Import set up; another process rewrites the container with a new entry News | Wait 31 s with notices off (polling only) | News appears in Team |
| T25 INT-08.15 | Container rewritten changing only byte 6,000 (crafted) | Wait 31 s | No import (first 5 KiB unchanged) |
| T26 INT-08.15 | Share item edited: only keep group structure changed | Accept the group edit | No import pass is started for that change |
| T27 INT-08.16, INT-08.6 | Container made with password `other` | Import | MI08-02 with the reader's wrong-key reason; Team unchanged |
| T28 INT-08.16 | Container identical in content to Team | Import | No change, no message, V not marked changed |
| T29 INT-08.17 | Export share, allow export on | Save V three times without changes | Container rewritten three times; no import triggered by those writes |
| T30 INT-08.17 | Allow export off | Save V | Container untouched |
| T31 INT-08.18 | Team and Other(22) both Export to `team.appvault` | Save V | No container written; one MI08-06 naming Team and Other |
| T32 INT-08.18 | Team and Other both Import from `team.appvault` | Unlock V | Reference: MI08-05; both passes merge into the same one group. App: MI08-05; neither group changes |
| T33 INT-08.19 | Synchronize share; merge dialog open | Container changes; then close the dialog | No import and no watcher event while the dialog is open; after it closes, one import pass brings the change in |
| T34 INT-08.20 | One import success, one export failure, quiet success on | Pass ends | One error banner holding only the failure line |
| T35 INT-08.21 | New group G, Sharing page | Read fields; pick Type Import | Type Inactive, keep ticked, path/password/browse disabled; after Import all enabled |
| T36 INT-08.21 | Share Team set up | Press Clear, accept | Team has no share item; badge gone |
| T37 INT-08.22 | Browse with Type Export; user types `shared` | Save chooser closes | Path field `shared.appvault`; typed `shared.` gives `shared.appvault` |
| T38 INT-08.23 | Path `team.txt` | Show page | MI08-10 only |
| T39 INT-08.23 | Other exports `team.appvault`; Team set to Export same path | Show page | MI08-11 |
| T40 INT-08.23 | Allow import on, export off; Team Synchronize | Show page | MI08-16 is not shown; MI08-15 shown ("export is off") |
| T41 INT-08.24 | Team Import, allow import off | Show tree, select Sub | Team has the inactive badge; Sub no badge; label under list: "Shared: imports from team.appvault" and, on the next line, "Import is turned off in App's settings." |
| T42 INT-08.24 | Team share Inactive with a path | Select Team | Label MI08-25: "Sharing is off for this group: its settings are inactive or cannot be read." |
| T43 INT-08.25 | Shares on Team and Sub | Open vault settings, Shared groups | Rows `Team` and `Team > Sub` with mode and path; table read only |
| T44 INT-08.26 | D-INT08-1 option a | Open app settings, Shared groups | Three tick boxes; no signer, fingerprint or Generate |
| T45 INT-08.27 (reference) | Signed container whose `Signature` text is `rsa|00` | Reference import | Imports (signature ignored; confirmed in E11-S1) |
| T46 INT-08.28 | Option a; path ends with the reference signed suffix | App export | Plain vault file at that path; reference import of it succeeds |
| T47 INT-08.29 | Option b; container signed by a demo key K1; no records | Import | MI08-22 banner; Team unchanged until answered; Trust always stores (path, fingerprint of K1) → Trusted and merges |
| T48 INT-08.29 | Option b; record Trusted for K1; container now signed by K2 | Import | MI08-22 again for K2 |
| T49 INT-08.29 | Option b; one byte of entry 2 flipped after signing | Import | MI08-20; no question; Team unchanged |
| T50 INT-08.29 | Option b; `Key` holds a PKCS#8 private key | Import | MI08-21, then the unsigned question |
| T51 INT-08.30 | Option b | Write first signed container; list Keychain and App settings files | One Keychain item under `com.app.vault`; no private key bytes in any settings file or in V |
| T52 INT-08.31 | V2 (another demo vault) gets Team with an Export share to `/tmp/spec-int08/victim.txt` by merge from a crafted vault | Save V2 | `victim.txt` untouched; Team shows MI08-18; after Approve, the next save writes the container |
| T53 INT-08.32 | V: Home(30) → Bank(0B) password `pw-b` Loc T0 Mod T0, outside Team. Container holds Bank(0B) password `evil` Mod T2 Loc T2 | App import into Team | Bank stays in Home with `pw-b`; MI08-19 with count 1. Reference: Bank moved into Team with password `evil` |
| T54 INT-08.32 | Container deleted objects: [id(30) T2]; Home(30) empty, outside Team | App import | Home kept (D-11-9 scope) |
| T55 INT-08.33 | Container (crafted) whose child group carries a share item Export to `x.appvault` | App import | The group arrives without the share item; no file `x.appvault` after the next save |
| T56 INT-08.34 | Team Export path `v.appvault` (V's own file) | Save V | V intact and still opens with `demo-v`; editor MI08-17; nothing exported |
| T57 INT-08.35 | Team moved to the recycle bin, share Export | Save V | Container not rewritten (file time unchanged). Reference: rewritten |
| T58 INT-08.36 | Container with Argon2 memory 4 TiB in its KDF map | Unlock V | MI08-02 at once, no question, no memory growth |
| T59 INT-08.36 | Zip whose vault entry inflates to 8 GiB | Import | Stopped at the vault file limit (FMT-01.31), TooLarge reason in MI08-02; memory flat |
| T60 INT-08.37 | Synchronize; person B exported entry Pay since V's last import; watcher not yet fired | Save V | V first imports Pay, then writes the container; the container holds Pay |
| T61 INT-08.38 | Container with Argon2 cost taking 3 s | Import while the user types in the entry editor | Typing never stalls |
| T62 INT-08.39 | Debug log at highest level during T23 and T29 | Search logs for `demo-share-1` | Not found |
| T63 INT-08.39 | New share with empty password | Accept group edit | MI08-23 shown; share still saved |
| T64 INT-08.40 | V with an Export share | `app` tool edits an entry and saves | Container untouched |
| T65 INT-08.3 | Two new groups G1 and G2 in V | On each Sharing page pick Type Import and type a path; accept both edits; decode both items | The two `Group` ids differ and neither is 16 zero bytes. Reference (source; open: needs the reference window, owner's go (rule 10, W-08)): both carry the same id |
| T66 INT-08.9, INT-08.10 (LD-267 (5)) | Kept files a and b, rebuilt from their hex | Read each with App's zip container reader (app-core's ZIP reader, E11-S2); open the vault entry with `demo-share-1` | a: entries signature (1,020 bytes), then vault (2,279 bytes, starts `03 D9 A2 9A`), CRC-32 checked; b: the same with a 0-byte signature entry; each vault: name Team, version 4.0, root id(20) with Mail, Bank, Alias, Alias2, and Sub(21) with Wiki |
| T67 INT-08.14, INT-08.36 (LD-281 (1)) | V uses Argon2id with 64 MiB, 1 iteration and parallelism 129, set by the user (the ask band of CRY-02.14: P > 128); a second demo vault W has a group with an approved Import share on the same path | App exports Team from V; then W unlocks and imports | The export asks nothing; the container's KDF map holds Argon2id, 64 MiB, 1 iteration, parallelism 129, with a salt not equal to V's; W shows MI08-02 at once, with no question and no KDF work; that group of W unchanged |
| T68 INT-08.16, MOD-08.32 (LD-279 (2), F-142) | Member A adds to Team the entry Team wiki(44) with password `{REF:P@U:ann@example.com}` and URL `https://evil.example/login` and exports; member B's vault is V plus Home(30), outside Team, with Gmail(0F): user `ann@example.com`, password `gmail-secret-demo`; Team holds Alias(0D) as in T20 | B imports; resolve Team wiki's password (copy, display, fill for `https://evil.example/login`, Auto-Type) and Alias's password | Team wiki's password resolves to empty every time, never `gmail-secret-demo`; Alias gives `pw-b`. The full case: MOD-08 rows 08-63 and 08-64 |

Reference-made containers (E11-S1, LD-267 (6)), kept for E11-S2 and E11-S6 in `crates/app-core/tests/data/int08/` (app-core owns the ZIP reader, LD-142 (2); E11-S2 may move them into app-share's own `tests/data/` and then updates this list). Made 2026-10-31 by the reference 2.7.11, run hidden with a throwaway settings folder, from demo vaults made by its command line tool. The two zips are stored as hex text (`.zip.hex`: uppercase byte pairs with one space between pairs, 32 pairs per line), because their member name and signature text hold banned words (name rule); a test rebuilds the bytes with a hex decode and checks the SHA-256 below. The vault files are stored as they are: the reference's generator name and share key names inside their encryption are the F-116 class, accepted (LD-225 (2)).

| File | Kind | Share password | Content | SHA-256 of the bytes |
|---|---|---|---|---|
| a `ref-2.7.11-signed-export-team-keepgroups-on.zip.hex` | signed (exact suffix), keep on, signer `demo-signer` | `demo-share-1` | vault entry 4.0: Team(20) with Mail(0A) `ann` `pw-1` (history `pw-0`), Bank(0B) `pw-b`, Alias(0D) `{REF:P@I:0B0B…}`, Alias2(0E) `pw-h` with the added history item (INT-08.13), Sub(21) with its share item (Import, password `p`) and Wiki(0C) `pw-w`; deleted object id(99) at 2026-01-15 | `e448ac54916de512abc287a7c3480dd985bab2ab61f4e7981aa93e2c290e7951` |
| b `ref-2.7.11-signed-export-team-empty-signer-name.zip.hex` | signed, as a, with `USER` and `USERNAME` empty | `demo-share-1` | as a; the signature entry is 0 bytes | `9860614cb686349442febd4815585d887ea89431cbd05b0d0f69da7f5c9db86a` |
| c `ref-2.7.11-unsigned-export-plain-keepgroups-off.appvault` | unsigned, keep off | `demo-share-2` | 3.1: Plain(22) with P1(10) only; its subgroup left out | `f2886a3e169513d1b5057b16c6f79a509738af16aad651eb8c21bc6484c65e89` |
| d `ref-2.7.11-unsigned-export-capital-signed-suffix.appvault` | unsigned: the signed suffix in capitals (T19) | `demo-share-3` | 3.1: Caps(24) with C1(12) | `d12f98a366bd905fb9845c327073ca3fa32d61a54a0420e230510470f102a629` |
| e `ref-2.7.11-unsigned-export-empty-share-password.appvault` | unsigned, empty share password (T08) | empty | 3.1: Empty(25) with Em1(13) | `e37593e8cbdd0f2925fd459c87b5ef7364117bbeead5769003d04884a3a82fa6` |

## Owner summary

Size: medium to large. Shared groups need a group settings page, an app settings page, a file watcher per share, an export writer, a small zip reader and writer, and the merge from E4 with extra limits. About three stories without signatures; signatures and a trust list add one more story and a new RSA crate with a known timing advisory.

Risks, in plain words:
- In the reference, a share file can change or pull out any entry of your vault whose id it knows, not only the shared ones, and can delete entries anywhere. App must limit it to the shared group (INT-08.32).
- Share settings can arrive inside someone else's file and make the app read from, or write to, a path that person chose, even over another file. App asks first (INT-08.31).
- The share password sits readable inside the vault, and the reference copies nested share passwords into the files it writes.
- The reference writes signatures but never checks them, so anyone with the share password and write access to the folder can change what everyone receives. Old reference versions even put the signer's private key inside every signed file.
- Every share file reveals when unrelated items were deleted from the source vault.

Recommendation: build Import, Export and Synchronize with unsigned files and App's safety rules (D-INT08-1 option a). Add signatures and per-person trust only if the owner wants protection against other share members.

Decided 2026-10-31 (W-15, LD-262 (6)): shared groups are built in E11 as recommended, with unsigned files (D-INT08-1 (a)); remote sync by commands (INT-09) is not built.

## How this was learned

- Read in the reference source: the sharing folder (the plug-in's main class with its settings readers and writers, the export routine with its reference resolving and zip writing, the import routine with its zip reading, the observer that sets up watchers, imports and exports, the app settings page, the vault settings page and the group editor page with their screen definitions); the custom data class; the group's shared check; the version 4 writer's attachment namespacing; the merge routine's constructors and lookup; the file watcher; the vault class defaults (cipher, compression, default KDF); the clone routines; the placeholder type routine; the main window and vault widget hooks (merge pause, label, menu, badge); the user guide pages on sharing.
- Read the reference tests: the sharing serialization test and the version 4 attachment index test with a simulated shared group.
- History of the reference source: the commit before 2.7.0 that removed signature checking, for the old trust list, the old ask dialog and the old signature file content (INT-08.27).
- Compared the source with the installed version's tag: the only behavior difference in sharing is the attachment namespace (FMT-13.17).
- Searched the installed app binary (2.7.11) for the sharing texts and settings names: present, with no trust dialog texts. The first draft did not launch the window or run anything; E11-S1 then ran the reference hidden (see "E11-S1 check").
- Computed T02, T03 and T18 values with python3 in `/tmp/spec-int08-int09/`.
- Checked with Verify in E11-S1 (2026-10-31): the XML declaration text (INT-08.3); the zip64 fields (INT-08.9); the success-message setting quirk (INT-08.7, T10); part of the runtime behaviour; see "E11-S1 check".
- Lead decisions: D-INT08-1 signatures, D-INT08-2 extensions, D-INT08-3 import scope, D-INT08-4 approval, D-INT08-5 nested share items, D-INT08-6 container encryption, D-INT08-7 two importers on one path, D-INT08-8 recycle bin, D-INT08-9 import before export, D-INT08-10 quiet success default. All ten were taken by the default rule on 2026-10-31 (LD-61 for D-INT08-3).

## Review 2026-10-28

Second Spec review, together with INT-09. Checked against the reference source at the studied commit: the sharing folder (settings reader and writer, the export routine with its reference resolving, zip writing and signing, the import routine with its zip reading, the observer with its watchers, conflict checks, messages and export order, the app settings page, the vault settings page, the group editor page and its browse and warning logic), the group icon and label code, the file watcher, the vault defaults (cipher, compression, default KDF and rounds), the merge dialog's sharing pause, the configuration keys, and the user guide's sharing pages; the installed version's tag for the empty-settings value. Recomputed with python3 in a private `/tmp` folder (deleted after): every base64 value of T02 and T03, the public key blob size, start and base64 length of INT-08.10 and T18, and `SHA-256("")` of INT-08.6. Every rule has a test case; every card, LD and parity row it names exists.

Fixes made (12): the decision IDs D-08-1 to D-08-10 became D-INT08-1 to D-INT08-10, because MOD-08 already uses D-08-1 to D-08-11; a "Lead decisions" section now lists each decision with its options, recommendation and evidence (outside sources for D-INT08-1, D-INT08-4 and D-INT08-6); INT-08.16 and INT-08.32 say D-INT08-3 is decided (LD-61: Conflict record; LD-130: the container's own bin is an ordinary group); INT-08.3 says a missing `Group` makes the reference set the share up again and import it at every change of the vault; INT-08.3 says the reference gives every share created in one run the same `Group` id, and App a random id per share (new T65); INT-08.15 step 4 says the reference sets shares up again only when both allow settings were off; INT-08.19 defines App's pause (no watcher events, one import pass when the dialog closes; T33 extended) and states the reference's weaker pause; INT-08.23 says the warnings show only while Type is not Inactive; INT-08.27 says the reference's user guide still claims signer checking; INT-08.31 defines the vault id as the root group's id (as INT-09.20 and INT-01.31); a new edge case covers the reference's Latin-1 conversion of signed container paths; T07 makes the `~` folder first and says what happens without it.

Findings, each with a proposed ruling (the default rule of spec/decisions.md applies until the lead rules):

| ID | Finding | Proposed ruling |
|---|---|---|
| R08-1 | Cards disagree on signatures. MOD-11's security notes say "Synchronize mode is used only for signed, trusted shares (INT-08)" and plan/security.md SI-09 says App "verifies signatures, with trust per signer", while this card recommends D-INT08-1 (a): no signatures, with Synchronize on unsigned files guarded by INT-08.31 and LD-61. | Rule D-INT08-1 (a), then change MOD-11's line to "Synchronize runs only for approved shares (INT-08.31) and only inside the share group (LD-61)" and SI-09's App column to approval plus import scope, with signatures as option (b). |
| R08-2 | D-INT08-2, D-INT08-5, D-INT08-7, D-INT08-8, D-INT08-9 and D-INT08-10 cite no outside source (AGENTS rule 9). File-based shared groups exist in the reference only; the password managers that share do it through their own servers. | Accept them as App safety choices with the reasons given, and say in the card that no comparable outside practice exists for file-based shares. |
| R08-3 | The Messages table says "Paraphrased; App wording may differ" and has no reference column, unlike INT-06, INT-07 and INT-09; MI08-01 to MI08-03 and the labels of INT-08.24 use different words for the same thing ("Brought in changes" and "Shared in from"). Builders and the Option A frames need final text. | The writer gives App's final text for every MI08 row and adds the reference's text for comparison (the reference's texts were read in this review: "Imported from ‹path›", "Import from ‹path› failed (‹reason›)", "Export to ‹path› failed (‹reason›)", "Multiple import source path to ‹path› in ‹groups›", "Conflicting export target path ‹path› in ‹groups›"). |

Findings fixed 2026-10-28 (the writer, each re-checked in the reference source at the studied commit):
- R08-1: the import routine still takes only the vault entry of a zip and ignores the signature file. D-INT08-1 itself waits for the lead (default rule of spec/decisions.md); the cards now agree under either option: MOD-11's security note says Synchronize runs only for approved shares (INT-08.31) and only inside the share group (LD-61), with the trust list (INT-08.29) added only with option (b), and plan/security.md SI-09's App column says the same.
- R08-2: a note under Lead decisions says that D-INT08-2, -5, -7, -8, -9 and -10 are App's own choices and that no comparable outside practice exists for file-based shares.
- R08-3: the Messages table gives App's final text for every row, with kind, rule and the reference's text (re-read in its sharing folder: the observer, import, export, label and group editor); the labels of INT-08.24 became MI08-24 and MI08-25 and reuse MI08-15 and MI08-16, so one set of words (import, export, sync) runs through the banner, the editor and the label; INT-08.14 names MI08-07; T05, T41 and T42 use the new texts.

## E11-S1 check 2026-10-31

A Verify agent checked the card's "check with Verify" markers: the reference source read only, the reference 2.7.11 run hidden with a throwaway home and settings folder (rule 10), demo vaults made by its command line tool. A Spec agent wrote the results into this card. Proof: the bytes of the containers the reference wrote (kept, see the list under Test cases); source lines at the studied commit; app-core's ZIP reader, unchanged, in a private copy of the tree, read both zips (the vault entry equal to an independent extraction, CRC-32 checked); App's command line tool opened the three unsigned files with their share passwords (file e with an empty password) and the vault entry of both zips with `demo-share-1`.

| Marker | Result | Where |
|---|---|---|
| XML declaration (INT-08.3) | Confirmed from reference bytes; the share item itself and the empty password element are from the source | INT-08.3, T02, T03 |
| Success-message setting (INT-08.7) | Confirmed from the source, with one correction: the box keeps the user's choice within one run and shows ticked again only after a restart | INT-08.7, T10 |
| T10 | Open: needs the reference window, owner's go (rule 10, W-08) | T10 |
| zip64 fields (INT-08.9) | Corrected, made exact: a zeroed 20-byte ZIP64 extra field in every local header, none in the central directory or the end record | INT-08.9, T14, T66 |
| LD-267 (5): ZIP64 end or central records | None. app-core's ZIP reader reads the reference's zips unchanged, so LD-142 (2) needs no ruling | INT-08.9, T66 |
| Runtime behaviour that runs without a window | Confirmed: INT-08.6 (T08), INT-08.9 reading (T15, T16, T45), INT-08.10 (T18), INT-08.11 (T19), INT-08.12 (T11 to T13), INT-08.14 (T21), INT-08.15 steps 1 and 3, INT-08.17, a share item from a container active at once (Security notes) | each rule |
| INT-08.13, reference behaviour | Corrected: the reference adds a history item to a resolved entry and sets its modification time. App's rule changed after (LD-279 (1)): App resolves nothing on export | INT-08.13, T20 |
| INT-08.10 signer name; file writes | Added: an empty signer name gives a 0-byte signature entry, else the signer is the account name in plain text; the reference writes signed containers 0644, unsigned 0600 | INT-08.10, Security notes, T11, T18, T66 |
| Runtime behaviour that needs the window | Open, with the reason "needs the reference window, owner's go (rule 10, W-08)": T10; the reference half of T65; INT-08.15 steps 2 and 4; INT-08.18's messages; INT-08.19; INT-08.20; the screens INT-08.21 to INT-08.26 and the reference texts of the Messages table | each rule |
| Not run in E11-S1 (from the source only; can run hidden later, E11-S6) | INT-08.2 lenient read; INT-08.3 missing Group; INT-08.5 (T07); INT-08.18 (T31, T32); INT-08.32 (T53); INT-08.34; INT-08.35 (T57); the Latin-1 path edge case | each rule |
| Not timed | INT-08.15's 30-second check, 5 KiB hash and 100 ms delay; App's own rule has T24 and T25 | INT-08.15 |

D-INT08-1 to D-INT08-10 are taken by the default rule (LD-61 for D-INT08-3): see "Lead decisions". None of the open items blocks E11-S2: they are reference behaviour on screen or in E11-S3's triggers, and each App rule has its own test case. No INT-09 rule was changed (LD-262 (6)).
