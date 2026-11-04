# FMT-16 Choosing the file version on save

Status: reviewed
Epics: E3-S7
Parity rows: SF-02, SF-05, SF-06, SF-07, SF-14, SD-06

## What it does

Every save writes a file version (FMT-01.6). The reference picks the lowest version that can hold everything the vault uses, but never goes below the version it has recorded for the vault, and never below 3.1. This card gives the reference's exact rule, what each version can and cannot hold, and what happens to data a lower version cannot hold.

The last section, "What App does", gives App's rule: App writes only version 4 (4.0 or 4.1, and a higher 4.x only to keep unknown parts of such a file), uses the reference's 4.0 versus 4.1 rule plus the extra 4.1 triggers that make it lossless, and says what App writes where the reference would write 3.1.

Terms:

- Recorded version: a version number the reference keeps with the open vault (FMT-16.2). It is not stored anywhere except as the version field of the file.
- Legacy AES-KDF: AES-KDF as a version 3 file holds it, through header fields 5 and 6 (FMT-17). Internally the reference marks it with the id `C9D9F39A-628A-4460-BF74-0D08C18A4FEA`.
- Version 4 AES-KDF: the same AES-KDF computation, held in the KDF map of a version 4 file (FMT-03). Internally the reference marks it with the id `7C02BB82-79A7-4AC0-927D-114A00648238`, but in the file it still writes `C9D9F39A-...` in the map (FMT-03). The computation is identical; only where the settings live differs.
- Current entry: an entry in a group. History entry: an older copy kept inside an entry's history (MOD-03).

## Inputs and outputs

Input: the vault model at save time: KDF, public custom data, every group (root included) with its custom data, tags and previous-parent reference, every current entry and its history entries with their custom data, report-exclusion flag and previous-parent reference, the custom icons with their names and modification times; (reference only) the recorded version; (App only) whether the vault still holds kept unknown document parts, and the version of the file it was read from (FMT-16.24).

Output: the version to write, as (major, minor): 3.1, a 3.x kept from the file, 4.0 or 4.1 for the reference; 4.0 or 4.1 for App, or the 4.x version read under FMT-16.24. Also a possible KDF change: for the reference FMT-16.12, for App FMT-16.21.

## Rules

### The reference's rule

FMT-16.1 Start at 3.1. The reference never writes 3.0 or 2.x.

FMT-16.2 Raise to the recorded version. The recorded version is set:

- when a file is read: to the file's version field. For version 4 files the reference then overwrites it while it reads the KDF header field (field 11), with the result of this rule for a still-empty vault, which is always 4.0. So after opening, every version 4 file has recorded version 4.0, whatever its version field said (observed: files stamped 4.1, 4.2 and 4.65535 with no version 4.1 content were all saved back as 4.0). Version 3 layout files keep their version field: 2.x and 3.0 are below the 3.1 start and so are saved as 3.1; a 3.x with x of 2 or more is saved with that same x (observed: 3.0 and 2.0 and 2.1 were saved as 3.1; 3.2 as 3.2; 3.65535 as 3.65535).
- when the KDF is changed (by the user, the command line `-t` option, or FMT-16.12): to the result of this rule computed without the recorded version (FMT-16.15).
- after every save: to the version just written.
- after every XML export (FMT-16.17): to the version the export used, which this rule computes including the recorded version, so it is never lower than before (source, re-read by Verify: the export step stores, as the recorded version, the result of this rule computed with the recorded version included).

A new vault starts with no recorded version (zero).

FMT-16.3 Raise to 4.0 when the vault's KDF is anything but the legacy AES-KDF (Argon2d, Argon2id, or version 4 AES-KDF). Because a version 4 file's AES-KDF is always read as version 4 AES-KDF, every vault read from a version 4 file meets this rule.

FMT-16.4 Raise to 4.0 when the public custom data (header field 12, FMT-02) is not empty. The reference keeps there, for example, the name, color and icon shown on its unlock screen and the id used for quick unlock.

FMT-16.5 Raise to 4.0 when any of these has at least one custom data item (FMT-14): any group, the root group included; any current entry; any history entry.

FMT-16.6 Raise to 4.1 when any group, the root group included, has tags that are not empty.

FMT-16.7 Raise to 4.1 when any group has a previous-parent group reference that points to a group that exists in the vault now.

FMT-16.8 Raise to 4.1 when any current entry is excluded from reports. An entry counts as excluded when its exclusion flag is set, or when its custom data has the key `KnownBad` with the value `true` (an older way to store the same flag).

FMT-16.9 Raise to 4.1 when any current entry has a previous-parent group reference that points to a group that exists in the vault now.

FMT-16.10 Raise to 4.1 when any custom icon has a name that is not empty, or has a last-modification time. Reference: "has a time" means a valid time value. An icon read with a `LastModificationTime` element always gets one: empty text counts as base64 of zero bytes and gives 0001-01-01T00:00:00Z, and text that is neither base64 nor ISO gives the time of loading (FMT-12). Only an icon without the element has no time (from the source). A binary value so large that the toolkit cannot turn it into a date may count as no time in the source build (check with Verify; FMT-12.8). App: an icon has a time when its `LastModificationTime` element was read, whatever the value (0 from empty text and values outside the calendar range included, kept as read per FMT-12.8), or when App set one (FMT-14.4). Any time present raises to 4.1, so App never drops a stored time at 4.0.

FMT-16.11 These never raise the version: vault (metadata) custom data, even with many items; entry tags; attachments; history entries that are excluded from reports or have a previous-parent reference; a previous-parent reference that points to a group that no longer exists; custom data item modification times; the settings-changed time. Some of them are then dropped when the chosen version cannot hold them (FMT-16.13).

FMT-16.12 Writer choice. If the result is 4.0 or higher and the KDF is the legacy AES-KDF, the reference first switches the KDF to version 4 AES-KDF with the same number of rounds and a new random seed, and derives the keys again. (A hardware key response then moves into the composite key, because version 4 uses a different key flow; FMT-04, FMT-17.) It then writes the version 4 layout with the result as the version field. If the result is below 4.0, the KDF is necessarily the legacy AES-KDF and the reference writes the version 3 layout (FMT-17) with the result as the version field.

FMT-16.13 What each version holds. Items marked "dropped" are left out of the file without a message, and are gone when the file is read again.

| Item | 3.1 (version 3 layout) | 4.0 | 4.1 |
|---|---|---|---|
| Time values | ISO 8601 text, for example `2026-10-24T19:10:41Z` | base64 of seconds since 0001-01-01 as i64 LE, for example `sflu4g4AAAA=` for the same time (FMT-12) | as 4.0 |
| Header hash element in the document metadata | written (FMT-17) | not written | not written |
| Attachments | in the document metadata pool (FMT-17, FMT-13) | in the inner header (FMT-09, FMT-13) | as 4.0 |
| Protected-field stream | Salsa20, key in outer header field 8 | ChaCha20, key in the inner header | as 4.0 |
| KDF settings | header fields 5 and 6 | KDF map, field 11 | as 4.0 |
| Settings-changed time in the metadata | dropped | written | written |
| Vault custom data items | written | written | written |
| Last-modification time of vault custom data items | dropped | dropped | written |
| Last-modification time of group and entry custom data items | cannot occur (FMT-16.5) | dropped | reference: dropped (it never writes them, FMT-14.13); App: written (FMT-14.13, decision L1) |
| Group and entry custom data | cannot occur (FMT-16.5) | written | written |
| Public custom data | cannot occur (FMT-16.4) | written | written |
| Group tags | cannot occur (FMT-16.6) | cannot occur | written |
| Entry tags | written | written | written |
| Report exclusion of a current entry | cannot occur (FMT-16.8) | cannot occur | written as `QualityCheck` = `False` |
| Report exclusion of a history entry | dropped | dropped | written as `QualityCheck` = `False` |
| Previous-parent group of a group or current entry, target exists | cannot occur | cannot occur | written as `PreviousParentGroup` |
| Previous-parent group whose target no longer exists, or of a history entry | dropped | dropped | written |
| Custom icon name and last-modification time | cannot occur (FMT-16.10) | cannot occur | written |

FMT-16.14 The rule takes the highest of all raises. Order does not matter. The reference stops checking once it reaches 4.1, which does not change the result.

FMT-16.15 A KDF change re-runs the rule without the recorded version, so it can lower the version. The graphical app's encryption settings offer a "version 3" choice (legacy AES-KDF only). Choosing it on a 4.x vault with none of the features of FMT-16.4 to FMT-16.10 makes the next save write 3.1. When any of those features is present, the app greys out that choice and says the format cannot be changed (source, re-read by Verify; the app was not run: the choice is disabled, with the cannot-change message, when the vault is version 4 and this rule computed without the recorded version and without the KDF gives 4.0 or more; the version 3 choice offers only the legacy AES-KDF, and setting that KDF resets the recorded version to this rule's result without it, so 3.1).

FMT-16.16 Within one session the recorded version never goes down on its own: after a save or an XML export (FMT-16.2) that used 4.1, removing the last 4.1 feature still saves as 4.1 until the vault is closed and opened again (then FMT-16.2 resets a version 4 file to 4.0). (Source, re-read by Verify: a save stores the written version as the recorded version, and the next save takes the highest of the recorded version and the content.)

FMT-16.17 The reference's XML export uses the same rule to choose the time format and other version-gated parts: an export of a vault that would save as 3.1 has ISO times, an export of a 4.x vault has base64 times (observed in exports of demo vaults). Export details are in FEA-09.

### What App does

FMT-16.18 App writes only the version 4 layout, with version 4.0 or 4.1, or a higher 4.x minor only under FMT-16.24. It never writes 3.x or 2.x, and never offers a version 3 choice.

FMT-16.19 App writes 4.1 when any of FMT-16.6 to FMT-16.10 applies, or when the vault holds one of these values, which only a 4.1 file can keep (decided: spec/decisions.md LD-08, the lossless choice):

- a history entry excluded from reports (its flag set; the legacy custom data key is already turned into the flag on read, FMT-14.19, FMT-11.29);
- a history entry with a previous-parent group reference, whether or not that group exists;
- a group or current entry whose previous-parent group reference points to a group that no longer exists (FMT-11.30).

Otherwise App writes 4.0. So App never drops a report-exclusion flag or a previous-parent reference: the FMT-16.13 rows that mark them "dropped" in 3.1 and 4.0 never apply to App. The one thing App still leaves out of a 4.0 file is the last-modification time of custom data items on the vault, groups and entries: item times never raise the version (FMT-16.11). In a 4.1 file App writes item times on every container (FMT-14.13), where the reference writes them only on vault items. History: the other option, dropping what the reference drops, was not chosen, because open, save, open again must keep every piece of user data (plan/architecture.md, `app-format` Must).

FMT-16.20 App does not keep a recorded version. It computes the version from the content at every save, so a file read as 4.1 without 4.1 content is saved as 4.0, and a file with an unknown minor (4.2 and up) is saved as 4.0 or 4.1; the one exception is FMT-16.24 (kept unknown parts). Without kept unknown parts this gives the same file version as the reference after opening a file (FMT-16.2), and can differ from it only within one session (FMT-16.16) or where FMT-16.19 adds a 4.1 trigger.

FMT-16.21 Where the reference would write 3.1 (a vault read from a version 3 layout file, legacy AES-KDF, no feature of FMT-16.3 to FMT-16.10 and none of FMT-16.19), App writes 4.0 instead, and converts the KDF the way the reference does in FMT-16.12: version 4 AES-KDF with the same number of rounds and a new random 32-byte seed (CRY-03, LD-15), stored in the KDF map with the id `C9D9F39A-628A-4460-BF74-0D08C18A4FEA` (FMT-03) (decided: spec/decisions.md LD-07). The protected-field stream changes to ChaCha20 (FMT-09), attachments move to the inner header (FMT-13), times become base64 (FMT-12), the header hash element is not written, and a hardware key response moves into the composite key (FMT-04). The same conversion applies when a version 3 vault is saved as 4.1. The unlock time stays the same. Before the first such save, App tells the user once that the vault moves to the newer format (LD-07; the screen and its message belong to an APP card, saving, APP-05). This rule is the single home of the conversion: FMT-04.18, CRY-02.20 and FMT-17.24 state it by reference. History: switching such vaults to App's default KDF (Argon2id, CRY-02) on the first save was not chosen, because it would change the unlock time without asking.

FMT-16.22 The same applies when App saves a vault read from a 3.x file with x of 2 or more, or from a 2.x file: App writes 4.0 or 4.1 by FMT-16.19 and FMT-16.21 (decided: spec/decisions.md LD-07).

FMT-16.23 App never lowers a vault's protection on save without the user's choice: every save gets the version 4 header HMAC and block HMACs (FMT-05, FMT-06), and the KDF settings stay the same or are raised only by the user (AT-A09, SF-14).

FMT-16.24 Kept unknown parts keep the version (decided: spec/decisions.md LD-09). App remembers, with the open vault, the version of the file it was read from (major and minor; it does not change during the session, except that a merge that copies in kept unknown parts raises it to the source's read version, MOD-11.23, LD-68). When App saves a vault that still holds at least one kept unknown document part (FMT-10.20, FMT-11, FMT-14, FMT-15), the version written is the higher of the FMT-16.19 result and the version read. Examples: read as 4.1, no 4.1 content, an unknown element kept: 4.1. Read as 4.2 with an unknown element kept: 4.2, with every known part written in its 4.1 form (the minor does not change the layout, FMT-01.9; the element gates of FMT-10, FMT-11 and FMT-14 treat any minor of 1 or more as 4.1). Read as 3.x or 2.x: no effect, because App writes 4.0 or more. Without kept unknown parts, FMT-16.19 alone decides. The reference drops unknown parts and so has no such rule (FMT-10.20). History: choosing from known content only was the card's earlier default; it was not chosen, because a file must never claim an older version than the content it carries.

## Edge cases and errors

- A vault read from a 3.1 file whose user adds tags to one group: the reference saves 4.1 and switches to version 4 AES-KDF with the same rounds (observed through import: tags gave 4.1 with AES-KDF and 1,000,000 rounds in the KDF map). App: same.
- A vault whose only custom data is vault custom data (every vault made by the reference's command line tool has such an item): the reference saves 3.1 (observed); App saves 4.0.
- Custom data only on a history entry: the reference saves 4.0 (observed through import). App: 4.0.
- Report exclusion only on a history entry: the reference saves 3.1 and drops it (observed: the export of the saved file has no `QualityCheck`). With root group custom data added: 4.0 and still dropped (observed). With root group tags added: 4.1 and kept (observed). App: 4.1 and kept in all three cases (FMT-16.19, LD-08).
- A custom icon with neither a name nor a time: no raise (reference unit test). Adding a name: 4.1 (reference unit test; observed through import). Only a last-modification time, no name: 4.1 (reference unit test). Removing the name again from an icon that has no time: back to the lower version (from the source; the unit test removes the whole icon instead, which also gives the lower version).
- A previous-parent reference to a deleted group (on a group or current entry), or any previous-parent reference on a history entry: the reference does not raise; it writes the reference only if the file is 4.1 for another reason, and drops it otherwise. App: 4.1 and kept (FMT-16.19, LD-08).
- Root group only with custom data or tags: counts (the root group is included).
- File stamped 4.1 with no 4.1 content: the reference saves 4.0 (observed). App: 4.0.
- File stamped 4.2: the reference opens it and saves 4.0 or 4.1 by content (observed: 4.0). App: same when it keeps no unknown part; with a kept unknown part, 4.2 (FMT-16.24).
- File stamped 3.2: the reference keeps 3.2 on save (observed). App: 4.0 or 4.1.
- Unknown document parts read from a 4.1 or newer file and kept by App (SD-06): App writes at least the version the file was read as (4.1 for a 4.1 file, 4.2 for a 4.2 file), even with no known 4.1 content (FMT-16.24, LD-09). The reference drops the parts and saves 4.0 (observed for an unknown element in the metadata, FMT-10.23).
- A vault read from a 4.1 file with a kept unknown part, saved by App as 4.1, then every kept part removed in the same session (for example the only entry holding one deleted for good): the next save follows FMT-16.19 alone, so 4.0 when no known 4.1 content is left.
- The KDF cannot be the legacy AES-KDF in a version 4 file, in either app: it is converted before writing (FMT-16.12, FMT-16.21).

## Security notes

- Writing 3.1 loses the keyed header HMAC and the per-block HMACs; integrity then rests on the start bytes, the hashed blocks and the header hash inside the encrypted document (FMT-17). That is why App writes version 4 only: every save restores full integrity (SF-05, SF-06, AT-A09).
- The version 3 header carries the protected-field stream key in the clear (FMT-17). Moving to version 4 puts that key inside the encrypted inner header.
- Converting legacy AES-KDF to version 4 AES-KDF must keep the same rounds or more, never fewer. A new seed is always drawn from the OS random source (CRY-03, SF-07).
- When the KDF is converted, keys must be derived again before writing. The reference notes that forgetting this would save a file without the hardware key part (paraphrased). App must derive keys from the full composite key, hardware key response included, for every version 4 save (FMT-04, AT-H04).
- Dropping data silently (FMT-16.13) is a data-safety issue, not a secret leak. App drops none of the user's values: report exclusion and previous-parent references always raise to 4.1 (FMT-16.19, LD-08), and kept unknown parts keep their version (FMT-16.24, LD-09). Only custom data item times are left out of a 4.0 file (FMT-16.11). A file App writes never claims an older version than the content it carries.
- The version decision must use the whole model, including history entries and the root group; a bug that skips them would write a 4.0 file that silently drops data.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| FMT-16.1 floor | A new vault with legacy AES-KDF and nothing else (the reference's command line db-create; `password-only.appvault`) | Reference saves | 3.1 (observed: bytes 8 to 11 `01 00 03 00`) |
| FMT-16.2 recorded version, version 3 files | Format300 copies stamped 3.0, 3.2, 3.65535, 2.0, 2.1 (password "a") | Reference adds a group and saves | 3.1, 3.2, 3.65535, 3.1, 3.1 (observed) |
| FMT-16.2 recorded version, version 4 files | A 4.0 vault without 4.1 content (v40-password, a gap vault of FMT-01.29; observed on the scratch vault of FMT-01 Vector L4) re-sealed as 4.1, 4.2, 4.65535 | Reference adds a group and saves | 4.0 each time (observed) |
| FMT-16.3 KDF | A legacy AES-KDF vault switched to Argon2d / Argon2id / version 4 AES-KDF, each with AES-256, ChaCha20 or Twofish, no other feature | Reference saves | 4.0 for all nine (reference unit test); switched to legacy AES-KDF instead: 3.1 for each cipher |
| FMT-16.4 public custom data | Legacy AES-KDF vault with one public custom data item | Reference saves | 4.0 (reference unit test) |
| FMT-16.5 custom data | Legacy AES-KDF vault plus one custom data item on: the root group / a subgroup / an entry in the root / an entry in a subgroup / a history entry | Reference saves | 4.0 in each case (unit test; history case observed through import) |
| FMT-16.5 vault custom data | Legacy AES-KDF vault with vault custom data items | Reference saves | 3.1 (unit test and observed) |
| FMT-16.6 group tags | The basic content (`testdata/README.md`) plus a subgroup with tags `demo-tag`; then the tags cleared | Reference saves | 4.1 (observed through import); cleared: 3.1 (unit test) |
| FMT-16.7 group previous parent | Group 1 with previous parent group 2 (exists); then cleared | Rule | 4.1; cleared: 3.1 (unit test; 4.1 also observed through import) |
| FMT-16.8 report exclusion | A current entry with exclusion set; then cleared | Rule | 4.1; cleared: 3.1 (unit test; observed through import) |
| FMT-16.8 legacy exclusion key | A current entry with custom data `KnownBad` = `true` and no flag | Rule | 4.1 (custom data alone would give 4.0) |
| FMT-16.9 entry previous parent | A current entry with previous parent group 2; then cleared | Rule | 4.1; cleared: 3.1 (unit test) |
| FMT-16.10 custom icon | A custom icon with no name and no time / with name `abc` / with only a last-modification time / that icon removed | Rule | 3.1 / 4.1 / 4.1 / 3.1 (all four from the reference unit test, which removes the named icon and adds it back with only a time; name case also observed through import) |
| FMT-16.10 name removed | A custom icon with name `abc` and no time; then the name cleared, the icon kept | Rule | 4.1; then 3.1 (from the source, not in the unit test) |
| FMT-16.10 App: any time counts | Three vaults with no other 4.1 feature, each with one custom icon without a name, whose `LastModificationTime` was read as: empty text (0, 0001-01-01T00:00:00Z) / `sflu4g4AAAA=` / base64 of `FF FF FF FF FF FF FF 7F` | App saves | 4.1 for each, and the time is written back unchanged (FMT-12.8) |
| FMT-16.13 group and entry item times | A vault with one entry custom data item that has a last-modification time, and no 4.1 feature | App saves; then a group tag is added and App saves again | First 4.0 with the item time left out (no raise); then 4.1 with the item time written. The reference writes no group or entry item time at either version (FMT-14.13) |
| FMT-16.11 no raise | `rich-v3.appvault`: entry tags `demo,work`, database custom data, attachments, history; no feature of FMT-16.3 to FMT-16.10 | Read the version | 3.1 (made by import, observed); also observed with the basic content plus entry tags only |
| FMT-16.11 history flags no raise | history-excluded (a gap vault of FMT-01.29): one entry whose history entry is excluded from reports | Reference saves | 3.1 (observed on a scratch import) |
| FMT-16.12 KDF switch | `rich-v4.appvault` (an import into a legacy AES-KDF vault made with `-t 100`) | Read the saved header | Version 4.1; KDF map with AES-KDF id `C9D9F39A-...`, the rounds of the import (13,043,478 in the current file), a 32-byte seed S. Also observed with 1,000,000 rounds and a 4.0 result (scratch import with root group custom data, FMT-01 Vector L4) |
| FMT-16.12 hardware key kept | A legacy AES-KDF vault with password, key file and hardware key, upgraded by any 4.0 trigger | Save, then open with the full key / with an empty key | Opens / fails (reference unit test); App: same with a software response |
| FMT-16.13 dropped in 3.1 | `rich-v3.appvault` (password `demo-pass-4`) | Decrypt and read the document | No settings-changed element; times as ISO text; header hash element present; attachment pool (`Binaries`) in the metadata |
| FMT-16.13 written in 4.0 | v40-password (gap vault, FMT-01.29; observed on the scratch vault of FMT-01 Vector L4) | Decrypt and read the document | Settings-changed element present; times base64 (`sflu4g4AAAA=` = 2026-10-24 19:10:41 UTC in the scratch vault); no header hash element; no last-modification time on vault custom data items |
| FMT-16.13 written in 4.1 | `rich-v4.appvault` (password `demo-pass-5`) | Decrypt and read the document | Settings-changed element present; times base64; no header hash element; no `Binaries` in the metadata (attachments are in the inner header); vault custom data items that have a known modification time carry a last-modification time element (observed: the random-slug item the reference adds has one) |
| FMT-16.13 history flag kept only in 4.1 | The history-excluded content plus root group tags | Reference saves, then exports | 4.1, one `QualityCheck` in the export (observed on a scratch import); without the tags: none (observed) |
| FMT-16.14 highest wins | A vault with group custom data (4.0) and group tags (4.1) | Rule | 4.1 |
| FMT-16.15 version 3 choice | A 4.0 vault without features of FMT-16.4 to FMT-16.10, version 3 chosen in the graphical app | Save | 3.1 (source, re-read by Verify; app not run) |
| FMT-16.15 choice greyed out | A 4.0 vault with group custom data | Open encryption settings | The version 3 choice is disabled (source, re-read by Verify; app not run) |
| FMT-16.16 sticky in session | A vault saved as 4.1 because of one group tag; the tag removed in the same session | Reference saves again | 4.1; after closing and opening again and saving: 4.0 (source, re-read by Verify; app not run) |
| FMT-16.16 sticky after export | A 4.0 vault (v40-password) given one group tag, exported to XML without saving, then the tag removed, all in one session | Reference saves | 4.1 (the export set the recorded version; source, re-read by Verify; app not run) |
| FMT-16.17 export times | `testdata/rich-v3.json` and `testdata/rich-v4.json` (exports made by the reference) | Read times | ISO text (`2024-01-01T00:00:00Z`) / base64 (`gPcj3Q4AAAA=`) (observed) |
| FMT-16.18 App writes version 4 only | Format300 opened in App with "a" | App saves | Version field `00 00 04 00`; version 4 layout |
| FMT-16.19 App 4.0 or 4.1 | Each case of FMT-16.6 to FMT-16.10 | App saves | 4.1; with none of them and none of the FMT-16.19 list: 4.0 |
| FMT-16.19 history exclusion kept | The history-excluded content (entry "Demo login" whose one history entry has `QualityCheck` = `False`); then the same plus root group custom data | App saves and reads back | 4.1 both times; the history entry is still excluded from reports. Reference: 3.1 / 4.0 and the flag dropped (observed) |
| FMT-16.19 history previous parent kept | The basic content; "Demo login" has one history entry whose previous-parent group is group "Demo" (exists); nothing else of FMT-16.6 to FMT-16.10 | App saves and reads back | 4.1; the history entry's previous-parent group is "Demo". Reference: 3.1 and the reference dropped (FMT-16.11, FMT-16.13) |
| FMT-16.19 dangling previous parent kept | The basic content; "Demo login" has previous-parent group id `0102030405060708090A0B0C0D0E0F10`, which names no group in the vault | App saves and reads back | 4.1; the same id is read back (FMT-11.30). Reference: no raise, dropped |
| FMT-16.19 item times never raise | A vault whose only 4.1-capable value is a last-modification time on one vault custom data item | App saves | 4.0, the item time left out (FMT-16.11) |
| FMT-16.20 no recorded version | A 4.0 vault without 4.1 content and without unknown parts (v40-password, or one written by App) re-sealed as 4.1 / 4.2 | App opens and saves | 4.0 / 4.0 |
| FMT-16.21 App instead of 3.1 | `default-time.appvault` opened in App with `demo-pass-3` | App saves | Version 4.0; KDF map: id `C9D9F39A-...`, R = 1,000,000, a new 32-byte seed; inner stream ChaCha20; reopens in App and in the reference command line tool with the same content; the one-time notice of LD-07 was raised before the save, and is not raised again on the next save (spy) |
| FMT-16.21 3.x to 4.1 | `rich-v3.appvault` opened in App with `demo-pass-4`, then one group tag added | App saves | Version 4.1; KDF map with AES-KDF, the same rounds as the file read, a new 32-byte seed |
| FMT-16.22 App and 3.x minors | Format300 copies stamped 3.2 and 2.1 (password "a") | App saves | 4.0 for each, AES-KDF with 6,000 rounds in the KDF map |
| FMT-16.24 kept unknown part, 4.1 | Version 4 demo vaults with AES-KDF and no known 4.1 content: (a) stamped 4.1, `<FooBar/>` in the metadata; (b) the same without `<FooBar/>`; (c) stamped 4.0 with `<FooBar/>` | App opens and saves each | (a) 4.1 and `<FooBar/>` kept; (b) 4.0; (c) 4.0 and `<FooBar/>` kept (same vaults as FMT-10.23). Reference: 4.0 each, `<FooBar/>` dropped |
| FMT-16.24 kept unknown part, 4.2 | Vault (a) above re-sealed as 4.2; then (b) re-sealed as 4.2 | App opens and saves | First: 4.2 (bytes 8 to 11 `02 00 04 00`), `<FooBar/>` kept, and it reopens in App; second: 4.0 |
| FMT-16.24 parts removed | Vault (a) above with the unknown element inside the entry "Demo login" instead of the metadata; the entry deleted for good (not only moved to the recycle bin) | App saves | 4.0 |
| FMT-16.23 never lowers | A version 4 vault with Argon2id, 64 MiB, 3 iterations | App saves | Same KDF settings with a new salt; header HMAC and block HMACs present |

## How this was learned

- Read in the reference source: the save routine that computes the minimum version and picks the version 3 or version 4 writer, including the KDF switch and its comment about re-deriving keys; the vault model's KDF setter, which recomputes the recorded version; the version 4 header reader, which sets the KDF while reading field 11; the entry accessor that treats the old custom data key as report exclusion; the group and entry accessors for previous-parent groups; the document writer's version checks (times, header hash, attachment pool, settings-changed time, custom data item times, report exclusion, previous-parent groups, icon names); the graphical encryption settings code (version 3 choice and the greyed-out case).
- Read the reference's unit tests for the version 2 and version 4 upgrade paths, the version 4.1 rule, and the hardware key integrity after an upgrade.
- Review round 2: read the time reader and the icon check of the save routine in the source (what counts as a time); read the document writer's custom data item branch (vault items only); decrypted scratch copies of `rich-v3` and `rich-v4` from `testdata/` and checked their version-gated elements.
- Ran the installed reference command line tool 2.7.11 in a scratch folder: imported edited XML exports of a demo vault, each adding one feature (group custom data, history entry custom data, group tags, entry tags, entry report exclusion, history entry report exclusion with and without other triggers, a named custom icon, a group previous-parent reference), and read the version of each saved file and its export; saved copies of test vaults whose version bytes were edited (3.0 base) or edited and re-sealed (4.0 base) and read the version written.
- Review round 3 (cross-check findings): made FMT-16.21 the single home of its lead decision, so FMT-04.18, CRY-02.20 and FMT-17.24 are read as "per FMT-16.21 (lead to confirm)". No rule changed.
- Sprint 0 close-out: wrote the lead rulings into the card. LD-08 replaced the default of FMT-16.19 with the lossless rule (history report exclusion, history previous-parent references and dangling previous-parent references raise to 4.1), matching FMT-11.29 and FMT-11.30. LD-09 added FMT-16.24 (kept unknown parts never get a lower version than the one read) and changed FMT-16.18 and FMT-16.20. LD-07 decided FMT-16.21 and FMT-16.22 (same rounds, fresh 32-byte seed, one-time notice). Edge cases, security notes and tests follow; the observed reference behavior stays as fact.
- Sprint 1 close-out: reviewed the layout rulings LD-07, LD-08 and LD-09 in this card against FMT-01, FMT-10, FMT-11, FMT-14, FMT-15 and FMT-17; the kept-unknown-parts edge line now says "at least the version the file was read as", as FMT-16.24 does.
