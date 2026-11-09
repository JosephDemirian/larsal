# MOD-06 Icons

Status: reviewed
Epics: E4-S5
Parity rows: SN-02, SD-06

## What it does

Every entry and every group shows one icon. It is either a standard icon, chosen by number from a fixed set that every app of this vault format knows, or a custom icon, an image stored once in the vault and pointed to by id. This card says which numbers exist and what they show, which icon new items get, how custom icons are added, scaled, de-duplicated and removed, and which items show which icon. FMT-11.10 and FMT-11.11 own how an item stores its icon; FMT-14.1 to FMT-14.9 own how custom icons are stored. Downloading website icons is APP-01 and parity row SN-02; this card only takes the image that a download returns.

Words used in this card: **live entry**, **history item**, **now**, **change batch** as in MOD-01. **Uses** of a custom icon are the live entries and groups whose custom icon is that id; history items are counted separately where a rule says so.

## Inputs and outputs

- Standard icon: a 32-bit signed number stored on the item (FMT-11.10).
- Custom icon (FMT-14.1): id (16 bytes), image bytes (PNG when Larsal or the reference makes it), name (text, may be empty), time (optional). The vault's custom icons form one list in stored order.
- Inputs to "add custom icon": image files the user picks, or an image returned by a website icon download (APP-01).
- Outputs: PNG bytes of at most 128 × 128 pixels added to the vault list; messages with our IDs `msg.icons_added`, `msg.icons_exist`, `msg.icons_failed`, `msg.icon_in_use`, `msg.icons_all_in_use`, `msg.icons_purged` (texts are Larsal's own).

Limits: MOD-06.7 (Larsal's input limits); FMT-14.25 (reading).

## Rules

### Standard icons

MOD-06.1 **The standard set.** Standard icon numbers run from 0 to 68: 69 icons. Their meaning is fixed by the format family, so other apps show a matching picture for the same number. Larsal ships its own drawing for each number, made in the style of design/mockup.html, never the reference's artwork. What each picture shows:

| # | Picture | # | Picture | # | Picture |
|---|---|---|---|---|---|
| 0 | key (default for entries) | 23 | grid of icons | 46 | help, question mark |
| 1 | globe, network | 24 | connection made | 47 | package |
| 2 | warning sign | 25 | mail folder | 48 | closed folder (default for groups) |
| 3 | server | 26 | floppy disk, save | 49 | open folder |
| 4 | pinned note, clipboard | 27 | network drive | 50 | archive folder |
| 5 | languages, speech | 28 | media player | 51 | open padlock |
| 6 | building blocks | 29 | secure terminal | 52 | closed padlock |
| 7 | notepad, text editor | 30 | terminal, console | 53 | check mark |
| 8 | power socket | 31 | printer | 54 | signature, pen |
| 9 | identity card | 32 | file system view | 55 | picture thumbnail |
| 10 | contacts card | 33 | run, launch | 56 | address book |
| 11 | camera | 34 | wrench, configure | 57 | text list |
| 12 | remote, wireless | 35 | remote desktop | 58 | encryption key pair |
| 13 | key ring (passkeys) | 36 | archive box | 59 | developer tools |
| 14 | battery, power | 37 | percent sign | 60 | home |
| 15 | scanner | 38 | network share | 61 | star, services |
| 16 | web browser | 39 | clock, history | 62 | penguin |
| 17 | optical disc | 40 | mail search | 63 | feather |
| 18 | monitor | 41 | vector drawing | 64 | apple (fruit) |
| 19 | envelope, e-mail | 42 | memory chip | 65 | letter W |
| 20 | gear, miscellaneous | 43 | trash can (recycle bin) | 66 | money |
| 21 | calendar, organizer | 44 | sticky note | 67 | certificate |
| 22 | plain text file | 45 | cancel, no entry | 68 | mobile phone |

The icon picker shows the 69 standard icons in number order.

MOD-06.2 **Icons Larsal sets by itself.**

| Item | Icon |
|---|---|
| New entry | 0, or the group's icon by MOD-06.3 |
| New group | 48 |
| Recycle bin when it is made (MOD-04) | 43 |
| An old recycle bin kept as a normal group when the bin is turned off (MOD-04) | 48 |
| Entry or group made by the browser bridge (INT-02) | 1 |
| Passkey entry, and the group the browser bridge makes for passkeys (INT-04) | 13 |
| Item whose custom icon is removed (MOD-06.14) | 0 for entries, 48 for groups |

MOD-06.3 **Group icon for new entries.** Setting `set.entry_group_icon` (our ID; APP-01 owns the final ID), default on. When it is on and the group the new entry is added to has a custom icon, or a standard icon other than 48 and 49, the new entry gets that icon (the same custom icon id, or the same number). Otherwise the new entry gets 0. The setting is read when the add screen opens; it only affects "Add entry" on the screen (MOD-01.22).

MOD-06.4 **Numbers outside 0 to 68.** Any number read from a file is kept and written back (FMT-11.10). A number outside 0 to 68 is shown as icon 0. The reference's edit screen cannot select such a number, so saving the edit screen stores 0 even when the user did not touch the icon. Larsal keeps the stored number until the user picks another icon (lead decision D-06-1, recommended).

### Custom icons

MOD-06.5 **The custom icon list.** The vault holds one list of custom icons in stored order (FMT-14.5); new icons go at the end. The icon picker shows them in that order. An item that uses a custom icon stores icon number 0 (MOD-01.13).

MOD-06.6 **Adding from files.** On the entry or group edit screen the user chooses "add custom icon" and picks one or more files. For each file, in the order picked:
1. Decode it (MOD-06.7). A file that cannot be decoded, or breaks a limit, counts as failed.
2. Scale it (MOD-06.8) and encode it as PNG.
3. De-duplicate (MOD-06.9): when an equal icon exists, count the file as "already there" and use that icon.
4. Otherwise add a new icon with a new random id (as MOD-01.12, unique among custom icons), the PNG bytes, the name = the file name up to its first dot (`bank.logo.png` gives `bank`, `.hidden.png` gives an empty name), and the time = now.

Afterwards one message reports: how many of the picked files were added (`msg.icons_added`), how many already existed (`msg.icons_exist`), and the names of the files that failed, at most the first 8 (`msg.icons_failed`). When none was added the message says so. The icon of the last file that did not fail (new or existing) becomes the selected icon in the picker. The file dialog offers an "images" filter and an "all files" filter.

MOD-06.7 **Formats and input limits.**
- Reference: it accepts every format its UI toolkit's decoders read on that system. The installed 2.7.11 on Mac bundles decoders for BMP, CUR, GIF, HEIC, HEIF, ICNS, ICO, JPEG 2000, JPEG, PBM, PGM, PNG, PPM, TGA, TIFF, WBMP, WebP, XBM and XPM, and none for SVG (seen in the app bundle's decoder folder, not run through the screen: check with Verify). It has no size limit.
- Larsal (decided: spec/decisions.md LD-65, replacing D-06-2): images are decoded in Rust, in larsal-core, with a Rust image crate, and only PNG, JPEG and ICO are accepted. Any other format, or a broken image, counts as failed. The crate needs an AT-J03 review and a line in the approved crate table of plan/architecture.md, in E4, before the story that builds this. macOS image services are not used.
- Larsal input limits, lead decision D-06-3 (the proposed numbers, decided by the default rule): input bytes of at most 16 MiB and a decoded image of at most 4,096 pixels on each side; input over either limit counts as failed. The pixel limit is checked from the image header before any pixel memory is taken. The same limits apply to every decode: picked files, downloads (MOD-06.11) and icon bytes read from a vault (MOD-06.19). Tests must be able to lower both.

MOD-06.8 **Scaling.** When the image is wider or taller than 128 pixels it is resized to exactly 128 × 128 pixels; the aspect ratio is not kept, so a 256 × 64 image becomes 128 × 128. An image of at most 128 pixels on both sides keeps its size, 1 × 1 included. The result is encoded as PNG. The reference uses its toolkit's fast (nearest pixel) resizing; Larsal uses a smooth filter. That only changes pixels, not the rule.

MOD-06.9 **De-duplication.** Before adding, Larsal compares the new PNG bytes with every icon in the list. When one has exactly the same bytes, no icon is added and that icon is used. When several have the same bytes, Larsal uses the first in stored order. (The reference compares an MD5 hash of the bytes and uses the most recently added of the equal icons.) Equal pictures encoded differently are different icons. Reading a file never de-duplicates by bytes (FMT-14.7 only fixes repeated ids).

MOD-06.10 **When the icon joins the vault.** An icon added on the edit screen joins the vault at once, as its own change, even when the user then cancels the edit screen; such an unused icon stays until the user removes or purges it (MOD-06.14, MOD-06.15). This is the reference's behavior; Larsal does the same. An icon added on the edit screen has a time (and maybe a name), so the next save writes version 4.1 (FMT-14.4, FMT-16).

MOD-06.11 **Icons from a website download.** APP-01 owns whether downloads are allowed, where they go and their limits (SN-02). This card takes the returned image:
- Edit screen download for one entry: decode, scale and de-duplicate as above; a new icon gets an empty name and the time now. When an equal icon exists the screen says the existing one was selected; when the download returns nothing it says the icon could not be fetched.
- Bulk download for selected entries: same steps per site; a new icon gets no name and no time (so it does not force version 4.1). The icon is set directly on every selected entry with that site, as one change batch per site: each entry's modification time moves, no history item (MOD-01.32).

MOD-06.12 **Choosing an icon on the edit screen.** The picker offers "standard" (the 69 icons) or "custom" (the vault list). Picking a standard icon stores its number and clears the custom icon; picking a custom icon stores its id and sets the number to 0 (MOD-01.13). When "custom" is chosen but no custom icon is selected, the item gets the default icon of its kind (0 for an entry, 48 for a group).

MOD-06.13 **Apply to children** (group edit screen only). The choices are: this group only (default, chosen again each time the screen opens), also child groups, also child entries, also all children. After the group's own save:
- child groups = every group in the group's subtree except the group itself;
- child entries = every live entry in the group and in its subtree (history items untouched);
- each of them gets the group's icon (the same custom icon id, or the same number). Each item that really changes gets a new modification time; no history items are made (MOD-01.32). Applying from the root with "child groups" also changes the recycle bin's icon (the reference does the same).

MOD-06.14 **Removing selected custom icons** (vault settings, maintenance page). The page lists the custom icons in stored order; the user selects one or more and chooses Delete. For each selected icon:
- Count its uses by live entries (recycle bin included) and groups.
- When it has uses, ask once for the whole action (`msg.icon_in_use`: some selected icons are in use; their items will get the default icon; Delete or Skip, Skip is the default). The answer holds for every selected icon of this action.
- Skip: icons with uses are kept; icons without uses are still removed.
- Delete, or no uses: every live entry using it gets icon 0 and every group using it gets icon 48 (each such item's modification time moves, no history item); every history item using it gets icon 0 without any change to its times; the icon is removed from the list; the icon's id is recorded as a deleted object with the current time (FMT-14.9, FMT-15).
- All of it is one change batch.

MOD-06.15 **Purging unused custom icons** (same page). Every custom icon that no live entry and no group uses is removed, including icons used only by history items; those history items get icon 0 without any change to their times. Each removed icon gets a deleted-object record, unless the vault knows a share: a share can bring an icon with an outside object's id, and a plain record reaches outside, so with a share known there is no record and a stale copy can bring the icon back (INT-08.32). When nothing was removed the page says all custom icons are in use (`msg.icons_all_in_use`); otherwise it reports the count (`msg.icons_purged`, "purged N icons"). One change batch.

MOD-06.16 **Which item shows which icon.**
- Entry: its custom icon when it has one, else its standard number. Shown in the entry list's title column, in the detail view and on the edit screen. The entry list's group column shows the group's icon.
- Group: the same rule; shown in the sidebar tree and on the group edit screen. An expanded group keeps its own icon (no automatic open-folder picture).
- An expired entry or group gets the expired badge on its icon (MOD-09). A shared group that is not expired gets the shared badge (INT-08).
- A custom icon id that names no icon in the vault (FMT-14.8): the reference shows an empty picture and its edit screen then stores the default icon on save or cancel (0, for groups too). Larsal shows the default icon of the item's kind (0 or 48) and keeps the id until the user picks another icon (lead decision D-06-1).
- Custom icon bytes that cannot be decoded: Larsal shows the default icon of the item's kind and keeps the bytes.

MOD-06.17 **Copies between vaults.** When a group is moved or copied into another open vault (MOD-02.22), every custom icon used by the group, its subtree, their live entries and those entries' history items is added to the target vault with its id, bytes, name and time, unless the target already has that id. When a single entry is moved or copied, its own custom icon is added the same way; the reference copies only id and bytes in that case (FMT-14.3), so name and time are lost there. Larsal copies name and time in both cases (lead decision D-06-4, recommended). An icon whose id the target already has is not compared or replaced.

MOD-06.18 **History items.** A history item keeps the icon its entry had at that time, standard or custom. Only MOD-06.14 and MOD-06.15 change a history item's icon.

MOD-06.19 **Image data is untrusted.** Custom icon bytes come from files, vaults, imports, shared groups and downloads. Larsal decodes them only to show them or to add them, in Rust with the limits of MOD-06.7, and never in the format layer (FMT-14.2). Before an icon reaches the screen layer, Larsal re-encodes it as PNG; the screen never receives the stored or downloaded bytes themselves (decided: spec/decisions.md LD-65). Icon bytes read from a vault in a format other than PNG, JPEG or ICO, or bytes that fail to decode or break a limit, show the default icon of the item's kind (MOD-06.16) and are kept unchanged in the vault, byte for byte. A failed decode never stops the vault from opening.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Entry with icon number 99 | Shown as icon 0; Larsal writes 99 back unless the user picks an icon (MOD-06.4). |
| Entry with icon number -3 in the file | Read as 0 (FMT-11.10). |
| Picked file is not an image | Counted as failed and named in `msg.icons_failed`; nothing added. |
| 12 picked files fail | Only the first 8 names are listed. |
| Same image picked twice in one action | First added, second counted in `msg.icons_exist`. |
| Image of 4,097 × 10 pixels (Larsal) | Failed by D-06-3. |
| Picked GIF, BMP, TIFF, WebP or HEIC file (Larsal) | Failed: Larsal accepts only PNG, JPEG and ICO (LD-65). |
| Vault icon stored as GIF (Larsal) | Default icon shown; the GIF bytes are written back unchanged (MOD-06.19). |
| Image of 1 × 1 pixel | Added at 1 × 1. |
| Add custom icon, then cancel the edit screen | The icon stays in the vault, unused. |
| "Custom" chosen with no custom icon selected on a group | Group gets 48. |
| Remove an icon used by 2 entries, answer Skip | Icon kept; entries unchanged. |
| Purge when every icon is in use | Nothing removed; `msg.icons_all_in_use`. |
| Custom icon id with no icon in the vault | Default icon shown; id kept (Larsal). |
| Icon bytes that are not a valid image | Default icon shown; bytes kept and written back. |
| Apply to all children from the root | Every group (recycle bin included) and every live entry gets the root's icon. |

## Security notes

- **Hostile images.** Custom icon bytes are attacker-controlled when a vault, shared group or import comes from someone else, and downloaded icons come from the network. Decoders are a classic attack surface. Larsal decodes only in Rust, only PNG, JPEG and ICO (LD-65), enforces input limits before taking pixel memory (D-06-3), never decodes in larsal-format, re-encodes as PNG before the screen layer sees anything, and treats a decode failure as "show the default icon" (MOD-06.19). No untrusted image bytes reach the web view. Fuzz the add path and the vault-icon path with malformed images (AT-A10 style). The parity matrix in plan/security.md notes it (LD-65).
- **Network (SN-01, SN-02).** No icon is fetched unless the user turned website icons on (APP-01). This card never starts a download.
- **Screen layer (AT-E01, AT-E04).** The screen shows custom icons only from PNG bytes Larsal hands it (for example as an inline image), never from a remote URL; the content security policy blocks remote images.
- **Deletion records.** Removing an icon records a deleted object (MOD-06.14) so a merge does not bring it back (MOD-11). With a share known it does not (MOD-06.15, INT-08.32).
- **Keep data (SD-06).** Unknown icon numbers, dangling icon ids and undecodable bytes are kept, not dropped (MOD-06.4, MOD-06.16).

## Test cases

Notation: t0 = 2026-10-25T10:00:00Z, t1 = 2026-10-25T10:05:00Z. Vault V: root R (icon 48), group G under R, entry E in G (icon 0), all times t0. Image files are demo files made by the test: `red.png` (16 × 16 red square), `wide.png` (256 × 64), `big.jpg` (300 × 300), `note.txt` (text).

| Case | Given | When | Then |
|---|---|---|---|
| MOD-06.1 range | Icon picker | Count standard icons | 69, numbered 0 to 68 in order. |
| MOD-06.2 new items | Vault V, setting `set.entry_group_icon` on, G icon 48 | Add group N under R; add entry F in G | N icon 48; F icon 0. |
| MOD-06.2 recycle bin | Vault V, no recycle bin | Delete E | New recycle bin with icon 43 holds E. |
| MOD-06.3 group icon used | G icon 12, setting on | Add entry F in G | F icon 12. |
| MOD-06.3 group custom icon | G uses custom icon X, setting on | Add entry F in G | F uses X, number 0. |
| MOD-06.3 folder icons skipped | G icon 49, setting on | Add entry F in G | F icon 0. |
| MOD-06.3 setting off | G icon 12, setting off | Add entry F in G | F icon 0. |
| MOD-06.4 out of range | File entry with icon 99 | Open, edit Notes, save, read | Shown as icon 0; file holds 99. |
| MOD-06.4 user picks | Same entry | Pick icon 5, save | File holds 5. |
| MOD-06.5 order | Vault with custom icons X, Y | Add icon Z | List order X, Y, Z. |
| MOD-06.6 add from file | Vault V with no custom icons, clock t1 | On E's edit screen add `red.png` | One custom icon: new id, PNG 16 × 16, name `red`, time t1; it is selected; `msg.icons_added` reports 1 of 1. |
| MOD-06.6 name to first dot | Vault V | Add `bank.logo.png` (a valid image) | Icon name `bank`. |
| MOD-06.6 mixed result | Vault V already holding the icon made from `red.png` | Add `red.png`, `note.txt`, `big.jpg` in one pick | One new icon (from `big.jpg`); message: 1 of 3 added, 1 already there, failed: `note.txt`; selected icon = the `big.jpg` icon. |
| MOD-06.6 failed list cap | 12 text files renamed `a1.png` … `a12.png` | Add all 12 | 0 added; failed list names `a1.png` to `a8.png` only. |
| MOD-06.7 formats accepted | Vault V | Add a demo PNG, JPEG and ICO file | Each added as PNG. |
| MOD-06.7 formats refused | Vault V | Add a demo GIF, BMP, TIFF, WebP and HEIC file | All 5 counted as failed and named in `msg.icons_failed`; nothing added. |
| MOD-06.7 limits | Test build with the pixel limit lowered to 100 | Add `big.jpg` (300 × 300) | Counted as failed; nothing added. |
| MOD-06.8 scale | Vault V | Add `wide.png` | Stored image is 128 × 128 PNG. |
| MOD-06.8 small kept | Vault V | Add a 1 × 1 PNG | Stored image is 1 × 1. |
| MOD-06.9 dedupe | Vault with icons X and Y whose bytes are equal (read from a file) | Add an image whose PNG bytes equal X's | No icon added; X selected (first in stored order). |
| MOD-06.10 cancel keeps icon | Vault V | Open E's edit screen, add `red.png`, Cancel | Vault has the new icon; E's icon still 0. |
| MOD-06.10 version | Vault V saved as 4.0 | Add `red.png` on the edit screen, save | File written as 4.1 (icon has a time, FMT-14.4). |
| MOD-06.11 bulk download | Entries E1, E2 with URL `https://demo.example`, download returns a 32 × 32 image, clock t1 | Bulk download for E1, E2 | One new icon, no name, no time; E1 and E2 use it; both modification times t1; no history items. |
| MOD-06.12 custom without pick | Group G edit screen | Choose "custom" with no icon selected, save | G icon 48. |
| MOD-06.13 apply to all | G icon changed to 7 with "also apply to all children"; G holds E, sub-group S holding F; F has 1 history item with icon 3 | Save | G, S, E, F icon 7; F's history item still icon 3; no new history items; E, F, S modification times = now. |
| MOD-06.13 default resets | Previous edit used "also apply to all children" | Open G's edit screen again | Choice shows "this group only". |
| MOD-06.14 delete in use | Icon X used by E and G; history item of E uses X; clock t1 | Select X, Delete, answer Delete | E icon 0 (modification t1, no history item); G icon 48; E's history item icon 0 with its times unchanged; X gone; deleted objects hold X's id at t1. |
| MOD-06.14 skip | Icons X (used by E) and Y (unused) | Select X and Y, Delete, answer Skip | X kept; Y removed with a deleted-object record. |
| MOD-06.15 purge | Icons X (used by G), Y (used only by a history item), Z (unused) | Purge | Y and Z removed; the history item's icon 0, times unchanged; `msg.icons_purged` reports 2. |
| MOD-06.15 nothing | Icons X used by E | Purge | Nothing removed; `msg.icons_all_in_use`. |
| MOD-06.16 dangling id | File entry with custom icon id(77) and no icon id(77) in the vault | Open, view, edit Title, save | Icon 0 shown; file still holds id(77). |
| MOD-06.16 badge | E expires at t0, clock t1 | Show the entry list | E's icon has the expired badge. |
| MOD-06.17 group copy | Vault V with G using icon X (name `bank`, time t0); vault W open without X | Copy G into W | W has icon X with the same id, bytes, name `bank`, time t0. |
| MOD-06.17 entry copy | E uses icon Y (name `mail`) | Copy E into W | W has Y with name `mail` (Larsal; reference: empty name, no time). |
| MOD-06.18 history keeps icon | E icon 0 at t0 | Change E's icon to 9 on the edit screen | E icon 9; new history item icon 0. |
| MOD-06.19 bad bytes | File with custom icon X whose bytes are `00 01 02`, used by E | Open the vault | Opens; E shows icon 0; save writes X's bytes back unchanged. |
| MOD-06.19 oversize header | Vault with custom icon X: a 60-byte PNG whose header claims 100,000 × 100,000 pixels, used by E | Open the vault, show E | Opens; E shows icon 0; no pixel memory taken (the header check fails first); save writes X's bytes back unchanged. |
| MOD-06.19 other format kept | Vault with custom icon Y stored as a valid GIF, used by G | Open, rename G, save, open again | G shows icon 48; Y's bytes in the saved file equal the original bytes exactly. |
| MOD-06.19 screen gets PNG only | Vault with custom icon Z stored as a valid JPEG, used by E | Show E in the list | The screen layer receives PNG bytes for Z (starting with the PNG signature), never the JPEG bytes; the vault still holds the JPEG bytes. |
| MOD-06.19 fuzz | Fuzz target over the icon decode path with malformed PNG, JPEG and ICO input | Run in every sprint | No crash, no hang, memory within the D-06-3 limits. |

## How this was learned

- Lead decisions D-06-1, D-06-3 and D-06-4 (decided: spec/decisions.md default rule: D-06-1 and D-06-4 as recommended, D-06-3 the proposed numbers). D-06-2 is replaced by LD-65: Rust decoding, PNG, JPEG and ICO only, PNG re-encoding before the screen.

- Read the reference's icon picker on the entry and group edit screens: add from files (decode, scale above 128, PNG encode, de-duplicate, name up to the first dot, time), the result messages and the 8-name cap, website icon download for one entry, the custom-without-selection fallback, and the "apply to" menu.
- Read the vault metadata routines for adding, finding (MD5 of the bytes) and removing custom icons, including the deleted-object record; the bulk download dialog (scale, de-duplicate, no name and no time, direct assignment); the vault settings maintenance page (remove with one question per action, history items set to 0 without time changes, purge, messages).
- Read the icon helpers: how entry and group pictures are chosen, badges, the decoder list for the file dialog, and the standard icon set (69 pictures listed in the resource list; the source folder also holds one stray extra file that is not in the resource list).
- Read the group model's "use group icon on create" and "apply to children" routines, the browser bridge's icon numbers, the recycle bin creation, and the edit screens' cancel handling of missing custom icons.
- Looked at the decoder folder of the installed app bundle for the format list (not run through the screen). Ran the installed command line tool 2.7.11 on demo vaults in a scratch folder: a new entry has icon 0, a new group 48, the recycle bin 43; a crafted XML import kept icon 99 and turned -3 into 0.
