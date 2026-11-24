# FEA-09 Export formats

Status: reviewed
Epics: E4-S13
Parity rows: SD-07, SD-06, SD-09 (exports owner-only, 0600), SC-04 (nothing secret on screen while exporting)

## What it does

Export writes the content of an open, unlocked vault to an unencrypted file in one of three formats: CSV, HTML or the plain XML document of our format. The desktop app offers them in File > Export (APP-08); the command line tool offers them in `larsal export` (INT-10). Exports warn that the file is not encrypted (SD-07).

Other cards: FEA-08 imports CSV and (command line) XML back. FMT-10 to FMT-16 own the XML document. FEA-04 owns the one-time password URI. MOD-05 owns exporting attachments, FEA-04 the TOTP setup code, INT-04 passkey export, INT-08 shared-group export.

## Inputs and outputs

Input: one unlocked vault as it is in memory, unsaved changes included. Output: one file (desktop) or standard output (command line).

| Format | Action ID | File | Holds | Leaves out |
|---|---|---|---|---|
| CSV | ACT-EXPORT-CSV | `.csv`, UTF-8 | every live entry of every group, recycle bin included; 10 columns | history, attachments, custom fields, tags, expiry, Auto-Type, colors, group notes, vault metadata, empty groups |
| HTML | ACT-EXPORT-HTML | `.html`, UTF-8 | vault name, description, file path; per group outside the recycle bin: notes and entries with user name, password, URL, custom fields, notes | recycle bin, history, attachments, tags, times, expiry, entries with nothing to show |
| XML | ACT-EXPORT-XML | `.xml`, UTF-8 | the whole document a vault file holds (metadata, groups, entries, history, recycle bin, deleted objects, custom icons and data), protected values in clear | the outer header (cipher, KDF settings), the protected-value stream |

## Rules

FEA-09.1 **Availability.** ACT-EXPORT-CSV, ACT-EXPORT-HTML and ACT-EXPORT-XML sit in the File > Export submenu and are enabled only while an unlocked vault is on screen. Export reads the vault in memory, unsaved changes included. Export never changes the vault: no modified mark, no save, no random values drawn (CRY-03).

FEA-09.2 **Warning (SD-07).** CSV and XML: before the save dialog Larsal asks MSG-EXP-CONFIRM, buttons Yes and No, default No; No or closing the question ends the export with nothing written. HTML: the export dialog (FEA-09.7) shows the same warning as a banner that stays visible; there is no separate question, as in the reference. Command line: the reference prints no warning; Larsal prints the warning on standard error on every plain export (decided: spec/decisions.md LD-42). The CSV warning also says that a spreadsheet may run values starting with `=`, `+`, `-` or `@` as formulas; values are written exactly (decided: LD-43).

FEA-09.3 **CSV header.** The first line is exactly these bytes, then LF: `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"`. The header is not translated.

FEA-09.4 **CSV bytes.** Every field is enclosed in `"`, and each `"` inside a value is doubled. Nothing else is escaped: commas, LF and CR inside a value are written as they are, inside the quotes. Fields are joined by `,`; every record, the header included, ends with one LF. UTF-8 without a byte order mark. A vault with no entries gives the header line only.

FEA-09.5 **CSV order and scope.** Groups are walked depth-first from the root: first the group's own entries in their stored order, then each child group in stored order, the same way. The recycle bin and everything in it are included, wherever the bin sits. Only live entries: no history items. A group without entries writes no line.

FEA-09.6 **CSV columns.**

| Column | Value |
|---|---|
| Group | the group names from the root down to the entry's group, joined by `/`; the root's name is the first part; a `/` inside a name is not escaped |
| Title, Username, Password, URL, Notes | the stored values unchanged; placeholders and references are not resolved (MOD-08) |
| TOTP | empty when the entry has no one-time password; else the `otpauth://` URI that FEA-04's writer makes from the entry's settings, always in that URI form, whatever form is stored; its label uses the title and user name after placeholder resolution (MOD-08) |
| Icon | the standard icon number in decimal, also when a custom icon is shown (then usually `0`) |
| Last Modified, Created | the time in UTC as `YYYY-MM-DDTHH:mm:ssZ` |

FEA-09.7 **HTML dialog.** ACT-EXPORT-HTML opens a dialog with the warning banner and a "sort entries by" choice: name (ascending), the default; name (descending); vault order. OK opens the save dialog (FEA-09.15); Cancel ends the export.

FEA-09.8 **HTML page.** One self-contained HTML page in UTF-8. Larsal chooses its own layout, markup and styles (an inline style element; no outside files, scripts or fonts). The page holds, in this order:
1. In the head: the declared character set UTF-8, Larsal's Content-Security-Policy (FEA-09.11), and the vault name as the page title.
2. The vault name as the main heading.
3. The vault description, with its line breaks kept.
4. The vault file's path: the full path on the desktop, the path as typed on the command line.
5. The group sections (FEA-09.9).

The name and description are escaped (FEA-09.11). An empty name gives an empty title and an empty heading; an empty description gives no text. Values must be easy to tell apart by kind: Larsal's markup marks each value as user name, password, URL, custom field or notes (the Builder picks the class names and records them for the tests of E4-S13).

FEA-09.9 **HTML groups.** Groups are walked depth-first from the root; the recycle bin and everything in it are skipped. Child groups are visited sorted by name for the two name orders (compared ignoring case, ascending or descending), in stored order for vault order. A group with at least one entry or with notes gets a section heading: the group icon (desktop only, FEA-09.12) and the group path, which is the escaped group names from the root down joined by " › " (the path style of the mockup). Non-empty group notes follow the heading, escaped, with line breaks kept. Then come the group's entries (FEA-09.10). The heading is written even when FEA-09.10 leaves out every entry of the group (matches the reference, Verify, 2026-10-27: its export of a group holding only a title-only entry keeps the heading). A group with no entries and no notes adds nothing to the page.

FEA-09.10 **HTML entries.** A group's entries are sorted by title like the groups (FEA-09.9). Each entry shows its title (escaped) and then labeled values, in this order, each only when its value is not empty: User name, Password, URL, then one value per custom field in key order (FMT-11.22), shown even when the value is empty and labeled with the field name, then Notes. Labels are in the interface language. An entry with none of these values is left out, for example one with only a title or only attachments. On the desktop the entry also shows its icon (FEA-09.12). Values are stored values, not resolved. In custom field values every space is kept as it is (runs of spaces are not collapsed) and line breaks are kept; in notes line breaks are kept. Protected custom fields, the TOTP field `otp` and passkey fields are written in clear like any other field. Passkey fields (INT-04) are left out, as INT-04.55 says (decided: spec/decisions.md LD-74).

FEA-09.11 **HTML escaping and links.** Every text from the vault is escaped: `&` `&amp;`, `<` `&lt;`, `>` `&gt;`, `"` `&quot;`, `'` `&#39;` (the reference leaves `'` as is). The URL value is shown as text cut to its first 100 characters followed by an ellipsis (…) when longer. Larsal makes it a link to the full escaped URL only when its scheme is `http` or `https` (ignoring case); other URLs are plain text (lead decision L09-2; the reference links every URL, `javascript:` included). The head holds `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">` (L09-2; the reference has none).

FEA-09.12 **HTML icons.** On the desktop each group heading and entry carries its icon (standard or custom, MOD-06) as an inline PNG image (a `data:image/png;base64,` URL) at the size of the entry list. The command line export writes no icons and leaves no room for them.

FEA-09.13 **XML document.** The document is what the vault writer would write for this vault (FMT-10 to FMT-15) at the version Larsal's save picks (FMT-16.18 to FMT-16.24, so 4.0 or higher, never 3.1; LD-07): times are always base64. The reference exports a vault it would save as 3.1 with text times (FMT-16.17); both apps read either form, so nothing is lost on import. Other differences:
- No protected-value stream. Every value that a save would protect (its own flag or the vault's field protection flags, MOD-12) is written in clear with the attribute `ProtectInMemory="True"`; an empty one as `<Value ProtectInMemory="True"/>` (FMT-09.18 reads it back).
- No `HeaderHash`.
- Attachments: FEA-09.14.
- Declaration `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`; root element name `4B 65 65 50 61 73 73 46 69 6C 65` (stored encoded, name rule); layout of FMT-10.2 (one TAB per depth, LF).

Everything else is written as a save writes it: vault metadata and settings, custom icons, custom data (the FMT-10.25 item with its current value, no fresh one), all groups including the recycle bin, entries with their history, deleted objects, and kept unknown parts (SD-06). Characters not allowed in XML 1.0 are left out as FMT-12 says.

FEA-09.14 **XML attachments.** The reference, for a vault that saves as 4.x, writes each attachment reference as `Ref="0"` and no content anywhere, so attachment content is lost (observed with the installed tool; the project's test data notes the same). For a 3.1 vault it writes a `Meta/Binaries` pool with the content, gzipped with `Compressed="True"` when the vault uses compression. Larsal always writes a `Meta/Binaries` pool, in every version: each distinct content once, numbered from 0 the way FMT-13's writer numbers pool items, base64 without compression, and the real `Ref` numbers (lead decision L09-1). It stands where version 3 puts it: after `HistoryMaxSize` (and `SettingsChanged` in 4.x), before `CustomData`. A vault without attachments gets the empty element `<Binaries/>`, as the reference writes it in every export that has a pool (matches the reference, Verify, 2026-10-27). The reference command line import reads such a pool in a 4.x document and restores the attachments (observed).

FEA-09.15 **Writing the file.** The save dialog has a title naming the format, the filter `*.csv`, `*.html` or `*.xml`, and starts in the folder last used for that format (kept in Larsal settings, APP-01), else the home folder; macOS asks before replacing an existing file. Larsal writes to a new temporary file in the target folder with permissions 0600 (AT-I06), then renames it over the target in one step; it never writes through a link at the target (AT-I04). On any error Larsal shows MSG-EXP-FAILED with the system reason, removes the temporary file and leaves an existing target unchanged. The reference instead truncates and writes the target in place with default permissions, and its XML export writes even after an error.

FEA-09.16 **Command line.** `larsal export` writes the chosen format to standard output (INT-10 owns the options). Formats `xml` (also when the option is missing or empty), `csv` and `html`. The reference matches the option by prefix ignoring case (`XMLX` gives XML, `Csvfoo` gives CSV; observed) and answers any other value with an error naming the value on standard error and exit status 1 (observed); INT-10 decides whether Larsal keeps prefix matching. CSV is FEA-09.3 to FEA-09.6; HTML is FEA-09.8 to FEA-09.11, sorted by name ascending, without icons; XML is FEA-09.13 and FEA-09.14.

FEA-09.17 **No other export formats.** There is no export of a single entry or a single group, as in the reference. Neighbor exports: attachments to files (MOD-05), TOTP setup code (FEA-04), passkeys (INT-04), shared groups (INT-08).

FEA-09.18 **Secrets while exporting.** The export text is built in Rust in a secret buffer and written straight to the file (or standard output), then wiped. No exported value passes through the screen layer; the screen sends only the chosen path and options. Nothing exported goes to logs.

FEA-09.19 **Round trip.** A CSV export imported with FEA-08 (CSV kind, defaults) maps all 10 columns by itself (FEA-08.20), drops the common root (FEA-08.24) and gives back the same groups (those with entries) and the same values in those 10 columns; the recycle bin comes back as a normal group named like the bin; everything in the "leaves out" column is lost. A Larsal XML export imported with `larsal import` (FEA-08.61) gives back everything, attachments included.

## Edge cases and errors

| ID | When | Larsal text |
|---|---|---|
| MSG-EXP-CONFIRM | FEA-09.2 | Title: Export without encryption? Text: The file will hold every password and secret in this vault as plain text. Anyone who can open the file can read them. |
| MSG-EXP-FAILED | FEA-09.15 | Larsal couldn't save the <CSV / HTML / XML> export: <system reason>. Any file already at that place is unchanged. |
| MSG-EXP-FORMAT (command line) | unknown format | <value> is not an export format. Use xml, csv or html. |

- Group named `A/B` under root `R`: CSV Group `R/A/B`; a CSV import makes two levels (FEA-08.25).
- Title `Specials <tag> & "quotes" 'apos' ]]>`: CSV `"Specials <tag> & ""quotes"" 'apos' ]]>"`; HTML entry title `Specials &lt;tag&gt; &amp; &quot;quotes&quot; &#39;apos&#39; ]]&gt;`.
- Notes with CR LF inside: CSV writes CR LF raw inside the quotes; the record still ends with LF.
- Entry whose only content is an attachment: one CSV line; not in the HTML page; XML keeps the attachment (FEA-09.14).
- URL of 150 characters: HTML text = first 100 characters + an ellipsis, link target = the full URL.
- A value holding U+0001: removed in XML (FMT-12), kept in CSV and HTML (escaped only per FEA-09.11).
- Vault locked while the save dialog is open: the export is cancelled and nothing is written (APP-02).
- Disk full or read-only folder: MSG-EXP-FAILED, target untouched (AT-I02, AT-I03).

## Security notes

- An export is the whole vault in clear. The warning (SD-07) is mandatory for the desktop CSV and XML exports and visible in the HTML dialog; it must not be turned off by a setting.
- Exported files are owner-only (0600, AT-I06), written atomically and never through a link (AT-I04). The reference writes them world-readable under the usual umask.
- HTML export: everything is escaped (AT-E01 style); only http and https links (AT-E02 style); a strict Content-Security-Policy, so a hostile vault cannot make the exported page run script or load remote content when the user opens it (L09-2).
- CSV values starting with `=`, `+`, `-` or `@` are written as they are, as in the reference; a spreadsheet may treat them as formulas. Larsal does not change them, so a CSV round trip stays exact; the warning covers it.
- Export must never draw random values or touch the vault file (CRY-03).
- Secrets stay in Rust secret buffers and are wiped after writing (FEA-09.18, SR-07, AT-C06).

## Test cases

Demo vault V (built with the reference tool on 2026-10-24, password `demo-pass-1`, scratch copy): root `Passwords` holds entry "Top Entry" (user `zoë`, password `root-pw`), group Work with entry "Mail" (user `alice2` after one edit, password `demo-secret-1`, URL `https://example.com`, notes `line1` LF `line2 "quoted", comma`, attachment `note.txt`), group Work/Sub with entry "Bank" (user `bob`, password `pw,with"quote`), and the recycle bin with entry "Old" (user `carol`, password `gone-pw`). Times below are V's.

| Case | Given | When | Then |
|---|---|---|---|
| 09-01 availability (FEA-09.1) | V locked; then unlocked with an unsaved title change "Top Entry" → "Top" | Open File > Export; export CSV | Export items disabled while locked; the CSV holds `"Top"`; V still shows as modified and its file is unchanged |
| 09-02 warning (FEA-09.2) | V unlocked | ACT-EXPORT-CSV, press Return | Question MSG-EXP-CONFIRM; default No; nothing written. ACT-EXPORT-HTML shows the banner and no question |
| 09-03 CSV exact (FEA-09.3 to FEA-09.6) | V | Export CSV | Bytes: header line; `"Passwords","Top Entry","zoë","root-pw","","","","0","2026-10-24T22:53:24Z","2026-10-24T22:53:24Z"`; `"Passwords/Work","Mail","alice2","demo-secret-1","https://example.com","line1` LF `line2 ""quoted"", comma","","0","2026-10-24T22:53:25Z","2026-10-24T22:53:24Z"`; `"Passwords/Work/Sub","Bank","bob","pw,with""quote","","","","0",…`; `"Passwords/Recycle Bin","Old","carol","gone-pw",…`; every record ends with LF; `ë` as `C3 AB`; no BOM (matches the reference output, observed) |
| 09-04 CSV empty (FEA-09.4) | New vault with no entries | Export CSV | Exactly the header line and LF |
| 09-05 CSV scope (FEA-09.5) | V (Mail has two history items and an attachment) | Export CSV | 4 records; no history line; no attachment data; no line for a group without entries |
| 09-06 CSV TOTP (FEA-09.6) | `rich-v3.larsalvault` (testdata), entry "Full demo entry" with stored `otp` `otpauth://totp/Demo:demo-user?secret=JBSWY3DPEHPK3PXP…` | Export CSV | TOTP column `otpauth://totp/Full%20demo%20entry:demo-user?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Full%20demo%20entry` (regenerated label; observed); Icon `0` although a custom icon is set |
| 09-07 CSV no resolving (FEA-09.6) | Entry with Username `{REF:U@I:…}` pointing at another entry | Export CSV | Username column holds the reference text, not the target's value |
| 09-08 HTML dialog (FEA-09.7) | V | ACT-EXPORT-HTML | Dialog: banner, sort choices in the order name ascending (selected), name descending, vault order |
| 09-09 HTML frame (FEA-09.8) | V (empty name and description), file `/tmp/spec/d1.larsalvault` | Export HTML on the desktop | The head declares UTF-8 and holds the CSP of FEA-09.11; the page title and main heading are empty; no description text; the path `/tmp/spec/d1.larsalvault` is shown before the first group section |
| 09-10 HTML groups (FEA-09.9) | V | Export HTML | Group headings in order `Passwords`, `Passwords › Work`, `Passwords › Work › Sub`; no "Recycle Bin" heading and no "Old" |
| 09-11 HTML sort (FEA-09.9, FEA-09.10) | Root entries titled `b`, `A`, `c`, stored in that order; child groups `y`, `X` | Export with each sort choice | Ascending: entries `A`, `b`, `c`, groups `X`, `y`. Descending: `c`, `b`, `A`; `y`, `X`. Vault order: `b`, `A`, `c`; `y`, `X` |
| 09-12 HTML rows (FEA-09.10) | `rich-v3.larsalvault` | Export HTML | "Full demo entry" rows: User name, Password, URL, then custom fields `Demo PIN`, `Demo hint`, `Empty custom field` (empty value), `Spaces` (leading spaces kept), `otp`, then Notes with its line breaks kept; "Shared attachment 1", "Shared attachment 2" and the untitled empty entry are left out |
| 09-13 HTML escaping and links (FEA-09.11) | Entry title `Specials <tag> & "quotes" 'apos' ]]>`, URL `javascript:alert(1)`; entry with URL `https://` + 150 `a` | Export HTML | Entry title escaped as in "Edge cases"; the javascript URL is plain escaped text, not a link; the long URL is a link to the full URL showing 100 characters then an ellipsis |
| 09-14 HTML icons (FEA-09.12) | V | Export HTML on the desktop; then `larsal export --format html` | Desktop: every group heading and entry has a `data:image/png;base64,` image; command line: no image at all |
| 09-15 XML protected (FEA-09.13) | V (vault protects passwords) | Export XML | `<Value ProtectInMemory="True">root-pw</Value>`; no `Protected=` attribute anywhere; no `HeaderHash`; root element bytes as FEA-09.13; times base64 (4.1 vault, observed) |
| 09-16 XML version (FEA-09.13) | `rich-v3.larsalvault` and `rich-v4.larsalvault` | Export XML | Larsal, both files: base64 times, for example `<LastModificationTime>gPcj3Q4AAAA=` for 2024-01-01T00:00:00Z; 4.1 file: entry `QualityCheck` False, `PreviousParentGroup` and group tags present. Note: the reference gives `2024-01-01T00:00:00Z` for the 3.1 file (observed) |
| 09-17 XML attachments (FEA-09.14) | V (Mail has `note.txt` = `hello attachment` LF) | Export XML with Larsal; with the reference | Larsal: `Meta/Binaries` with `<Binary ID="0">` + base64 of the content, Mail's `<Value Ref="0"/>`; `larsal import` of it restores `note.txt`. Reference: `Ref="0"` and no `Binaries` (observed) |
| 09-18 XML everything (FEA-09.13) | V | Export XML | Holds the recycle bin with "Old", Mail's two history items (the first with user `alice`), the deleted-objects list, vault custom data; no new value for the FMT-10.25 item (equals the value in memory) |
| 09-19 file writing (FEA-09.15) | umask 022; target `out.csv` existing with mode 0644 and content `x`; then a read-only folder | Export CSV over it; then into the folder | Result mode 0600, content the export; read-only folder: MSG-EXP-FAILED, no file, no temporary file left |
| 09-20 link at target (FEA-09.15) | `out.csv` is a symlink to `victim.txt` | Export CSV to `out.csv` | `victim.txt` unchanged; `out.csv` replaced by a regular file (or refused per AT-I04) |
| 09-21 command line formats (FEA-09.16) | V | `larsal export` with no format, `--format csv`, `--format html`, `--format bogus` | XML; CSV equal to 09-03; HTML sorted ascending without icons; `bogus`: MSG-EXP-FORMAT on standard error, exit 1. Reference observed: `XMLX` gives XML, `Csvfoo` gives CSV |
| 09-22 no other formats (FEA-09.17) | V | Look for export of one entry or one group | None offered |
| 09-23 secrets (FEA-09.18) | Debug build, V | Export CSV, then dump memory and read logs (AT-C01, AT-C06) | The screen received only the path; after the export no buffer with `demo-secret-1` from the export remains; logs hold no value |
| 09-24 round trip (FEA-09.19) | V exported to CSV | Import it with FEA-08 CSV defaults into a new vault | Root `Passwords`; groups Work, Work/Sub and a normal group `Recycle Bin`; the four entries with the same 10 column values; no attachment, no history |

## How this was learned

- Read in the reference source: the CSV exporter, the HTML exporter and its desktop subclass that adds icons, the HTML export dialog and its layout file, the tab view's export handlers and export confirmation, the vault's XML extract routine and the writer it calls (protected values, binary pool only for version 3, header hash), the command line export command, the entry's TOTP export string routine, the main window menu layout, and the CSV exporter tests.
- Ran the installed command line tool 2.7.11 in `/tmp/spec-fea08-09/` on demo vault V (password `demo-pass-1`) and on scratch copies of `rich-v3.larsalvault` (`demo-pass-4`) and `rich-v4.larsalvault` (`demo-pass-5`): CSV, HTML and XML exports, format option matching, the unsupported-format error, the XML attachment references for 3.1 and 4.1, and re-import of edited XML exports (a `Meta/Binaries` pool added to a 4.1 export restores attachments).
- Not run: the desktop export screens (no window launch); dialog behavior comes from the source.
- Note for the lead: FMT-11 ("How this was learned") says the installed tool's XML export always writes the 3.1 form; the exports above show base64 times, custom data and 4.1 elements for a 4.1 vault, which agrees with FMT-16.17.
- Lead decisions (recommended option first):
  - L09-1: write a `Meta/Binaries` pool in every XML export, uncompressed (reference: content lost for 4.x vaults).
  - L09-2: HTML links only for http and https, plus a Content-Security-Policy meta element (reference: every scheme linked, no policy).
