# INT-02 Association and site access

Status: reviewed (LD-189, LD-191); INT-02.10's error 8 sentence added 2026-11-01 (LD-298), re-read and signed in E7-S7a; INT-02.11's error sentence aligned (LD-299)
Epics: E7-S2 (associations, site access prompts, the screens of this card), E7-S4 (what a fill carries: one-time codes, HTTP sign-in, hide-from-browser and skip-submit, saving and updating sign-ins); used by E7-S5 (INT-04) and E7-S7
Parity rows: SI-02, SI-04, SI-10, SI-11, SI-12, SR-16, SD-05 (recycle bin)

## What it does

A browser may use a vault only after the user connected it. Connecting stores the extension's identification public key in the vault's custom data under a name the user picks ("Firefox on MacBook"). From then on, a page asks, Larsal finds the entries whose URLs fit the page (INT-03), drops the ones the user's options hide, and tells the extension what it may see. Before a password, a one-time code or a passkey leaves Larsal, every entry must be allowed for that site: the user allowed it before for that host ("Remember"), or allows it now in Larsal's prompt, or turned on "Never ask". Denied hosts are remembered too. HTTP sign-in pop-ups always ask unless the user chose otherwise.

The extension can also save a new sign-in into the vault, update a changed password (after a question), read the vault's groups and make one (after a question).

Neighbor cards: INT-01 (the channel, request names, error numbers, limits), INT-03 (which entries fit a URL; the public suffix list), INT-04 (passkeys use this card's vault and option rules), MOD-02.17 (how group options resolve), MOD-04 (recycle bin), MOD-08 (placeholders, the save guard MOD-08.28), MOD-09 (expiry), MOD-12.18 (the vault settings actions), MOD-13.8 (a forced key change counts as locked), FMT-14 (the custom data keys), APP-01 (S-BRW settings), APP-02 (lock closes the prompts, SR-16), APP-05 (data and view-state changes), APP-06 (the unlock panel), APP-10.3 (screen capture protection of the prompts), FEA-01 (search), FEA-04 (codes).

## Inputs and outputs

**Vault custom data** (FMT-14; keys with a banned word given only as hex bytes of their ASCII text, "stored encoded, name rule"):

| Key | Value | Rule |
|---|---|---|
| prefix `4B 50 58 43 5F 42 52 4F 57 53 45 52 5F` (stored encoded, name rule) followed by the association name | the extension's identification public key, base64, 44 characters (INT-01.28) | INT-02.1 |
| `_CREATED_` followed by the association name | when it was connected; Larsal writes ISO 8601 UTC, for example `2026-10-28T09:12:00Z` | INT-02.1 |
| `_LAST_USED_` followed by the association name | when it last got a secret; ISO 8601 UTC; Larsal's own key | INT-02.9 |

**Entry custom data:**

| Key | Value | Rule |
|---|---|---|
| `4B 65 65 50 61 73 73 58 43 2D 42 72 6F 77 73 65 72 20 53 65 74 74 69 6E 67 73` (stored encoded, name rule): the site access item | compact JSON object `{"Allow":[hosts],"Deny":[hosts],"Realm":""}` | INT-02.16 |
| `BrowserHideEntry`, `BrowserSkipAutoSubmit`, `BrowserOnlyHttpAuth`, `BrowserNotHttpAuth` | `true` or `false` | INT-02.14 |
| `BrowserLastUse` | compact JSON object: association name → ISO 8601 UTC time; Larsal's own key | INT-02.9 |

**Group custom data** (MOD-02.17): `BrowserHideEntry`, `BrowserSkipAutoSubmit`, `BrowserOnlyHttpAuth`, `BrowserNotHttpAuth`, `BrowserOmitWww` (`true`/`false`, missing = inherit) and `BrowserRestrictKey` (an association name; empty = no limit).

**Custom fields:** names starting with the five characters `KPH: ` (K, P, H, colon, space) are extra fields for the browser (INT-02.21).

**Settings** (APP-01): S-BRW-09 notify (on), S-BRW-10 ask to unlock (on), S-BRW-11 match scheme (on, INT-03), S-BRW-12 best matches only (off, INT-03), S-BRW-13 allow expired (off), S-BRW-14 search every vault (off), S-BRW-15 never ask (off), S-BRW-16 update without asking (off), S-BRW-17 HTTP sign-in without asking (off), S-BRW-18 extra fields (on).

**Outputs:** the replies of INT-01's requests (summaries and full entries), the Connect dialog, the site access prompt, the update and create-group questions, the vault picker, a notification, and four screens: the settings page, the entry editor's Browser page, the vault settings Browser Keys page, the Browser report.

## Rules

### Associations

INT-02.1 **Storage.** An association is one vault custom data item: key = the prefix (stored encoded, name rule) + the name; value = the identification public key in base64, exactly as the extension sent it in `connect`. A second item `_CREATED_` + name holds the time it was made. These are the reference's keys, so both apps list, keep through merges and remove the same browser connections (D-INT02-1); the reference's merge never removes keys with this prefix (FMT-14.20). Larsal reads `_CREATED_` values in any form: ISO 8601 is shown as a date; any other text (the reference writes the system locale's short date and time) is shown as stored (D-INT02-2).

INT-02.2 **Names.** A name is the text after trimming spaces at both ends: 1 to 64 characters, no control characters (U+0000 to U+001F, U+007F to U+009F) and no line breaks. It must not already be used in that vault: no item with the prefix + that exact name exists (compared code unit by code unit). Larsal never overwrites an association (D-INT02-3). Reference difference: any non-empty text, and an existing name is overwritten after a question, which silently cuts off the other browser.

INT-02.3 **Connect: before the dialog.** For `connect` (INT-01.30) Larsal needs: a valid proof of `id_key` (INT-01.28; else error 8), the shown vault unlocked and not behind MOD-13's forced prompt (else error 1; the extension may send `unlock` first). When the shown vault already stores this `id_key` under some name, Larsal answers at once with that name and the vault id, without a dialog.

INT-02.4 **The Connect dialog** (frame `dialogs-connect-a-browser`). Larsal comes to the front and shows, over the vault's window:
- title "Connect a new browser?";
- text "A Larsal extension asks to connect to “‹vault name›”. Name it so you know it later. Only allow it if you just installed the extension." (‹vault name›: the vault's name, else its file name without the extension);
- a "Name" field, filled with the request's `name` when that is a valid name (INT-02.2), else "‹browser› on ‹computer name›" (‹browser› from the hello, INT-01.20; ‹computer name›: the Mac's name from System Settings › General › Sharing), else "‹browser› 2", "‹browser› 3" … when taken;
- the line MI02-01 with the four pairing words (INT-02.5); the frame lacks this line (mockup gap, D-INT02-4);
- buttons "Deny" and "Connect" (primary; Return chooses it, Escape chooses Deny). "Connect" is disabled while the name is not valid; a name already used shows MI02-02 under the field.
- One dialog at a time (INT-02.15). It closes as Deny after 120 seconds, when the vault locks (SR-16), when the session ends, and when integration is turned off. The dialog is protected from screen capture like Larsal's other windows (APP-10).

INT-02.5 **Pairing words.** Four words that the extension shows too (frame `extension-popup-first-connection`: "Check that Larsal shows the same four words"), so the user can tell Larsal's dialog for this browser from one another program raised (AT-F04). Computed: D = SHA-256 over the ASCII bytes `browser-bridge pairing v1`, then Larsal's 32-byte session public key, then the client's 32-byte session public key, then the 32-byte `id_key`. N = the first 8 bytes of D as an unsigned big-endian number. For i = 1 to 4: word i = entry (N mod 7,776) of Larsal's built-in word list (FEA-03: 7,776 words, in file order, first entry 0), then N = N div 7,776. Shown in order, lower case, separated by spaces. Bitwarden asks the user to compare a fingerprint between its desktop app and extension in the same way ("Require verification for browser integration").

INT-02.6 **Connect: the result.** "Connect": Larsal writes the association item and `_CREATED_` + name with the current time (a data change, APP-05; the vault's custom data change time moves, FMT-14), and answers `{"name":…,"vault":…}`. "Deny", the timeout, a lock or a closed session: nothing is written; error 6 (or nothing, INT-01.45). Reference difference: its dialog is a plain name field and a save button; it shows no words and gives no default name.

INT-02.7 **Check.** `check` lists every unlocked vault (not behind MOD-13's prompt) that stores the session's proven `id_key`, with the vault id, the vault name and the association name. None: error 8. `check` never opens a dialog and never unlocks anything.

INT-02.8 **Disconnect** (frame `vault-vault-settings-browser-keys`; MOD-12.18). "Disconnect" on a connected browser asks MI02-03 (default "Cancel"), then removes its association item, its `_CREATED_` item and its `_LAST_USED_` item. A session that used it gets error 8 at its next request. Entries' `BrowserLastUse` records stay (they are history). The frame has no rename and no value editing: MOD-12.18's rename and edit rules have no screen yet and wait for a mockup addition (Review 2026-10-28, R02-3); Larsal builds none until then.

INT-02.9 **Last use** (D-INT02-5). When Larsal gives a password (`logins.get`), a one-time code (`code.get`) or a passkey result (INT-04) for an entry, Larsal records the time under each association name by which the vault holds the session's key: `_LAST_USED_` + name in the vault custom data, and name → time in the entry's `BrowserLastUse` item (compact JSON, names sorted, at most 16 names; the oldest time is dropped first). Both are view-state changes (APP-05): they do not make the vault changed, add no history item, do not move the entry's modification time, and are written with the next save or silently at lock. `logins.recent` gives, for this session's association names, up to 5 entries with the newest `BrowserLastUse` times, newest first, as summaries (INT-02.20). The frames `editor-editor-browser` ("Browsers that used this entry") and `vault-vault-settings-browser-keys` ("last used today, 09:12") read these items. The reference records no use.

### Which vaults a request uses

INT-02.10 **Usable vaults.** A request uses the shown vault when it stores the session's key; with S-BRW-14 on, every unlocked vault that stores it, in the order the vaults are open (APP-09). Locked vaults and vaults behind MOD-13's forced prompt are never used (MOD-13.8). No usable vault: error 1 when no vault the request may use is unlocked; error 8 when one is unlocked but none of them stores the session's key (INT-02.8, INT-01.30, INT-01 T86; LD-298). A save (INT-02.24) with S-BRW-14 on and more than one usable vault shows the vault picker (INT-02.27); otherwise it uses the shown vault. Reference difference: its save picker lists every unlocked vault, associated or not. Passkeys follow this rule too since INT-04's second review (INT-04.20, LD-191).

INT-02.11 **Unlock on request** (S-BRW-10, on). `unlock`: with S-BRW-10 off, error 1 at once. When the shown vault is unlocked, Larsal answers at once. Otherwise Larsal shows the unlock panel for the shown vault (APP-06; purpose text MI02-04; Touch ID starts by itself when available, APP-04) and answers when the panel closes: unlocked → `{"vault":…}` (the vault id only when the vault stores the session's key), cancelled → error 6. A second `unlock` while the panel shows waits for the same panel and gets the same answer. Other requests never unlock; they get INT-02.10's error 1 or 8 while no usable vault is unlocked. Reference difference: any request can carry an unlock flag, and the reply is error 1 at once while Larsal raises its window.

INT-02.12 **What is never offered.** Entries and groups in the recycle bin (MOD-04, SD-05), history items, and the template group's entries are never offered, filled, counted or searched over the bridge.

### Which entries a site may see

INT-02.13 **The steps, in order.** For `logins.find`, `logins.get` and `code.get`, per usable vault, Larsal walks the groups in tree order (a group, then its subgroups depth-first, the root first) and each group's entries in stored order, and keeps an entry when all hold:
1. it is not in the recycle bin (INT-02.12);
2. its group is not hidden and the entry is not hidden (INT-02.14);
3. its group's resolved `BrowserRestrictKey` is empty or equals one of the names by which this vault holds the session's key;
4. its URLs fit the page (INT-03), or its site access item allows the page host (INT-03.12);
5. for an HTTP sign-in request (`http_auth` true) its "never for HTTP sign-in" option is off; for any other request its "only for HTTP sign-in" option is off;
6. it is not expired, unless S-BRW-13 is on (MOD-09.16);
7. its site access is not "denied" (INT-02.17).
Each kept entry then has the access state "allowed" or "ask" (INT-02.17 to INT-02.19). The same entry found through two of its URLs is kept once. Reference difference: for HTTP sign-in it skips steps 6 and 7, so expired and denied entries reach its prompt (D-INT02-9); and it repeats the whole search once per dot in the host when nothing is found, with the same result each time.

INT-02.14 **Entry and group options** (D-INT02-10). For each of hide, skip-submit, only-HTTP and never-HTTP: when any group from the entry's group up to the root has the option's key, the first such group decides (MOD-02.17: on when its value is exactly `true`); otherwise the entry's own key decides (on when exactly `true`). `BrowserOmitWww` exists only on groups and is used by INT-03.9. Reference difference: for the two HTTP options it treats the option as on when either the entry says `true` or a group resolves on, so a group's `false` does not override an entry's `true`; Larsal lets the group decide, which is also what both apps' editors show.

INT-02.15 **One dialog at a time.** Larsal shows at most one bridge dialog at a time (Connect, site access, update, create group, vault picker; passkey dialogs of INT-04 join the same line). Further requests that need a dialog wait in arrival order, at most 16 across all sessions (INT-01.44); more get error 42. A waiting request whose session ends, or whose vault locks, leaves the line. Each dialog comes to the front over Larsal's window or alone when Larsal's window is hidden, and Larsal returns to its earlier state (hidden, in the background) after the dialog closes, as the reference does. Times: Connect 120 s, the others 60 s, then Deny without remembering. Reference difference: a second request while a prompt shows gets no prompt; it gets only its entries that were already allowed, at once.

INT-02.16 **The site access item.** Read from the entry's custom data (key above). Reading: up to 1,048,576 bytes, else the item is treated as absent; a JSON object; `Allow` and `Deny`: arrays whose string elements are hosts (other elements ignored); `Realm`: kept but unused (the reference never sets it). Hosts are compared in ASCII form: each read host is lower-cased and its non-ASCII labels encoded with MOD-08.9's host encoding (LD-58); a host that cannot be encoded is ignored. A host in both lists counts as denied (reference: allowed, because it tests Allow first). An item that is not valid JSON counts as absent and is replaced only when Larsal next writes it. Writing (on Remember, in the editor, never otherwise): `{"Allow":[…],"Deny":[…],"Realm":"…"}` compact, members in that order, hosts in ASCII form, each list sorted and without repeats, at most 1,000 hosts per list (the oldest beyond that are dropped, in list order), `Realm` as read or empty. Adding a host to one list removes it from the other. Writing it is an entry data change that moves the entry's modification time without a history item (as the reference). Reference: hosts as its URL parser gives them (Unicode for some top-level domains), lists in no fixed order.

INT-02.17 **Access state.** With P the page host (the host of `url`) and F the host of `form_url` when present and different from P:
- **denied** when P or F is in Deny;
- **allowed** when P is in Allow and (no F, or F is in Allow);
- **ask** otherwise.
Then: S-BRW-15 ("Never ask before giving access", off) turns ask into allowed, except for HTTP sign-in (below), INT-02.19 and INT-02.22's outside fills. For HTTP sign-in every entry is ask (also allowed ones), unless S-BRW-17 is on, which makes every non-denied entry allowed (SI-02). Denied entries are left out of every reply (step 7).

INT-02.18 **The site access prompt** (frame `dialogs-browser-asks-for-an-entry`). Shown for `logins.get` and `code.get` when one or more of the asked entries are in state ask; entries already allowed are answered without it. Contents:
- title "‹browser› asks for a sign-in on ‹P›" (‹browser› from the hello; ‹P› in ASCII form, LD-58);
- text "Choose the entries ‹browser› may use on this site.";
- one row per asked entry in state ask: a checkbox (checked), the title and the username, both resolved (MOD-08), as plain text (AT-E01);
- the checkbox "Remember for ‹P›" (unchecked); hidden for HTTP sign-in and for INT-02.19;
- for INT-02.19, its line (MI02-05 or MI02-06) above the rows (mockup gap, D-INT02-7);
- buttons "Deny" and "Allow Selected" (primary, disabled while no row is checked). Escape = Deny.

Result: "Allow Selected" gives the checked entries for this request; with Remember, each checked entry gets P (and F, when present) added to Allow, each unchecked entry gets them added to Deny. "Deny" gives nothing (error 6); with Remember, every row gets P (and F) added to Deny. Timeout, lock, session end: nothing given, nothing remembered. Reference: same lists and Remember; its rows start selected and its Allow button has focus; it also has a per-row button that blocks the entry for this site (always remembered as Deny), which Larsal leaves out: unchecking with Remember does the same.

INT-02.19 **Frames and forms of other sites** (AT-F06; D-INT02-7). When the registrable domain (INT-03.10) of `top_url` differs from that of `url` (the sign-in form is in a frame from another site), or the registrable domain of F differs from P's (the form sends to another site); for a host without a registrable domain (an IP address, a one-label host) its whole host stands in: every entry is ask, whatever Allow, S-BRW-15 or S-BRW-17 say; Remember is hidden and nothing is remembered; the prompt shows MI02-05 (frame) or MI02-06 (form). Matching itself uses `url` (INT-03). Reference difference: it has no top page; a remembered allow for a form host lets later fills go silently to that host.

INT-02.20 **Summaries.** `logins.find`, `logins.search` and `logins.recent` give, per entry, without any secret: `vault`, `id`, `title` and `username` (resolved, MOD-08), `group` (the group's name), `code` (true when FEA-04 settings are valid), `passkey` (true when it holds a passkey, INT-04), `skip_submit` (INT-02.14), `expired` (true or absent), `access` (`allowed` or `ask`; search and recent results that do not fit the page are always `ask`). `logins.find` orders them by INT-03.14 and keeps only the best group when S-BRW-12 is on; at most 200 entries (the best first). `logins.find` never opens a dialog (D-INT01-9).

INT-02.21 **Full entries.** `logins.get` takes `ids` (1 to 20 `{"vault","id"}` pairs). Each pair must name an entry that INT-02.13 keeps for this page, or one that `logins.search` or `logins.recent` could give (an outside fill, INT-02.22); others are left out. Entries in state ask go to one prompt (INT-02.18). The reply lists, in the order asked, each given entry: `vault`, `id`, `title`, `username`, `password` (resolved, MOD-08), `code` (the current one-time code when FEA-04 settings are valid), `skip_submit`, `expired`, and, with S-BRW-18 on, `fields`: the entry's custom fields whose names start with `KPH: `, each `{"name": the rest of the name, "value": resolved}`, in name order. Nothing given because nothing fit: error 15; because the user denied: error 6. Reference difference: one request finds, asks and returns passwords together (D-INT01-9), and it sends the extra fields with the prefix.

INT-02.22 **Search, recent and outside fills.** `logins.search` runs Larsal's search (FEA-01, the text as a query with default fields) over the usable vaults and gives up to 50 summaries, leaving out what INT-02.12 to INT-02.14 hide (recycle bin, hidden, restricted to another browser) and expired entries unless S-BRW-13 is on. `logins.recent`: INT-02.9. Filling such an entry on a page it does not fit (frame `extension-popup-search-everything`: "These do not match github.com, so Larsal asks before filling them here.") always asks, whatever S-BRW-15 says; there Remember adds P to the entry's Allow list, which makes the entry fit P from then on (INT-03.12; D-INT02-8). The reference has no search; its list-all request (off by default) gives every title and URL without site rules.

INT-02.23 **One-time codes.** `code.get` gives the current code of one entry, its period and the seconds left (FEA-04), only when the entry is kept for the page by INT-02.13 (else error 18) and allowed (asking first when its state is ask). No valid one-time settings: error 15. Reference difference: it gives the code of any entry id in the vault (or in every vault with search-all on) with no site check (SI-11).

### Saving and updating

INT-02.24 **Save a new sign-in.** `logins.save`:
- The username and password are checked by MOD-08.28's test (D-08-5); a placeholder or reference gives error 34. Each is at most 65,536 bytes; `title` at most 1,024 characters; longer: error 43.
- Vault: INT-02.10. Group: the given group id when it names a group of that vault outside the recycle bin, else the default group (INT-02.26).
- The new entry: a new random id; title = `title` when given and not empty after trimming, else P in ASCII form; username; password; URL = `url` without its query, fragment and user info (scheme, host, port, path); icon 1 (MOD-06); everything else as a new entry (MOD-01). No Larsal dialog: the extension's own "Save this sign-in?" is the confirm (frame `extension-in-page-save-sign-in`). A data change (APP-05). Reply `{"entry":{"vault","id"}}`.
- `icon` true: Larsal downloads the website icon only when the user has turned on website icon downloads (MOD-06, SN-02); otherwise it is ignored.
- Reference differences: it stores the page URL with its query string (which may hold a session token) and uses a default group whose name holds a banned word.

INT-02.25 **Update a sign-in.** `logins.update`:
- The entry must be kept for this page by INT-02.13 and not denied (else error 18); Larsal does not add a new entry when the id is unknown. Reference difference: any entry id in the vault may be updated, and an unknown id silently makes a new entry.
- When the entry's password is a reference to another entry (MOD-08), Larsal follows it to the entry that holds the value, at most 10 steps; a missing target or a loop gives error 18. Reference difference: a reference whose target id cannot be read (an all-zero id, or a reference by title) makes its loop never end, and so does a loop of references.
- The values are checked as in INT-02.24 (error 34).
- When neither the username nor the password differs: `{"updated":false}`, no question. Reference difference: it never updates an entry whose username is empty.
- Otherwise, unless S-BRW-16 is on, Larsal asks MI02-07 with "Not Now" and "Update" (primary). "Update": the password changes, and the username too unless the entry's username is a reference; a normal edit with a history item (MOD-03); `{"updated":true}`. "Not Now", timeout, lock: error 6.

INT-02.26 **Groups.** `groups.list` gives the tree of the given usable vault (else the shown one): each group's `id`, `name` and `children` in stored order, leaving out the recycle bin and everything under it (reference). `groups.create` with a `path` (INT-04.24's path rules: `/` between levels, names exact): an existing group is returned without a question; otherwise Larsal asks MI02-08 ("Create" primary, "Cancel"); "Create" makes every missing level with a new random id and the group key `BrowserHideEntry` = `false` on each made level (reference), then returns the last level. Cancel: error 6. Default group for new sign-ins: the first group named "Browser Sign-ins" in tree order outside the recycle bin, else a new one under the root with icon 1, made without a question. Passkeys differ (INT-04.24): their default "Browser Passkeys" is a path from the root, and a missing one is made only after MI02-08, as the reference does for its own default.

INT-02.27 **The vault picker.** A small dialog: MI02-09, one row per usable vault by name (the shown one selected), "Cancel" and "Save Here" (primary). Cancel: error 1. Not in the locked frames (mockup gap, D-INT02-4).

### Screens

INT-02.28 **Settings page** (frame `settings-settings-browser-integration`). "Let browsers use Larsal" with "Fill sign-ins, one-time codes and passkeys through the Larsal extension." is S-BRW-01; while off, every row below is disabled (APP-01.5). "Browsers": INT-01.8. "When a browser asks": "Show a notification" S-BRW-09 (INT-02.31), "Ask to unlock a locked vault" S-BRW-10, "Offer only the best matches" S-BRW-12, "Search every open vault" S-BRW-14, "Never ask before giving access" S-BRW-15 with "Not recommended: any site that matches gets the entry.", "Allow passkeys on localhost" S-BRW-19 with "For web developers." "Advanced": the own proxy program S-BRW-23 (with its path field S-BRW-24 when on; the frame's label is replaced by "Use my own proxy program", LD-167) and "Rewrite the browser setup files at start" S-BRW-21. Settings without a row in the frame (S-BRW-11, -13, -16, -17, -18) keep their values and defaults and are not shown (D-INT02-12); S-BRW-20, -22 and -25 to -27 do not exist in Larsal (D-INT01-6, D-INT01-10).

INT-02.29 **Entry editor, Browser page** (frame `editor-editor-browser`; shown while S-BRW-01 is on, as the reference). Top to bottom:
- "Sites" with "The browser extension fills this entry on its website and on these sites."
- "Also allowed on": the Allow list as removable chips, then a field "Add a site…". "Never on": the Deny list, same form. Typing a host or a URL and Return adds its host in ASCII form (INT-02.16); text that gives no valid host (INT-03.4) shows MI02-10 and adds nothing. Removing a chip removes the host. Changes are written when the editor is saved (INT-02.16).
- "Options": "Hide this entry from the browser" (`BrowserHideEntry`; subline "The extension never sees it."; LD-167 replaces the label with "Never offer this entry to browsers"), "Fill, but do not submit" (`BrowserSkipAutoSubmit`; "You press the sign-in button yourself."), "Only for sign-in pop-ups (HTTP)" (`BrowserOnlyHttpAuth`; "For routers and old intranet pages."). When a group decides an option (INT-02.14), its switch shows the group's value, is disabled and carries MI02-11. Saving writes `true` for on and `false` for off, but writes nothing for off when the entry had no key (reference). `BrowserNotHttpAuth` has no switch in the frame; Larsal keeps and applies a stored value.
- "Browsers that used this entry": one row per name in `BrowserLastUse`, newest first, with the browser's logo (from the first word of the name when it names a known browser, else a generic icon) and the time (today: the time; else the date).

INT-02.30 **Vault settings, Browser Keys page** (frame `vault-vault-settings-browser-keys`). "Connected browsers": one row per association item of the vault (Larsal's and the reference's), sorted by name: logo (as INT-02.29), the name, "Connected ‹created› · last used ‹last used›" (MI02-12; "never used" when there is no `_LAST_USED_` item), "Disconnect" (INT-02.8). "Stored permissions": "Site permissions kept in entries", "‹n› entries hold allowed or blocked sites" (live entries with a site access item that lists at least one host), "Remove all…" (MOD-12.18 `vault.act.forget_site_access`).

INT-02.31 **Notification** (S-BRW-09, on; D-INT02-11). When Larsal gives a password, code or passkey result without any dialog (remembered allow or S-BRW-15), it posts a macOS notification MI02-13 naming the browser and the page host, never a title or username, at most once per browser and host in 10 minutes. The reference has this setting hidden and without effect.

INT-02.32 **Browser report** (frame `reports-reports-browser`). For the shown vault: one row per live entry that has a site access item listing a host or any of the four entry options on (INT-02.14, as resolved): "Entry" (title, and under it the main URL's host), "Also allowed on", "Never on" (hosts, or "—"), "Options" (MI02-14 words for the options that are on, joined with ", ", or "—"). Rows in title order. Under the table: MI02-15 with the vault's associations and their connect dates. "Check again" builds the table again. The reference's report also lists entries without settings and has filter switches the frame does not have.

### Messages

Larsal's own wording; IDs are ours; ‹…› marks a placeholder. The frame texts quoted in the rules above are Larsal's locked design.

| ID | Kind | Rule | Larsal text |
|---|---|---|---|
| MI02-01 | line | INT-02.5 | Check that the extension shows: ‹word 1› ‹word 2› ‹word 3› ‹word 4› |
| MI02-02 | field error | INT-02.2 | A browser with this name is already connected. Choose another name. |
| MI02-03 | question | INT-02.8 | Disconnect “‹name›”? That browser can't fill from this vault until you connect it again. Buttons: Cancel, Disconnect |
| MI02-04 | panel purpose | INT-02.11 | ‹browser› asks to use this vault. |
| MI02-05 | prompt line | INT-02.19 | This sign-in form is inside a frame from ‹frame host› on ‹top host›. |
| MI02-06 | prompt line | INT-02.19 | This form sends what you type to ‹form host›. |
| MI02-07 | question | INT-02.25 | Update the sign-in “‹title›” for ‹host› with what ‹browser› sent? |
| MI02-08 | question | INT-02.26 | ‹browser› wants to make the group “‹path›” in “‹vault name›”. |
| MI02-09 | dialog title | INT-02.27 | Save the sign-in in which vault? |
| MI02-10 | field error | INT-02.29 | That is not a website address Larsal can use. |
| MI02-11 | note | INT-02.29 | Set by the group “‹group name›”. |
| MI02-12 | row line | INT-02.30 | Connected ‹date› · last used ‹date or time› / Connected ‹date› · never used |
| MI02-13 | notification | INT-02.31 | ‹browser› filled a sign-in on ‹host›. |
| MI02-14 | words | INT-02.32 | hidden / fill, no submit / HTTP only / not for HTTP |
| MI02-15 | line | INT-02.32 | Connected browsers: ‹name› (since ‹date›) · … Manage them in Vault Settings. |

## Edge cases and errors

- **The vault is locked while a prompt shows:** the prompt closes, nothing is given or remembered (error 6), the vault locks without waiting for it (SR-16).
- **The same extension connected to two vaults:** two association items, one in each vault; with S-BRW-14 on, `logins.find` lists entries of both, each with its vault id.
- **A vault holds the session's key under two names** (connected twice by the reference's rules): both names count for `BrowserRestrictKey` and for last use.
- **The reference's associations** show on the Browser Keys page and can be disconnected; Larsal's extension can never use them (it does not hold their secret keys, INT-01.28).
- **An association name with a slash, an emoji or quotes:** allowed (INT-02.2); stored as given.
- **A site access item from a hostile vault** (huge, deep JSON, thousands of hosts): bounded by INT-02.16; it can only allow or deny hosts for that entry.
- **A host in Allow that the entry's URLs do not fit:** the entry fits that host anyway (INT-03.12); it shows in "Also allowed on".
- **An entry both hidden and allowed:** hidden wins (step 2 comes first).
- **`BrowserRestrictKey` naming a disconnected browser:** that group's entries reach no browser until the key is changed (reference).
- **An expired entry with S-BRW-13 on:** listed with `expired` true (MOD-09.16); the extension marks it.
- **Username is a reference, password changes through `logins.update`:** the username stays the reference.
- **Two prompts for the same entry and host from two tabs:** the second waits (INT-02.15); if the first was remembered as allowed, Larsal checks again before showing the second and answers without a prompt.
- **MOD-13 forced key change prompt open:** the vault is treated as locked (MOD-13.8, T15 of MOD-13).
- **Not on Mac.** The reference's dialogs are the same on every platform; Larsal 1.0 is Mac only.

## Lead decisions

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT02-1 | Where associations live (INT-02.1) | (a) The reference's vault keys (prefix and `_CREATED_`); (b) Larsal's own prefix | (a). Both apps then list and remove every browser connection of a vault, the reference's merge protects the prefix (FMT-14.20), and `BrowserRestrictKey` names one set of names. Larsal's extension cannot use the reference's associations and the reverse, because each extension holds its own secret key (INT-01.28) and talks only to its own host program |
| D-INT02-2 | Format Larsal writes into `_CREATED_` | (a) ISO 8601 UTC, reading any form; (b) the system locale's short date and time, as the reference | (a). A locale text cannot be read back reliably (it changes with the locale); the reference only shows the value as text, so it shows Larsal's ISO text fine |
| D-INT02-3 | A name already used (INT-02.2) | (a) refuse, ask for another name; (b) overwrite after a question, as the reference | (a). Overwriting silently cuts off the other browser; the reference's own documentation warns about it |
| D-INT02-4 | Mockup gaps | (1) the four words line in `dialogs-connect-a-browser` (the extension's frame says Larsal shows them); (2) the frame and form lines in `dialogs-browser-asks-for-an-entry` (INT-02.19); (3) the vault picker (INT-02.27); (4) the update and create-group questions (MI02-07, MI02-08) | Add all four to the locked mockup with the owner's approval (AT-K05). (1) is needed for the pairing check to work at all |
| D-INT02-5 | Last use data (INT-02.9) | (a) `_LAST_USED_` items and an entry item `BrowserLastUse`, written as view-state changes; (b) memory only, lost at quit; (c) drop the rows from the frames | (a). The locked frames show last use across days, so (b) cannot fill them and (c) changes the locked design. View-state changes cause no history and no "changed" mark (APP-05); the data stays inside the encrypted vault |
| D-INT02-6 | Several dialogs at once (INT-02.15) | (a) one at a time, the rest wait in a line; (b) refuse while one shows, as the reference | (a). Two tabs asking at once is normal; (b) makes the second fill fail with "no logins" for no visible reason. The line is bounded (16) for AT-F07 |
| D-INT02-7 | Frames and forms of other sites (INT-02.19) | (a) always ask, never remember, name the other host; (b) treat like any page, as the reference | (a). A sign-in form inside another site's frame, or a form whose action was changed to another site, is how credentials get stolen (AT-F06). Bitwarden filled such frames until Flashpoint's 2023 report; since then it fills frames only from the page's own domain or a URL the user added to the item, and otherwise shows the alert "Form is hosted by a different domain" before filling (Flashpoint blog "Bitwarden password pilfering", Bitwarden community thread of that title, PCWorld 2023) |
| D-INT02-8 | What an allowed host means (INT-02.16, INT-02.22, INT-03.12) | (a) Allow only skips the prompt, as the reference: an allowed host the entry's URLs do not fit never sees it; (b) an allowed host also makes the entry fit that host | (b). The locked editor frame says "fills this entry on its website and on these sites" with an "Add a site…" field, and the search frame implies that a remembered outside fill works next time; only (b) makes both true. Hosts get into Allow only by the user (prompt or editor) or by the reference's Remember. The reference ignores it for matching, which is a harmless difference |
| D-INT02-9 | HTTP sign-in and denied or expired entries | (a) deny and expiry apply first, as for pages; (b) reference: they reach the prompt | (a). A remembered "never" should hold for every kind of request |
| D-INT02-10 | Group against entry options (INT-02.14) | (a) the group decides whenever a group has the key; (b) reference: for the HTTP options, entry `true` or group on | (a). One rule for all four options, and it is what both apps' editors already show |
| D-INT02-11 | "Show a notification" (INT-02.31) | (a) notify on fills without a dialog, host and browser only, at most once per 10 minutes per host; (b) no effect, as the reference; (c) drop the row | (a). The locked frame shows the switch on, so it must do something useful; a silent fill is the moment a user may want to know about; no title or username, because notifications can show on the lock screen |
| D-INT02-12 | Settings the frame does not show | (a) keep defaults, not shown; (b) add rows under "Advanced" (needs a mockup change) | (a). Their defaults are the safe values (match scheme on, no expired entries, ask before updates and HTTP sign-ins, extra fields on); add rows only if users ask. A settings import that weakens them still needs the user's confirm (LD-54) |
| D-INT02-13 | Updates by id (INT-02.25) | (a) the entry must fit the page, unknown id is an error; (b) any id, unknown id adds an entry, as the reference | (a). An extension bug or a hostile page cannot then overwrite an unrelated entry's password, even behind the question |
| D-INT02-14 | URL of a saved sign-in (INT-02.24) | (a) without query, fragment and user info; (b) the full page URL, as the reference | (a). Query strings often carry one-time tokens; matching never uses them (INT-03.8) |

Check with Verify:

| ID | What to check |
|---|---|
| V-INT02-1 | The reference reads Larsal's `_CREATED_` value (ISO text) without trouble and lists Larsal's association in its vault settings table; the reference's command line or a demo vault opened in its settings view, with demo data only |
| V-INT02-2 | The reference reads a site access item Larsal wrote (members in Larsal's order, sorted lists) and keeps `BrowserLastUse` and `_LAST_USED_` items through its own save |

## Security notes

- **SI-02** (parity row): asks before a site gets a credential; remembers allow and deny per entry for the page host and the form host; HTTP sign-in always asks unless its option allows it; an always-allow option (off); one prompt at a time; prompts close on lock. Larsal goes further: other prompts wait instead of failing (INT-02.15); frames and forms of other sites always ask and are never remembered (INT-02.19, AT-F06); denied and expired entries never reach an HTTP sign-in prompt (D-INT02-9).
- **SI-04:** hide from the browser, skip submit, only or never for HTTP sign-in, ignore a leading `www`, one association only; expired entries refused unless allowed; extra `KPH: ` fields sent (S-BRW-18, on). Larsal makes groups decide uniformly (INT-02.14).
- **SI-10:** saving and updating; updates ask unless S-BRW-16; placeholders and references refused (MOD-08.28); updates follow a password reference. Larsal goes further: the updated entry must fit the page; references are followed at most 10 steps (INT-02.25).
- **SI-11:** Larsal gives one-time codes only for entries the site may use (INT-02.23).
- **SI-12:** the vault id and every vault-touching request need an association (INT-01.30, LD-73).
- **SR-16:** a lock closes every bridge dialog of that vault and gives nothing.
- **AT-F04:** an association needs the user's Connect click; the four words let the user see which request the dialog belongs to. **AT-F06:** INT-02.19.
- **Titles and usernames in dialogs:** shown resolved as plain text, never as markup (AT-E01). They are not secret from the user, but the prompts are kept out of screen capture (APP-10.3).
- **What `logins.find` shows:** titles and usernames of entries that fit the page reach the extension without a prompt (D-INT01-9). The extension must draw them only in its own frames where the page's scripts cannot read them (E7-S7).
- **Larsal cannot see the pick.** `logins.get` gives the password of an entry in state allowed to whichever associated session asks; that the user picked it is the extension's promise (E7-S7). The extension's "Fill when a page loads" option (frame `extension-extension-options`) asks without a pick (R02-4). For entries in state ask, Larsal's prompt is the pick.
- **What must never happen:** a password, code or passkey result for an entry in state ask without the user's Allow; a remembered allow for a frame or form of another site; an association made without the dialog; a recycle bin or hidden entry offered; a prompt that stays open after its vault locked.

## Test cases

No real browser: a test client speaks INT-01 over Larsal's socket with its own demo identification keys (K1, K2, K3 made at test start). Larsal runs hidden with a test settings file; dialogs are answered by the UI test harness (LarsalUITests) or, in Rust tests, by a scripted dialog answerer. Dates come from a fake clock.

Demo vault V (`access-demo.larsalvault`, password `demo-access-vault`), associations: `demo` = K1, `laptop` = K2. Groups and entries (passwords are demo values):
- Group Web (no options): E1 "Example Mail" `alex` / `demo-mail-pass`, URL `https://mail.example.com/login`, one-time secret `JBSWY3DPEHPK3PXP` (30 s, 6 digits); E2 "Example (work)" `work-bot` / `demo-mail-pass-2`, URL `https://example.com`; E3 "Hidden one" URL `https://example.com`, entry `BrowserHideEntry` = `true`; E4 "Expired one" URL `https://example.com`, expired at T−1 day; E5 "Router" URL `http://192.168.1.1`, entry `BrowserOnlyHttpAuth` = `true`; E6 "Shop" URL `https://shop.example.org`, custom field `KPH: pin` = `1234`, entry `BrowserSkipAutoSubmit` = `true`; E7 "Ref user" URL `https://example.net`, username `{REF:U@I:‹E1 id›}`, password `demo-net-pass`.
- Group Hidden (`BrowserHideEntry` = `true`): E8 URL `https://example.com`.
- Group Laptop (`BrowserRestrictKey` = `laptop`): E9 URL `https://example.com`.
- Recycle bin: E10 URL `https://example.com`.
Vault W (`second-demo.larsalvault`, password `demo-second-vault`): association `demo` = K1; E11 URL `https://example.com`.
Unless a case says otherwise: V shown and unlocked, W locked, session proven with K1, S-BRW defaults, page `https://example.com/login`, `top_url` the same.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-02.1 | V; K3 not stored | `connect` with K3, Connect in the dialog with name `Chrome on Test` | Vault custom data gains the prefix (stored encoded) + `Chrome on Test` = K3's base64 and `_CREATED_Chrome on Test` = the fake time in ISO form; reply holds the name and V's vault id |
| T02 INT-02.1 | `_CREATED_demo` = `10/24/26 8:11 PM` | Open Browser Keys | Row `demo` shows "Connected 10/24/26 8:11 PM" as stored |
| T03 INT-02.2 | Dialog open | Name `   ` (spaces), then `demo`, then 65 characters, then `a` + U+0007 | Connect disabled; `demo` shows MI02-02 |
| T04 INT-02.3 | V locked | `connect` with K3 | Error 1; no dialog |
| T05 INT-02.3 | K1 stored as `demo` | `connect` with K1 | Reply `demo` at once; no dialog |
| T06 INT-02.3 | Proof made for another session | `connect` | Error 8; no dialog |
| T07 INT-02.4 | Hello `browser` `Firefox`, computer name `Test Mac` | `connect` with K3 and no `name` | Name field `Firefox on Test Mac`; text names V's vault name |
| T08 INT-02.4 | Dialog shown (fake clock) | 120 s | Error 6; nothing written |
| T09 INT-02.4 | Dialog shown | Lock V | Dialog gone; error 6; nothing written; V locked at once |
| T10 INT-02.5 | Larsal key A, client key C, `id_key` I (INT-01 demo values) | Compute the words | SHA-256 `e5c612d6c7b89e3b584149871f0f5985ff4e2dbbd05a0255f5598a763754fcd8`; words `suspense bagginess crucial mongoose` |
| T11 INT-02.5 | Real session | Compare the dialog's words with the test client's own computation | Equal |
| T12 INT-02.6 | Dialog shown | Deny | Error 6; no custom data change; V not changed (APP-05) |
| T13 INT-02.7 | K1 in V and W, both unlocked | `check` | Both vaults listed with `connection` `demo` |
| T14 INT-02.7 | K3 in no vault | `check` with K3 | Error 8 |
| T15 INT-02.8 | Browser Keys page | Disconnect `laptop`, confirm | Prefix + `laptop`, `_CREATED_laptop`, `_LAST_USED_laptop` gone; a K2 session's next `logins.find` gets error 8 |
| T16 INT-02.9 | E1 allowed for `mail.example.com` | `logins.get` E1 on `https://mail.example.com/login` at fake time T | `_LAST_USED_demo` = T; E1's `BrowserLastUse` = `{"demo":"T"}`; V shows no changed mark; E1 has no new history item and the same modification time; after lock the file holds both |
| T17 INT-02.9 | E1 used at T, E6 at T+1 | `logins.recent` | E6, then E1, as summaries without passwords |
| T18 INT-02.10 | S-BRW-14 off, V and W unlocked | `logins.find` on `https://example.com/` | Only V's entries |
| T19 INT-02.10 | S-BRW-14 on, V and W unlocked | Same | V's entries then E11, each with its `vault` |
| T20 INT-02.11 | V locked, S-BRW-10 on | `unlock`; unlock in the panel | Reply with V's vault id |
| T21 INT-02.11 | V locked, S-BRW-10 off | `unlock` | Error 1 at once; no panel |
| T22 INT-02.11 | V locked | Two `unlock` requests; Cancel in the panel | One panel; both get error 6 |
| T23 INT-02.12 | — | `logins.find` on `https://example.com/` | E10 (recycle bin) never listed |
| T24 INT-02.13 | — | `logins.find` on `https://example.com/login` | Only E2. Absent: E1 (its host `mail.example.com` is below the page host, so it does not fit, INT-03.7), E3 (hidden), E4 (expired), E8 (hidden group), E9 (restricted to `laptop`), E10 (recycle bin) |
| T25 INT-02.13 | Session proven with K2 | Same | E2 and E9 |
| T26 INT-02.13 | S-BRW-13 on | Same | E2, E4 with `expired` true |
| T27 INT-02.13 | — | `logins.find` on `http://192.168.1.1/` with `http_auth` false | E5 absent (only HTTP sign-in) |
| T28 INT-02.13 | — | Same with `http_auth` true | E5 with access `ask` |
| T29 INT-02.14 | Group Web `BrowserOnlyHttpAuth` = `false`, E5 entry key `true` | `logins.find` on `http://192.168.1.1/`, `http_auth` false | E5 listed (the group decides); reference: absent |
| T30 INT-02.14 | Group Web `BrowserSkipAutoSubmit` = `true` | `logins.find` on `https://example.com/` | E2 `skip_submit` true |
| T31 INT-02.15 | Two sessions each send `logins.get` for E2 (state ask) | — | One prompt; the second appears after the first closes |
| T32 INT-02.15 | 17 waiting prompt requests | The 17th arrives | Error 42 |
| T33 INT-02.15 | Prompt shown (fake clock) | 60 s | Error 6; nothing remembered |
| T34 INT-02.16 | E2's item `{"Allow":["Example.COM"],"Deny":[]}` | `logins.get` E2 on `https://example.com/` | Given without a prompt (host compared in ASCII lower case) |
| T35 INT-02.16 | E2's item is `{not json` | `logins.get` E2 | Prompt (item absent); with Remember: the item is replaced by valid JSON |
| T36 INT-02.16 | E2's item lists `bücher.example` in Allow | `logins.get` E2 on `https://xn--bcher-kva.example/`, E2's URL `https://bücher.example` | Given without a prompt |
| T37 INT-02.16 | Remember allow for E2 on `example.com` | Read E2's item | `{"Allow":["example.com"],"Deny":[],"Realm":""}`; E2's modification time moved; no new history item |
| T38 INT-02.17 | E2's Deny holds `example.com` | `logins.find` | E2 absent |
| T39 INT-02.17 | E2's Allow holds `example.com`; `form_url` `https://login.example.com/x` | `logins.get` E2 | Prompt (form host not allowed) |
| T40 INT-02.17 | S-BRW-15 on, no item | `logins.get` E2 | Given without a prompt; a notification MI02-13 (INT-02.31) |
| T41 INT-02.17 | S-BRW-17 on | `logins.get` E5 with `http_auth` true on `http://192.168.1.1/` | Given without a prompt |
| T42 INT-02.17 | E5's Allow holds `192.168.1.1`, S-BRW-17 off | Same | Prompt, without Remember |
| T43 INT-02.18 | E2 and a copy E2b both ask | `logins.get` [E2, E2b]; uncheck E2b, check Remember, Allow Selected | Only E2 returned; E2's Allow and E2b's Deny gain `example.com` |
| T44 INT-02.18 | Prompt | Deny with Remember | Error 6; both entries' Deny gain the host |
| T45 INT-02.18 | Prompt for E7 | Read the row | Title "Ref user", username `alex` (resolved) |
| T46 INT-02.19 | `url` `https://example.com/login`, `top_url` `https://other.example.org/` | `logins.get` E2 with E2's Allow holding `example.com` | Prompt with MI02-05 naming both hosts; no Remember box |
| T47 INT-02.19 | `form_url` `https://collector.example.org/post` | `logins.get` E2, S-BRW-15 on | Prompt with MI02-06; nothing remembered after Allow |
| T48 INT-02.20 | — | `logins.find` on `https://shop.example.org/` | E6 summary: `title` `Shop`, `username` empty, `code` false, `skip_submit` true, `access` `ask`; no `password` member anywhere in the reply |
| T49 INT-02.20 | S-BRW-12 on; entries `https://example.com/login` (E12) and `https://example.com` (E2) | `logins.find` on `https://example.com/login` | E12 only (INT-03.14) |
| T50 INT-02.21 | E6 allowed | `logins.get` E6 on `https://shop.example.org/` | `fields` `[{"name":"pin","value":"1234"}]`; with S-BRW-18 off: no `fields` |
| T51 INT-02.21 | E1 allowed for `mail.example.com` | `logins.get` E1 there | `code` is the RFC 6238 code at the fake time; `password` `demo-mail-pass` |
| T52 INT-02.21 | — | `logins.get` naming E8 (hidden group) | Error 15; E8 not in any reply |
| T53 INT-02.22 | — | `logins.search` `shop` on page `https://example.com/` | E6 summary with access `ask` |
| T54 INT-02.22 | S-BRW-15 on | `logins.get` E6 on `https://example.com/`; Allow with Remember | Prompt shown despite S-BRW-15; E6's Allow gains `example.com`; the next `logins.find` there lists E6 |
| T55 INT-02.23 | E1 state ask on `mail.example.com` | `code.get` E1; Allow | Code, period 30, remaining 1 to 30 |
| T56 INT-02.23 | — | `code.get` E1 on `https://example.org/` (E1 does not fit) | Error 18; no code, no prompt |
| T57 INT-02.24 | — | `logins.save` url `https://new.example.com/signup?token=abc#x`, username `u1`, password `p1` | New entry in group "Browser Sign-ins" (made under the root, icon 1), title `new.example.com`, URL `https://new.example.com/signup`; V changed |
| T58 INT-02.24 | — | `logins.save` with password `{PASSWORD}` | Error 34; nothing added |
| T59 INT-02.24, INT-02.27 | S-BRW-14 on, V and W unlocked | `logins.save`; Cancel in the picker | Error 1; nothing added |
| T60 INT-02.25 | E2 allowed | `logins.update` E2 with password `new-pass`; Update | E2's password `new-pass`, one new history item; reply `updated` true |
| T61 INT-02.25 | — | `logins.update` with E6's id on `https://example.com/` | Error 18; no question |
| T62 INT-02.25 | Entry E13 URL `https://example.com`, password `{REF:P@I:‹E2 id›}` | `logins.update` E13 with password `x2`; Update | E2's password `x2`; E13 unchanged |
| T63 INT-02.25 | E13's password `{REF:P@I:00000000000000000000000000000000}` | `logins.update` E13 | Error 18 within 10 steps; no hang |
| T64 INT-02.25 | S-BRW-16 on | `logins.update` E2 | No question; updated |
| T65 INT-02.26 | — | `groups.list` | Root, Web, Hidden, Laptop; no recycle bin |
| T66 INT-02.26 | — | `groups.create` path `Web/New/Deep`; Create | Groups `New` and `Deep` made under Web, each with `BrowserHideEntry` = `false`; reply names `Deep` |
| T67 INT-02.28 | S-BRW-01 off | Open the settings page | Every row under the main switch disabled |
| T68 INT-02.29 | Group Web `BrowserHideEntry` = `false` | Open E3's Browser page | "Hide" switch off, disabled, MI02-11 naming Web |
| T69 INT-02.29 | E2's Browser page | Type `https://Gist.Example.com/x` in "Also allowed on", Return, Save | E2's Allow holds `gist.example.com` |
| T70 INT-02.29 | E2 has no `BrowserSkipAutoSubmit` key | Open, leave "Fill, but do not submit" off, change the title, Save | No `BrowserSkipAutoSubmit` key written |
| T71 INT-02.30 | E2 and E6 have items with hosts, E1 has `{"Allow":[],"Deny":[]}` | Open Browser Keys | "2 entries hold allowed or blocked sites" |
| T72 INT-02.31 | S-BRW-09 on, S-BRW-15 on (fake notifier) | Two silent fills on `example.com` within 10 min, a third after 11 min | Two notifications; text names the browser and `example.com`, no title, no username |
| T73 INT-02.32 | — | Open Reports › Browser | Rows for E3 ("hidden"), E5 ("HTTP only"), E6 ("fill, no submit") and E8 ("hidden", from its group); no row for E2 (no item, no option) or E10 (recycle bin) |
| T74 INT-02.24 | — | `logins.save` with a password of 65,537 bytes | Error 43; nothing added |
| T75 INT-02.19 | Entry R `http://192.168.1.1` allowed for `192.168.1.1`, S-BRW-17 on | `logins.get` R with `http_auth` true, `url` `http://192.168.1.1/`, `top_url` `http://192.168.1.2/` | Prompt with MI02-05; no Remember box (whole hosts compared) |

## How this was learned

- Read in the reference source (development branch): the browser service (the entry search over groups with the hide, restrict-key and omit-www group options and the recycle bin check, the HTTP sign-in options, the access check with Allow, Deny and Realm, the confirm step with remembering for the page and form hosts, the single-dialog flag, the always-allow and HTTP-sign-in options, the expired check, the entry reply with extra fields, the skip-submit resolution, the association store with its name dialog and overwrite question and the locale-formatted created date, the add and update routines with the password-reference loop and the update question, the group creation question and the default group, the vault picker for saves, the one-time code lookup by id, the window raise and hide handling, the lock and unlock notices); the entry browser config (the three properties, the JSON load and save, allow removing from deny and the reverse); the access control dialog and its screen definition (rows selected at start, the per-row disable button, Remember hidden for HTTP sign-in, Allow focused); the entry editor's browser page (options disabled when a group decides, writing only changed or existing keys, the additional URL list); the vault settings browser page (the association table, removing, disconnect all, forgetting site settings, a new root id); the browser statistics report; the browser settings and their defaults; the browser unit tests.
- Read in the reference's documentation: the browser integration topic (connecting and naming, the confirm-access dialog, clearing remembered sites, entry and group options, the warning about reusing a connection name).
- Not run: no browser or extension was used and the reference app was not started.
- Proven standards (AGENTS rule 9), read 2026-10-28: Bitwarden help "Unlock with biometrics" ("Require verification for browser integration": the user verifies the link between desktop app and extension each time it is made) and Bitwarden's desktop strings (a setting to turn off browser integration fingerprint validation); Bitwarden help "URI match detection" (a per-item list of websites the item fills on); Bitwarden's extension source (connected apps keyed by an id, replaced when the key changes); Flashpoint "Bitwarden password pilfering" (2023), the Bitwarden community thread "Auto-fill: Form is hosted by a different domain - confirmation popup" and PCWorld's report on the fix (frames of other domains filled only after an alert unless the URL is on the item). Proton Pass support "Biometric unlock" (no desktop-to-extension link). The FEA-03 word list (EFF Large Wordlist) is reused for the pairing words.

## Review 2026-10-28

Second Spec review. Read again in the reference source: the browser service (entry search, the HTTP sign-in and access checks, the confirm step and its remember lists, the single-dialog flag, the association store, the add and update routines, the one-time code lookup), the entry's site access item, and the reference routines its update loop calls. Nothing was run.

Confirmed against the reference source: the hidden, restricted-key and recycle bin skips; HTTP sign-in skipping the expiry and access checks (D-INT02-9); the either-side test for the two HTTP options (D-INT02-10); Allow tested before Deny; the realm member never set; Remember adding page and form hosts; the association name only checked for empty and overwritten after a question; the locale date in `_CREATED_`; the search repeated once per dot with the same input; the code lookup by id without a site check (SI-11); an unknown update id adding an entry. The update hang is real: the loop over the password reference keeps the same entry when the reference's id does not read as 16 bytes (an all-zero id, a reference by title), and it has no step limit, so a loop of references never ends either. Recomputed and correct: T10 (SHA-256 and the four words, checked against the word list Larsal ships).

Two-step fill: `logins.find`, `logins.search` and `logins.recent` carry no password, code or passkey result and open no dialog; `logins.get` and `code.get` give secrets only for entries in state allowed or after Larsal's prompt. Two leaks remain (R02-1, R02-2), and Larsal cannot see the user's pick (security note added, R02-4).

Fixes made (12): INT-02.6 and INT-02.18 describe the reference's dialog without quoting its texts; INT-02.8 points to R02-3; INT-02.15's reference difference corrected (a second request still gets its already allowed entries); INT-02.16 notes the reference's order (a host in both lists is allowed there); INT-02.17 lists INT-02.22's outside fills among the cases S-BRW-15 never opens; INT-02.19 compares whole hosts when a host has no registrable domain; INT-02.24 says what an overlong value gives (43); INT-02.25 names both reference hang cases and the empty-username refusal; a security note on what Larsal cannot see; tests T74 and T75.

Findings, each with a proposed ruling:

| ID | Finding | Proposed ruling |
|---|---|---|
| R02-1 | INT-02.22 runs FEA-01's query language on bridge text. FEA-01 reads `pw:`, `attribute:` and regular expressions (`*` modifier, FEA-01.8) over protected values (FEA-01.5, FEA-01 security notes), so an associated client could test guesses and read passwords one character at a time from hits and misses, with no prompt. Usernames that resolve to a password (FEA-01.19) and notes leak the same way | `logins.search` takes the text as one plain term, no query syntax (no field names, `is:`, `has:`, quotes or regular expressions), matched without letter case as part of the title, the username and the URL host only; notes, passwords and custom fields are never searched over the bridge. A test: `pw:demo-mail-pass`, `*pw:^demo` and `attribute:1234` find nothing (no title, username or host holds that text). Security note: the search shows every entry's title and username to an associated client (the frame `extension-popup-search-everything` needs it), like the reference's list-all without URLs |
| R02-2 | Summaries resolve titles and usernames (MOD-08) and go out without a prompt (INT-02.20). A title or username holding `{PASSWORD}` or a reference to another entry's password (`{REF:P@I:…}`) sends a password in clear inside the box before any pick | In summaries, a title or username whose resolution reads a password or a protected custom field is sent as an empty string with `"hidden_value": true`; the real value comes only with `logins.get` after access (INT-02.18's prompt rows are on Larsal's screen and stay resolved). A test with E7's username changed to `{REF:P@I:‹E1 id›}` |
| R02-3 | MOD-12.18's rename and value editing, `vault.act.disconnect_all` and `vault.act.new_root_id` have no control in the locked frame `vault-vault-settings-browser-keys` (it has a Disconnect button per row and "Remove all…" for site permissions) | List them as one mockup addition for the owner (with R01-5); Larsal builds none of the four until the owner approves; no screen is invented here |
| R02-4 | The extension's "Fill when a page loads" (frame `extension-extension-options`, "Off is safer") calls `logins.get` without a pick, which LD-189's "a password leaves Larsal only for the entry the user picks" does not cover | E7-S7 ships it off; when on, it fills only an entry already in state allowed with exactly one match, and never makes Larsal open a dialog on a page load |
