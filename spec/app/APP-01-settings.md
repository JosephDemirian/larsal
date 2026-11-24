# APP-01 Settings inventory and defaults

Status: reviewed
Epics: E1-S8, E5-S9
Parity rows: SR-01, SR-02, SR-03, SR-04, SR-08, SR-09, SR-12, SC-01, SC-04, SC-05, SC-08, SD-01, SD-02, SD-03, SD-05, SD-10, SF-16, SG-01, SG-02, SG-03, SI-01, SI-02, SI-03, SI-04, SI-05, SI-06, SI-07, SI-09, SI-10, SI-12, SN-01, SN-02, SN-03, SN-04

## What it does

Lists every application-wide setting of the reference app: screen by screen and section by section as its settings screen shows them, then the settings changed from other places (View menu, search menu, generator, dialogs), the state the app remembers on its own, and the values that exist only in its settings file. Vault settings are MOD-12, not here.

Every setting has a stable ID `APP-01.S-<area>-<nn>`. In this card the short form `S-<area>-<nn>` means the same. The Key column is the name Larsal stores the value under (D-01-1). Other cards that proposed names (APP-02, APP-03, FEA-01, FEA-02, FEA-03, MOD-09) are kept where they exist; this card wins on any difference.

The card also owns: how settings are stored, the settings screen's mechanics (OK and Cancel, dependent controls, reset, import, export), the update check (SN-04), and the display and entry options no other card owns. A setting whose behavior another card owns is summed up in one line with a pointer.

Sources: the reference source (development branch) and, marked "differs in installed version", the installed 2.7.11. The command line tool reads no setting except the language and, read-only, the stored unlock speed measurement (INT-10, D-INT10-6).

## Inputs and outputs

In: the settings screen, the View menu, the search field's menu, the generator, a few dialogs, the settings files, the OS (login items, dark mode, Touch ID availability), the browser manifest files (INT-01).
Out: the settings files, and the behavior each setting changes. Parts of the app that show data update at once when a setting they use changes (for example the entry list when S-VIEW-07 flips).

Reference storage, for the record: two plain-text key and value files with sections. The main file (portable values) sits in the app's Application Support folder; a second file for machine-bound values sits in its Caches folder. A version marker (value 2) drives one-time renames from older versions; Larsal does not carry it over. Command line flags can point to other settings files (APP-09). Two environment variables override the two paths and a third sets the fallback folder of file dialogs; Larsal does not read them (Decided: spec/decisions.md LD-48).

Settings screen (Mac), pages in this order on the left: General (tabs Basic and Auto-Type), Security, Browser Integration, Shortcuts, SSH Agent, shared groups. Linux adds a Secret Service page. Buttons: OK and Cancel, no Apply. Differs in installed version: there is no Shortcuts page.

Table legend:
- Values: range and unit. "Mac" = this-Mac scope (APP-01.1); all others are portable.
- Default: reference source; the installed 2.7.11 has the same default unless a row says otherwise.
- Rows: parity rows in plan/security.md.
- Larsal: B = build as the reference; D = build with the Larsal default given; S = skip, with the reason (D-01-8 unless another decision is named).

## Settings by screen

### General › Basic › Startup (12 controls)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-START-01 | `app.single_instance` | Allow only one running copy | on/off | on | A second launch hands its file arguments to the running copy and quits (APP-09). Off allows several copies sharing one settings file. | SR-09 | S (D-01-4, LD-47) |
| S-START-02 | `app.launch_at_login` | Open Larsal when I log in | on/off; kept by the OS, not in the settings file | off | APP-01.37 | – | B (D-01-7) |
| S-START-03 | `window.start_minimized` | Start minimized | on/off | off | At start the window hides to the menu bar icon if shown, else minimizes; same as the start-minimized flag (APP-09). | – | B |
| S-START-04 | `window.minimize_after_unlock` | Minimize after unlocking | on/off | off | After an unlock the window minimizes, or hides when S-UI-12 is on. Excludes S-LOCK-04 (APP-01.8). | SR-03 | B |
| S-START-05 | `recent.remember` | Remember recently used vaults | on/off | on | APP-01.14, .15, .17 | SR-12 | B |
| S-START-06 | `recent.count` | Number of recent vaults | 1–25 | 5 | Length of the recent list. | – | B |
| S-START-07 | `recent.reopen_at_start` | Reopen the vaults that were open at quit | on/off | on | APP-01.17 | – | B |
| S-START-08 | `recent.remember_keys` | Remember each vault's key file and hardware key | on/off | on | APP-01.16 | SF-04, SR-12 | D: off (LD-51) |
| S-START-09 | `update.check` | Check for updates once a week | on/off | on, but asked at first start | APP-01.19 | SN-01, SN-03, SN-04 | D: off (D-01-2) |
| S-START-10 | `update.include_beta` | Include test releases | on/off | off | APP-01.19 | SN-04 | B |
| S-START-11 | `expiry.notice_on_unlock` | After unlock, show entries expiring within N days | on/off | on | APP-01.18 | SR-08 | B |
| S-START-12 | `expiry.notice_days` | …N days | 0–90 days | 3 | 0 = expired entries only. | SR-08 | B |

### General › Basic › File management (8 controls)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-FILE-01 | `save.after_every_change` | Save changes as you make them | on/off | on | Each change is saved, at once or after the vault's auto-save delay (MOD-12); APP-05. Forces S-FILE-02 and -03 (APP-01.6). | SD-10 | B |
| S-FILE-02 | `save.on_lock` | Save when locking | on/off | on | A modified vault is saved without asking when it is locked or closed; if that fails the user is asked (APP-05). | SD-10 | B |
| S-FILE-03 | `save.non_data_on_lock` | Save view-only changes when locking | on/off | on | APP-01.35 | SD-10 | B |
| S-FILE-04 | `save.reload_on_change` | Reload when the file changes on disk | on/off | on | Off asks first (APP-05). | SD-03 | B |
| S-FILE-05 | `backup.enabled` | Keep a backup before saving | on/off | off | APP-05 | SD-02 | D: on (plan/security.md) |
| S-FILE-06 | `backup.pattern` | Backup name and place | text; tokens and rules in APP-05; empty = default; the folder picker fills `<folder>/<default>` | `{DB_FILENAME}.old.` + the reference vault extension (stored encoded (name rule): 6B 64 62 78) | A relative result goes next to the vault. | SD-02 | D: `{FILE_NAME}.old.larsalvault` (token of APP-05.20) |
| S-FILE-07 | `save.alternative` | Use another save method (helps with sync folders) | on/off; stored inverted (reference value "safe save" = on when this is off) | off | Off: write-and-swap save. On: the method in S-FILE-08 (APP-05). APP-01.36 never changes it (LD-52). | SD-01 | per APP-05 |
| S-FILE-08 | `save.alternative.mode` | …method | 0 temp file moved into place, 1 write straight into the vault (marked dangerous); Mac | 0 | APP-05 | SD-01 | per APP-05 |

### General › Basic › Entry management (11 controls)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-ENTRY-01 | `entry.autocomplete` | Suggest user names and field names while typing | on/off | on | APP-01.25. Differs in installed version: no such setting; inline user name completion always on. | – | B |
| S-ENTRY-02 | `entry.confirm_recycle` | Ask before moving to the Recycle Bin | on/off; stored inverted (reference value "do not ask" = on) | off (no question) | APP-01.26, MOD-04 | SD-05 | B |
| S-ENTRY-03 | `entry.autogen_password` | Fill a generated password into new entries | on/off | off | APP-01.25, FEA-02.19 | SG-01 | B |
| S-ENTRY-04 | `list.copy_on_double_click` | Double-click copies user name or password in the list | on/off | off | APP-01.22, APP-03 | SC-01 | B |
| S-ENTRY-05 | `list.url_double_click` | Double-click on a URL | 0 open in browser, 1 copy, 2 edit entry | 0 | APP-01.22 | – | B |
| S-ENTRY-06 | `entry.group_icon` | New entries take their group's icon | on/off | on | APP-01.25, MOD-06.3 | – | B |
| S-ENTRY-07 | `window.minimize_on_open_url` | Minimize the window when a link opens | on/off | off | After opening an entry's URL, or running its command URL (MOD-08), the window minimizes, or hides when S-UI-12 is on. | – | B |
| S-ENTRY-08 | `window.hide_on_copy` | Get the window out of the way after copying | on/off | off | APP-01.22, APP-03 | – | B |
| S-ENTRY-09 | `window.hide_on_copy.mode` | …by minimizing / …by moving it behind other windows (two choices) | minimize, background; the reference stores two on/off values | minimize | Choices disabled while S-ENTRY-08 is off. Reference edge: both values off = nothing happens; both on = minimize. | – | B |
| S-ENTRY-10 | `icons.download_timeout` | Time limit for website icon downloads | 1–60 s | 10 | APP-01.21 | SN-02 | B |
| S-ENTRY-11 | `icons.download` | Allow website icon downloads | on/off; Larsal only (the reference always offers downloads) | off | APP-01.21 | SN-01, SN-02 | D: off (LD-64) |

### General › Basic › User interface (12 controls, 11 on Mac)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-UI-01 | `ui.language` | Language | `system` or a translation code | `system` | Restart needed (APP-01.4). The command line tool uses it too (INT-10). | – | D (D-01-3) |
| S-UI-02 | `ui.toolbar_style` | Toolbar buttons | icon only, text only, text beside icon, text under icon, follow system | icon only | Toolbar button look. | – | S: the mockup's toolbar is fixed |
| S-UI-03 | `ui.toolbar_movable` | Toolbar can be dragged | on/off | off | Off puts the toolbar back at the top. | – | S: as S-UI-02 |
| S-UI-04 | `ui.font_size` | Text size | Small −1, Normal 0, Medium +1, Large +2 (points added to the system size); file may hold −2 to 4; Mac | 0 | APP-01.28 | – | B |
| S-UI-05 | `ui.show_toolbar` | Show toolbar (also in the View menu) | on/off; stored inverted | on | | – | S: as S-UI-02 |
| S-UI-06 | `ui.show_menu_bar` | Show the window's menu bar | on/off; stored inverted | on | Not on Mac: hidden, the Mac menu bar is always there. | – | S |
| S-UI-07 | `display.color_passwords` | Color the characters of shown passwords | on/off | off | APP-01.24 | – | D: on (LD-212 (5)) |
| S-UI-08 | `display.monospace_notes` | Fixed-width font for notes | on/off | off | Notes in the preview panel and in the entry and group editors. | – | B |
| S-UI-09 | `window.close_hides` | Close button hides instead of quitting | on/off | off | APP-08 | – | B |
| S-UI-10 | `menubar_icon.show` | Show a menu bar icon | on/off | off | APP-08 | – | B |
| S-UI-11 | `menubar_icon.style` | Menu bar icon style | monochrome, colorful | empty: monochrome, variant picked from dark mode when read (Verified 2026-10-28, V-A01-1: the reference turns an empty value into a light or dark monochrome variant by the Mac's dark mode, but on macOS it always draws the same mask image, so the variant changes nothing on screen; its settings box then shows Monochrome) | APP-08 | – | B |
| S-UI-12 | `menubar_icon.minimize_to` | Minimizing hides the window to the menu bar icon | on/off | off | APP-08 | – | B |

Under the sections: buttons Reset to defaults (APP-01.9), Import (APP-01.11), Export (APP-01.10). They are actions, not settings.

### General › Auto-Type (14 controls, 10 on Mac)

The tab is removed when Auto-Type is not available; on Mac it is always available and the Accessibility permission is asked at first use (INT-05).

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-AT-01 | `autotype.match_title` | Match windows by entry title | on/off | on | INT-05 | SI-06 | B |
| S-AT-02 | `autotype.match_url` | Match windows by entry URL | on/off | on | INT-05 | SI-06 | B |
| S-AT-03 | `autotype.always_ask` | Always ask before typing | on/off | on | Global Auto-Type shows the chooser even for one match (INT-05). | SI-06 | B |
| S-AT-04 | `autotype.skip_ask_main_window` | Don't ask when started from the main window | on/off | off | INT-05 | SI-06 | B |
| S-AT-05 | `autotype.hide_expired` | Leave expired entries out of Auto-Type | on/off | off | INT-05 | – | B |
| S-AT-06 | `lock.relock_after_autotype` | Lock again after Auto-Type | on/off | off | A vault unlocked for a global Auto-Type is locked once typing is done (APP-02). | SI-06 | B |
| S-AT-07 | `autotype.global_shortcut` | Global Auto-Type shortcut | key and modifiers, with Cmd or Ctrl; the reference stores two numbers | Ctrl-Opt-V (LD-176; the reference has none) | Registered as soon as it is entered; a refused combination turns the field red with the system's reason, and is still stored on OK (INT-05). | – | B |
| S-AT-08 | `autotype.retype_seconds` | Preselect the previous choice for | 0–60 s | 15 | INT-05 | – | B |
| S-AT-09 | `autotype.start_delay_ms` | Wait before typing starts | 100–10,000 ms, step 100 | 500 | INT-05 | – | B |
| S-AT-10 | `autotype.key_delay_ms` | Pause between keys | 0–500 ms (LD-176) | 25 | INT-05 | – | B |

The 4 other controls are Linux only (Not on Mac).

### Security › Timeouts (6 controls)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-TIME-01 | `clipboard.clear.enabled` | Clear the clipboard after | on/off | on | APP-03 | SC-01 | B |
| S-TIME-02 | `clipboard.clear.seconds` | …seconds | 1–999 s | 10 | APP-03 | SC-01 | B |
| S-TIME-03 | `lock.idle.enabled` | Lock vaults after no activity for | on/off | on | APP-02 | SR-01 | B |
| S-TIME-04 | `lock.idle.seconds` | …seconds | 10–43,200 s | 900 | APP-02 | SR-01 | D: 300 (plan/security.md) |
| S-TIME-05 | `search.clear_when_idle` | Clear the search after | on/off | off | APP-01.27 | SC-08 | B |
| S-TIME-06 | `search.clear_after_minutes` | …minutes | 1–1,440 min | 5 | APP-01.27 | SC-08 | B |

### Security › Lock options (4 controls; the user-switch box shows only on Mac)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-LOCK-01 | `quick_unlock.enabled` | Unlock with Touch ID | on/off; Mac | on | APP-04. Disabled when Touch ID is not available. Label as APP-04 (Decided: spec/decisions.md LD-200 (7)). | SR-04 | B |
| S-LOCK-02 | `lock.on_screen_lock` | Lock when the screen locks or the lid closes | on/off | on | APP-02 | SR-02 | B |
| S-LOCK-03 | `lock.on_user_switch` | Lock when another user takes over | on/off | on | APP-02 | SR-02 | B |
| S-LOCK-04 | `lock.on_minimize` | Lock after minimizing | on/off | off | APP-02; excluded by S-START-04 (APP-01.8) | SR-03 | B |

### Security › Convenience (5 controls)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-CONV-01 | `display.dots_for_empty` | Show dots for empty password fields | on/off | off | APP-01.23 | SC-04 | B |
| S-CONV-02 | `display.hide_password_in_editor` | Hide passwords in the editor | on/off | on | The editor's password field opens masked. | SC-04 | B |
| S-CONV-03 | `display.hide_password_in_preview` | Hide passwords in the detail pane | on/off | on | APP-01.23 | SC-04 | B |
| S-CONV-04 | `display.hide_totp_in_preview` | Hide one-time codes in the detail pane | on/off | off | APP-01.23 | SC-04 | B |
| S-CONV-05 | `display.hide_notes` | Hide notes | on/off | off | APP-01.23 | SC-04 | B |

### Security › Privacy (1 control)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-PRIV-01 | `icons.use_service` | Get website icons through a public icon service | on/off | off | APP-01.21. The service learns every domain looked up. | SN-01, SN-02 | B |

### Browser Integration (27 controls, 26 shown on Mac; behavior: INT-01 to INT-04)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-BRW-01 | `browser.enabled` | Turn on browser integration | on/off | off | Starts the bridge (INT-01); adds the Browser page to the entry and group editors (MOD-12.18). Disables both tabs while off. | SI-01 | B |
| S-BRW-02 to S-BRW-08 | `browser.manifest.<name>`; Safari `browser.safari` | Browsers, Larsal's list (the frame's six plus Edge; LD-189, D-INT01-6): 02 Safari, 03 Chrome, 04 Firefox, 05 Brave, 06 Vivaldi, 07 Opera, 08 Edge (the Edge row is a mockup addition for the owner) | on/off. 03 to 08 are not in the settings file: on = Larsal's manifest exists in that browser's folder (INT-01.8; Opera shares Chrome's file). 02 Safari is stored (Larsal only, not in the reference's defaults table, so the counts below do not change) and shown disabled until Larsal is signed (INT-01.15) | off (no manifest; Safari off) | APP-01.30, INT-01.8, INT-01.13 | SI-01 | B |
| S-BRW-09 | `browser.notify` | Notify when a site asks for credentials | on/off | on | Hidden on every platform; no effect. Larsal: shown, and notifies on fills without a dialog (INT-02.31, LD-189). | – | B |
| S-BRW-10 | `browser.unlock_on_request` | Ask to unlock a locked vault when a site asks | on/off | on | INT-02 | SI-02, SI-12 | B |
| S-BRW-11 | `browser.match_scheme` | Match the URL scheme | on/off | on | Returns only entries whose URL scheme matches the page (INT-03). | SI-03 | B |
| S-BRW-12 | `browser.best_match_only` | Offer only the best matches | on/off | off | INT-03 | SI-03 | B |
| S-BRW-13 | `browser.allow_expired` | Also return expired entries | on/off | off | The entry's title carries an "expired" mark (INT-02). | SI-02 | B |
| S-BRW-14 | `browser.search_all_vaults` | Search every connected open vault | on/off | off | INT-02 | SI-02 | B |
| S-BRW-15 | `browser.never_ask_access` | Never ask before giving access (Advanced tab, under a "change only if needed" warning) | on/off | off | INT-02 | SI-02 | B |
| S-BRW-16 | `browser.never_ask_update` | Update saved logins without asking | on/off | off | INT-02 | SI-10 | B |
| S-BRW-17 | `browser.skip_http_auth_ask` | Fill HTTP sign-in prompts without asking me | on/off | off | INT-02 | SI-04 | B |
| S-BRW-18 | `browser.extra_fields` | Return extra fields whose names start with `KPH: ` | on/off | on | Read only; creating such fields is not supported (INT-02). | – | B |
| S-BRW-19 | `browser.passkeys_localhost` | Allow plain-http localhost for passkeys | on/off | off | INT-04 | SI-05 | B |
| S-BRW-20 | `browser.no_migration_prompt` | Don't offer to move the legacy HTTP plug-in's settings | on/off | off | No effect in the source. | – | S |
| S-BRW-21 | `browser.rewrite_manifests` | Rewrite browser manifests at start | on/off | on | When the bridge starts, every enabled browser's manifest is rewritten with the current program path (INT-01). | – | B |
| S-BRW-22 | `browser.allow_list_all` | Let the extension list every entry (skips site rules) | on/off | off | The extension can fetch the title, URL and id of each entry in every connected vault (INT-02). Differs in installed version: absent. Larsal has no list-all request (INT-01.37, LD-189). | SI-12 | S |
| S-BRW-23 | `browser.custom_proxy` | Use my own proxy program | on/off | off | APP-01.30 | – | B |
| S-BRW-24 | `browser.custom_proxy.path` | …path | path; home shown as `~` | empty | | – | B |
| S-BRW-25 | `browser.custom_folder` | Use my own manifest folder | on/off; Mac | off | APP-01.30. Not in Larsal 1.0 (INT-01.8, D-INT01-6, LD-189), nor -26 and -27. | – | S |
| S-BRW-26 | `browser.custom_folder.kind` | …browser kind | Firefox, Chromium; Mac | none (−1; the list then shows Firefox) | | – | S |
| S-BRW-27 | `browser.custom_folder.path` | …folder | path, home shown as `~`; Mac | empty; stored empty while S-BRW-25 is off | | – | S |

Also on the page: a line with links to the reference's own browser extension (Larsal links its own, decision D4), and debug builds only: a custom extension id field (S-DEBUG-01, Mac, empty; S in Larsal).

### Shortcuts (1 control; differs in installed version: page absent)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-KEYS-01 | `shortcuts.custom` | Table of actions and their shortcuts, with a filter field | map from action to key combination; only values that differ from the default are stored | empty (all defaults, APP-08) | APP-01.29 | – | B |

### SSH Agent (6 controls, 3 on Mac; behavior: INT-06)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-SSH-01 | `ssh.enabled` | Turn on SSH agent integration | on/off | off | APP-01.31 | SI-07 | B |
| S-SSH-02 | `ssh.socket_override` | Agent socket override | path, spaces trimmed; Mac | empty = the system's `SSH_AUTH_SOCK` | APP-01.31 | SI-07 | B |
| S-SSH-03 | `ssh.sk_provider_override` | Security key provider override | text, trimmed; Mac | empty = `SSH_SK_PROVIDER`, else `internal` | Sent when a key needs a security key provider (INT-06). | SI-07 | B |

Read-only beside them: the current socket value and provider value, or an empty marker when none.

### Shared groups (4 controls; behavior: INT-08)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-SHARE-01 | `share.import` | Allow importing shared groups | on/off | off | APP-01.32 | SI-09 | B |
| S-SHARE-02 | `share.export` | Allow exporting shared groups | on/off; the reference keeps 01 and 02 in one value | off | APP-01.32 | SI-09 | B |
| S-SHARE-03 | `share.quiet` | Hide sync success messages | on/off | on (Larsal, D-INT08-10) | Success messages after a sync are not shown. APP-01.32 | – | B (D-01-10) |
| S-SHARE-04 | `share.identity` | Own signer name (editable), Generate button, fingerprint (read only) | signer text plus a key pair | made on first need | APP-01.32 | SI-09 | B, key in the Keychain (D-01-6) |

## Settings changed from other places

### View menu

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-VIEW-01 | `ui.theme` | Theme | auto, light, dark, classic | auto | APP-01.28 | – | B; classic S |
| S-VIEW-02 | `ui.compact` | Compact mode | on/off | off | Smaller icons and rows; restart needed (APP-01.4). | – | S: one density in the mockup |
| S-VIEW-03 | `ui.show_groups` | Show the group panel | on/off; stored inverted | on | | – | B |
| S-VIEW-04 | `ui.show_preview` | Show the preview panel | on/off; stored inverted | on | | – | B |
| S-VIEW-05 | `window.always_on_top` | Keep window on top | on/off; Mac | off | | – | B |
| S-VIEW-06 | `display.hide_usernames` | Hide user names | on/off | off | APP-01.23 | SC-04 | B |
| S-VIEW-07 | `display.hide_passwords` | Hide passwords | on/off | on | APP-01.23 | SC-04 | B |

The View menu also holds Show toolbar (S-UI-05), Show menu bar (S-UI-06, not on Mac) and Allow screen capture, which is never stored: protection is on at every start unless the start flag allows capture (APP-10, SC-05).

### Search field menu (FEA-01)

| ID | Key | Shown as | Values | Default | Effect | Rows | Larsal |
|---|---|---|---|---|---|---|---|
| S-SEARCH-01 | `search.limit_to_group` | Search only the selected group | on/off | off | FEA-01 | – | B |
| S-SEARCH-02 | `search.enter_to_search` | Search only when Return is pressed | on/off | off | APP-01.27 | – | B |

Case-sensitive search is session only, never stored (FEA-01).

### Generator (FEA-02, FEA-03)

Stored when the generator screen closes, when Apply is pressed and when advanced mode is toggled. S-ENTRY-03 uses the stored values.

| ID | Key | Default | ID | Key | Default |
|---|---|---|---|---|---|
| S-PWGEN-01 | `generator.kind` | password (0; 1 = passphrase) | S-PWGEN-12 | `generator.password.dashes` | off |
| S-PWGEN-02 | `generator.password.length` | 20 | S-PWGEN-13 | `generator.password.math` | off |
| S-PWGEN-03 | `generator.password.lower` | on | S-PWGEN-14 | `generator.password.extended` | off |
| S-PWGEN-04 | `generator.password.upper` | on | S-PWGEN-15 | `generator.password.extra` | empty |
| S-PWGEN-05 | `generator.password.digits` | on | S-PWGEN-16 | `generator.password.excluded` | empty |
| S-PWGEN-06 | `generator.password.special` (simple view) | on | S-PWGEN-17 | `generator.password.exclude_lookalike` | on |
| S-PWGEN-07 | `generator.password.advanced` | off | S-PWGEN-18 | `generator.password.every_group` | on |
| S-PWGEN-08 | `generator.password.signs` (advanced view's special group) | off | S-PWGEN-19 | `generator.passphrase.words` | 7 |
| S-PWGEN-09 | `generator.password.brackets` | off | S-PWGEN-20 | `generator.passphrase.separator` | one space |
| S-PWGEN-10 | `generator.password.punctuation` | off | S-PWGEN-21 | `generator.passphrase.word_list` | built-in list (reference stores its file name) |
| S-PWGEN-11 | `generator.password.quotes` | off | S-PWGEN-22 | `generator.passphrase.case` | lower (0; 1 upper, 2 title, 3 mixed) |

Rows: SG-01, SG-02, SG-03. Larsal: B for all.

### Dialog flags

| ID | Key | Set by | Default | Effect | Larsal |
|---|---|---|---|---|---|
| S-MSG-01 | `msg.no_old_keyfile_warning` | The do-not-show-again box in the old key file warning (APP-06) | off | APP-01.38 | B |
| S-MSG-02 | `msg.update_question_done` | The first-start update question | off | APP-01.19 | S (D-01-2) |
| S-MSG-03 | `msg.prerelease_dismissed` | Closing the development-build warning banner; Mac | empty | APP-01.38 | S |

## State the app keeps on its own (no control)

All are this-Mac (Mac) values in Larsal. The reference keeps S-STATE-15 and -16 in its portable file.

| ID | Key | Holds | Default | Rule |
|---|---|---|---|---|
| S-STATE-01 | `state.recent` | Recent vault paths, newest first | empty | APP-01.14 |
| S-STATE-02 | `state.key_files` | Vault path → key file path | empty | APP-01.16 |
| S-STATE-03 | `state.hardware_keys` | Vault path → hardware key as `serial:slot` | empty | APP-01.16 |
| S-STATE-04 | `state.last_active` | Vault shown at quit | empty | APP-01.17 |
| S-STATE-05 | `state.open_at_quit` | Vaults open at quit, in tab order | empty | APP-01.17 |
| S-STATE-06 | `state.last_folders` | Dialog role → last folder | empty (home folder) | APP-01.15 |
| S-STATE-07 to S-STATE-08 | `state.window_frame`, `state.window_layout` | Main window place and size; bar layout | empty | written when the window hides or the app quits |
| S-STATE-09 to S-STATE-10 | `state.columns`, `state.columns_search` | Entry list columns, normal and search view | empty | |
| S-STATE-11 to S-STATE-13 | `state.split_preview`, `state.split_main`, `state.split_groups` | Panel sizes | empty | showing the group panel again resets the main split |
| S-STATE-14 | `state.autotype_dialog_size` | Auto-Type chooser size | 600 × 250 | |
| S-STATE-15 | `state.autotype_sort_column` | Auto-Type chooser sort column | 0 | |
| S-STATE-16 | `state.autotype_sort_order` | Auto-Type chooser sort order | ascending | |
| S-STATE-17 | `state.update_next_check` | Next update check, seconds since 1970 UTC | 0 | APP-01.19 |

## Values only in the settings file

| ID | Key | Values | Default | Effect | Larsal |
|---|---|---|---|---|---|
| S-CFG-01 | `file.default_name` | text | empty | APP-01.34 | B (file only) |
| S-CFG-02 | `security.min_master_quality` | 0–4; Mac | 0 | APP-01.33, MOD-12 (parity row SF-16) | B (file only) |
| S-CFG-03 | – | on/off | on | Old proxy flag; no effect in the source. | S |
| S-CFG-04 | – | on/off | on | Old double-click flag: read once, only when S-ENTRY-05 is missing, to set it (on → 0, off → 2). | S |
| S-CFG-05 | – | list | empty | Old shared-groups trust list; no effect in the source. | S |

## Not on Mac

Kept in the inventory so nothing is lost; Larsal builds none of them.
- S-NOMAC-01 to -04 (Linux, Auto-Type tab): prefer desktop portals (off, restart needed); keep the remote desktop session open after typing (off); use the remote desktop session for the clipboard (off); remote desktop session memory: never, until exit (default), until the desktop revokes it.
- S-NOMAC-05, -06 (Linux, state): the portal session token (default empty); "global shortcut set up through the desktop" flag (default off). On such desktops the shortcut field is replaced by a Configure button.
- S-NOMAC-07 (Linux): a launch-at-login flag in the settings file, default off (Mac keeps S-START-02 in the OS).
- S-NOMAC-08, -09 (Windows, SSH page): use the PuTTY agent (on), use the OpenSSH agent (off); a third choice turns both on.
- S-NOMAC-10 to -14 (Linux, Secret Service page): turn on (off); notify when a client reads a password (on); confirm each read (on); confirm deletions by clients (on); ask to unlock before a client searches (on). The page also lists exposed groups and connected clients.
- Windows: an organization policy in the registry can fix any value; its control is then disabled with a note that an administrator set it. Windows Hello for quick unlock.
- Windows: a marker file next to the program switches to settings stored beside it (portable mode).
- Windows: the Chrome box also covers Vivaldi and Brave, the Firefox box covers Tor Browser, and there is no own manifest folder. Linux: a warning about sandboxed browser packages; light and dark monochrome icon styles.

## Rules

### Storage

APP-01.1 **Scopes.** Settings live in two scopes: portable (moved by export and import) and this-Mac (marked Mac, plus every S-STATE value). A value that was never written reads as its default; the settings files need not exist. Storing a value equal to the default is allowed but not required.

APP-01.2 **Defaults.** Each ID's default is in its table. Larsal uses the reference default except where the Larsal column says D: S-START-08 off (LD-51), S-START-09 off, S-FILE-05 on, S-FILE-06 `{FILE_NAME}.old.larsalvault`, S-TIME-04 300 s, S-UI-01 limited to the translations Larsal ships, S-ENTRY-11 off (Larsal only, LD-64), S-UI-07 on (LD-212 (5)).

### Settings screen

APP-01.3 **OK and Cancel.** Opening the screen loads current values into every page and shows the first page. OK stores every page, then applies at once: idle timer restarted with the new period, menu bar icon, text size, toolbar. Cancel drops all edits and registers again the global Auto-Type shortcut that was active before the screen opened.

APP-01.4 **Restart needed.** A changed S-UI-01 asks, about 0.2 s after OK, whether to restart now. Choosing classic in S-VIEW-01, leaving classic, or flipping S-VIEW-02 asks the same at once. Answering no keeps the stored value; it takes effect at the next start.

APP-01.5 **Dependent controls.** A control is disabled while the control it depends on is off: S-START-06/07/08 on S-START-05; S-START-10 on S-START-09; S-START-12 on S-START-11; S-FILE-06 and its folder picker on S-FILE-05; S-FILE-08 on S-FILE-07; S-ENTRY-09 on S-ENTRY-08; S-UI-11 and S-UI-12 on S-UI-10; S-AT-04 on S-AT-03; S-TIME-02 on -01, -04 on -03, -06 on -05; both Browser tabs on S-BRW-01; S-BRW-24 on -23; S-BRW-26/27 on -25; the SSH fields on S-SSH-01. A disabled control keeps its value.

APP-01.6 **Auto-save forces its partners.** Switching S-FILE-01 on also switches S-FILE-02 and S-FILE-03 on and disables both. Switching it off enables them again; they stay on.

APP-01.7 **Forgetting.** Switching S-START-05 off also switches S-START-07 and S-START-08 off. On OK with S-START-05 off, S-STATE-01, S-STATE-04 and all of S-STATE-06 are deleted. On OK with S-START-08 off, S-STATE-02, S-STATE-03 and all of S-STATE-06 are deleted.

APP-01.8 **Minimize after unlock excludes lock on minimize.** While S-START-04 is checked, S-LOCK-04 is unchecked and disabled with a note that it cannot be on together with S-START-04. On opening, S-LOCK-04 shows checked only if it is stored on and S-START-04 is off.

APP-01.9 **Reset to defaults.** Asks first (Reset or Cancel; Cancel is the default button). If the settings file cannot be written: error (APP-01.12), nothing changes. Otherwise both scopes are emptied: every setting, all S-STATE values, the generator values, the view toggles and the stored custom shortcuts. Then the Browser, SSH and shared-groups pages store again what they show, so those keep their values; the Shortcuts page stores only edits made in this session. The screen reloads and the new values apply. S-START-02 is not touched. Reference edge: custom shortcuts stay active until the next start (Verified 2026-10-28, V-A01-2: the reset empties the stored shortcuts, but the live menu actions keep their custom keys; only the next start, which reads the stored shortcuts again, brings the defaults back; the Shortcuts page still lists the custom keys, and a later edit saved on that page stores them again); Larsal applies the reset shortcuts at once (D-01-9).

APP-01.10 **Export.** The user picks a file; every stored portable value is written. Reference: the file is plain text and includes the shared-groups private key (S-SHARE-04). Larsal: never writes a secret into an export (D-01-6); the file holds portable values only.

APP-01.11 **Import.** The user picks a file. If it cannot be read or holds no values: an error names the file and says it is not a settings file Larsal can use; nothing changes. Otherwise the portable scope is emptied first, then only known portable values are copied; unknown names and this-Mac values in the file are ignored; the this-Mac scope is untouched. The screen reloads and applies. Larsal imports only its own export format (D-01-11).
Weakening imports (Decided: spec/decisions.md LD-54): before anything changes, Larsal compares the effective value of each setting below before and after the import (a value missing from the file reads as its default). When at least one would lower protection, Larsal lists each such setting with its old and new value under the message that this import lowers protection, with buttons Apply and Cancel, Cancel being the default. Cancel: nothing changes. Apply: the import runs as above. Settings that lower protection: S-TIME-01, S-TIME-03, S-LOCK-02, S-LOCK-03, S-CONV-02, S-CONV-03, S-VIEW-07 or S-AT-03 turned off; S-TIME-02 or S-TIME-04 made longer; S-ENTRY-04, S-START-08, S-FILE-07, S-BRW-15, S-BRW-16, S-BRW-17, S-BRW-19 or S-BRW-22 turned on; S-FILE-08 set to 1; a network feature turned on (S-START-09, S-START-10, S-PRIV-01, S-ENTRY-11); S-LOCK-04 turned off; S-BRW-23 turned on, or S-BRW-24 changed while S-BRW-23 is on after the import (Decided: spec/decisions.md LD-200 (3)). Other changes apply without a question. An imported bridge program path is never written into a browser manifest without asking: S-BRW-24 becomes the `path` of every enabled browser's manifest (INT-01.9, rewritten at start by S-BRW-21), so a change to it is always in the list, and no manifest is rewritten unless the user picks Apply.

APP-01.12 **Settings file not writable.** Opening the screen shows an error that names the settings file. OK and Reset show it again, store nothing, and leave the screen open.

APP-01.13 **Bad values.** Reference: a value out of a control's range is clamped by the control when the screen opens and stored clamped on the next OK. Until then the stored value acts: S-TIME-02 of 0 or less clears at once; S-TIME-06 of 0 or less never clears; S-TIME-04 under 10 acts as 10; S-UI-04 is used clamped to −2..4 and the screen shows an extra custom choice; S-AT-09 acts within 100..10,000, S-AT-10 within 0..500; S-CFG-02 within 0..4; S-START-06 of 0 empties the list at the next open. Larsal (D-01-5): on load, a number out of its Values range is clamped to it, and a value of the wrong type reads as the default.

### Remembered state

APP-01.14 **Recent vaults.** When a vault that has a file path is opened: if S-START-05 is on, its path goes to the front of S-STATE-01, later copies of the same path are removed, and the list is cut to S-START-06; if off, S-STATE-01 is deleted. The clear-history item at the end of the recent menu deletes S-STATE-01. Removing an item on the welcome screen removes that path. A new vault that was never saved is not listed.

APP-01.15 **Last folders.** Each file dialog role keeps its last folder in S-STATE-06. Roles that reveal vaults: vault, backup copy, merge source, CSV export, XML export, HTML export, passkey import and export, key file. Their folder is not stored, and is removed, while S-START-05 is off; the key file folder also while S-START-08 is off. Other roles (attachments, icons, shared groups, SSH key) are always stored. A folder that no longer exists removes its role. With no stored folder a dialog starts in the home folder.

APP-01.16 **Key file and hardware key per vault.** At each unlock attempt the vault's entries in S-STATE-02 and S-STATE-03 are removed, then set again to the key file path and to `serial:slot` of the hardware key if those were used. Both maps are written only while S-START-08 is on. The unlock screen pre-fills from them (APP-06).

APP-01.17 **Reopen at start.** At quit, if S-START-07 is on: S-STATE-05 = paths of all open vaults with a file, in tab order; S-STATE-04 = the shown vault (deleted when it has no file). If off, both are deleted. At start, if on: each path in S-STATE-05 whose file exists is opened, then S-STATE-04 is shown. Opened vaults show the unlock view (APP-06).

APP-01.18 **Expiring entries after unlock.** With S-START-11 on, the first unlock of a vault in this run (not an unlock after a lock) shows the search for entries expired or expiring within S-START-12 days (FEA-01, MOD-09.3), titled with the number of days, or as expired entries when N is 0.

### Network options

APP-01.19 **Update check.** Reference: 0.5 s after start and then every hour. The first time, if S-MSG-02 is off, a question asks whether to check at start (Yes is the default button); the answer is stored in S-START-09 and S-MSG-02 is set. Then, if S-START-09 is on and now ≥ S-STATE-17, one HTTPS request goes to the project's public release feed: the latest stable release, or with S-START-10 the full release list, whose first item is used. On any answer without a network error, S-STATE-17 = now + 7 days. On error S-STATE-17 is unchanged, so the next hourly tick tries again. A manual check from the menu always asks, whatever S-STATE-17 says, and shows the result. A request already running blocks a new one. Larsal (D-01-2): S-START-09 is off by default, no first-start question, and no request ever starts while it is off.

APP-01.20 **Version comparison.** Versions look like `X.Y.Z`, with an optional `-` suffix of letters and optional digits (`2.8.0-beta1`). The remote tag is newer when, in order: (1) both strings are equal: not newer; (2) the local suffix is `snapshot` in any case: not newer; (3) the numbers are equal and the local version has a suffix: newer when the remote has no suffix, or when the local suffix number is lower than the remote's; (4) else compare X, then Y, then Z as numbers: the first difference decides. A remote tag that does not match the shape is never newer.

APP-01.21 **Website icon options.** Icons are downloaded only when the user asks (MOD-06.11). S-ENTRY-10 is one time limit for the whole attempt across all addresses tried: when it runs out, the download in progress stops and no icon is returned. With S-PRIV-01 on, the icon service is tried first: `https://icons.duckduckgo.com/ip3/<host>.ico` for the full host, then for the base domain when it differs and the host is not an IP address. The site's own addresses follow (MOD-06.11).
- Larsal (decided: spec/decisions.md LD-64): the download actions of MOD-06.11, and the download a browser extension asks for when it saves a login (SN-02), happen only while S-ENTRY-11 is on, and it is off until the user turns it on. No icon request carries a user name or password: the user name and password written in the entry URL are removed first. No request carries the entry URL's path, query or fragment: Larsal asks only `/favicon.ico` at the root of the host, then at the root of the base domain when it differs, with the scheme and port of the entry URL. The icon service (S-PRIV-01) gets only the host names. The reference also asks `favicon.ico` next to the entry URL's path, and keeps the user name and password on its first tries.

### Entry list, editor and display

APP-01.22 **Copy and double-click.** A double-click on the user name or password cell copies the value when S-ENTRY-04 is on, else opens the editor. A double-click on a URL cell: S-ENTRY-05 = 0 opens it, 1 copies it, 2 opens the editor. After a copy from the main window or a one-time code dialog, with S-ENTRY-08 on, the window minimizes (or hides when S-UI-12 is on) or moves behind other windows, per S-ENTRY-09. Copying selected text with the standard copy shortcut does not hide the window. Clipboard rules: APP-03.

APP-01.23 **Masking.** Masked text is six U+25CF characters (●●●●●●). Entry list: user name cell masked when S-VIEW-06 is on, password cell when S-VIEW-07 is on, notes cell when S-CONV-05 is on (else the first line of the notes with spaces collapsed). An empty user name or password shows empty, unless S-CONV-01 is on: then it shows like a filled one. Preview panel: user name hidden behind a show button when S-VIEW-06 is on; password masked with a show button when S-CONV-03 is on (empty password: empty unless S-CONV-01); one-time code hidden until its button is pressed when S-CONV-04 is on; entry and group notes hidden behind a show button when S-CONV-05 is on. Editor: password field masked when S-CONV-02 is on; notes field hidden with a reveal button when S-CONV-05 is on.

APP-01.24 **Colored passwords.** When S-UI-07 is on and the preview panel shows a password, each character is colored: digits blue (dark theme light blue), upper case dark green (light green), lower case red (yellow), others black (white).

APP-01.25 **New entries.** S-ENTRY-06 on: a new entry takes its group's icon unless the group has standard icon 48 or 49 and no custom icon (MOD-06.3). S-ENTRY-03 on: the password field of a new entry holds a password made from the stored generator values, or from generator defaults when those are invalid (FEA-02.19). S-ENTRY-01 on: the user name field completes inline from the vault's 10 most used user names (MOD-01.23), and the field name editor offers all custom field names in the vault, matching anywhere and ignoring case; off: neither (the user name drop-down list stays).

APP-01.26 **Recycle bin question.** Moving entries to the recycle bin asks only when S-ENTRY-02 is on. Deleting for good always asks (MOD-04).

APP-01.27 **Search field timers.** Without S-SEARCH-02 the search runs 0.5 s after the last keystroke; with it, only on Return. With S-TIME-05 on, the search text is cleared S-TIME-06 minutes after the search field loses focus. Focus back in the field stops the countdown; a change of selected entry or of screen restarts it from full.

APP-01.28 **Theme and text size.** S-VIEW-01 auto follows macOS dark mode and changes live; light and dark are fixed. S-UI-04 adds its value in points to the system text size, clamped to −2..4.

### Pages

APP-01.29 **Shortcuts page.** Double-click on an action opens a small dialog with a shortcut field and Save, Cancel, Restore defaults. Save with a combination that another action already has, or that is pending for another action, asks whether to take the combination from the other action (Overwrite or Discard; Discard is the default); Overwrite empties the other action's shortcut. An empty shortcut never conflicts. Restore defaults sets the action's default. On OK only actions whose shortcut differs from the default are stored. Reference edge: the Reset Shortcuts button applies at once (Cancel does not undo it) and does not remove stored custom shortcuts unless another edit is saved in the same session (Verified 2026-10-28, V-A01-3: the button sets every live action back to its default at once and reloads the list, which also drops edits not yet saved; nothing is written, so the stored custom shortcuts come back at the next start, unless an edit made afterwards on the page is saved with OK, which stores the keys as they are then). Larsal: Reset Shortcuts is an edit like any other, stored on OK, dropped on Cancel (D-01-9).

APP-01.30 **Browser page.** A browser box shows checked when Larsal's manifest file exists in that browser's folder. On OK a checked box writes the manifest (failure: an error naming the browser) and an unchecked box deletes it. S-BRW-25 on writes the manifest into S-BRW-27 for the kind in S-BRW-26 (reference; Larsal 1.0 has no own folder, D-INT01-6). While S-BRW-01 is on, the page shows an error when the proxy program is missing: the S-BRW-24 path when S-BRW-23 is on (the field also turns red), else the installed proxy's expected path. Folders and manifests: INT-01.

APP-01.31 **SSH page.** The socket used is S-SSH-02 when set, else `SSH_AUTH_SOCK`. While S-SSH-01 is on, the page shows: a warning when both are empty; else a test listing of the agent's keys with "connection works" or the agent's error. Switching S-SSH-01 off removes from the agent every key Larsal added (INT-06).

APP-01.32 **Shared groups page.** S-SHARE-01 and -02 allow imports and exports of shared groups (INT-08). When no identity is stored, one is made the first time it is needed: an RSA 2048-bit key pair, signer name = the macOS login name. Generate makes a new one; editing the signer name changes only the name. Reference edge: S-SHARE-03 is not loaded into the screen, so its box always shows checked and OK stores on (Verified 2026-10-28, V-A01-4: the page's form starts with the box checked, the page's load routine never sets it from the stored value, and OK stores what the box shows); Larsal loads the stored value (D-01-10).

### Values only in the file, and the rest

APP-01.33 **Minimum master password quality.** When a new master password is set (MOD-12), its quality (FEA-05 levels 0 Bad, 1 Poor, 2 Weak, 3 Good, 4 Excellent) below S-CFG-02 is refused with a message that it is below the required quality. The separate weak-password warning below Good still applies above the minimum.

APP-01.34 **Default file name.** For a vault without a file on disk, Save As proposes S-CFG-01, or "Passwords" plus the vault extension when empty, in the last vault folder (S-STATE-06). Save a copy proposes the same name, but starts in the last backup-copy folder when one is stored.

APP-01.35 **View-only changes.** Expanding or collapsing a group and moving an entry up or down in its group are view-only changes. With S-FILE-03 off they mark the vault modified like any change. With it on they do not, and when the vault is locked they are saved quietly; a failure there is ignored.

APP-01.36 **Safe save fallback.** When saving fails for the third time in a row while S-FILE-07 is off, Larsal asks whether to turn safe saving off. The question, its buttons and the failures that do not count are APP-05.14. Turning it off applies to that vault only (APP-05.14) and saves again; S-FILE-07 is not changed (Decided: spec/decisions.md LD-52).

APP-01.37 **Launch at login.** S-START-02 is read from the OS when the screen opens and written to the OS on OK, never to the settings file. Reference on Mac: a per-user launch agent file named by the bundle id that runs the program at login. Reset leaves it alone.

APP-01.38 **One-time messages.** Ticking the do-not-show-again box in the old key file warning sets S-MSG-01 at once; the warning is not shown again (APP-06). Development builds show a warning banner at start until the user dismisses it for that build's version (S-MSG-03).

APP-01.39 **Inventory and count.** The tables above hold every setting of the reference. The count table below gives the numbers per screen and section and the method to repeat them.

### Lead decisions

Each is a lead decision; the recommendation applies unless spec/decisions.md rules otherwise.

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-01-1 | How Larsal stores settings | (a) one file; (b) two JSON files in `~/Library/Application Support/Larsal/`: `settings.json` (portable) and `state.json` (this Mac); (c) macOS user defaults | (b). One object of Key → value per file, keys from the Key column. Written atomically (temp file, then rename), 0600, folder 0700. Unknown keys are kept on write. A file over 1 MiB or not parseable: defaults, the file renamed with a `.bad` suffix, one notice. Read at start; the running app's values win. Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-2 | Update check default | (a) reference: on, with the first-start question (Yes default); (b) off, no question, manual menu check always there | (b), per plan/security.md safe defaults (SN-01). The feed is Larsal's own release feed, chosen in E14; until it exists, S-START-09, S-START-10 and the menu item are hidden. Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-3 | Languages | (a) every translation; (b) `system` and English until Larsal ships translations | (b). Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-4 | S-START-01 | (a) offer it; (b) Larsal always runs one copy | Decided (spec/decisions.md LD-47): (b), with no exception; two copies could write one vault and one settings file at once (SR-09, APP-09.8, APP-09.9). |
| D-01-5 | Bad stored values | (a) reference handling (APP-01.13); (b) clamp to the Values range on load; wrong type reads as the default | (b). Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-6 | Secrets in settings | (a) as the reference: shared-groups key in the settings file and in exports; (b) the identity in the Keychain, never in a settings file or export | (b). Keychain item: service `app.larsal.vault`, account `share-identity`, label `Larsal shared groups identity`; quick unlock never matches it (Decided: spec/decisions.md LD-49, APP-04.5) |
| D-01-7 | Launch at login | (a) a per-user launch agent file, as the reference; (b) the macOS login item service for the app | (b): the user sees and removes it in System Settings › Login Items; no file to write. Decided: spec/decisions.md LD-200 (as recommended); the same choice as D-APP09-8 (LD-153). |
| D-01-8 | Settings not built | Build all, or skip those with no matching screen in the mockup or no effect | Skip: S-UI-02, -03, -05, -06, classic in S-VIEW-01, S-VIEW-02, S-BRW-20 (S-BRW-09 is built since LD-189; S-BRW-22 and -25 to -27 are skipped by it), S-CFG-03 to -05, S-MSG-02, -03, S-DEBUG-01, all of Not on Mac. E5-S9 lists each with this reason. Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-9 | Shortcut resets | (a) reference (APP-01.9, .29 edges); (b) Reset Shortcuts is an edit stored on OK and dropped on Cancel; Reset to defaults applies default shortcuts at once | (b). Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-10 | S-SHARE-03 not loaded by the reference screen | (a) copy the defect; (b) load the stored value | (b). Decided: spec/decisions.md LD-200 (as recommended). |
| D-01-11 | Import format | (a) also read the reference's settings file; (b) only Larsal's own export | (b). Decided: spec/decisions.md LD-200 (as recommended). |

## Count

Method:
- Controls: in each settings screen definition, count check boxes, radio buttons, number fields, choice lists, text fields and shortcut fields inside each section. Labels, buttons and read-only fields are not counted. The Shortcuts page has no definition file (it is built in code); its one table counts as one control.
- Stored values: count the entries of the reference's defaults table, the one map from each setting to its scope and default (166 entries in the source; one only in debug builds). Values stored elsewhere are counted apart.
- IDs: rows of this card; a range row counts every ID in it.

| Screen › section | Controls defined | Shown on Mac | IDs | Stored values (defaults table) |
|---|---|---|---|---|
| General › Basic › Startup | 12 | 12 | 12 | 11 (+S-START-02 in the OS) |
| General › Basic › File management | 8 | 8 | 8 | 8 |
| General › Basic › Entry management | 11 | 11 | 11 | 11 |
| General › Basic › User interface | 12 | 11 | 12 | 12 |
| General › Auto-Type | 14 | 10 | 10 (+4 in Not on Mac) | 11 (+4) |
| Security › Timeouts | 6 | 6 | 6 | 6 |
| Security › Lock options | 4 | 4 | 4 | 4 |
| Security › Convenience | 5 | 5 | 5 | 5 |
| Security › Privacy | 1 | 1 | 1 | 1 |
| Browser Integration (release build) | 27 | 26 | 27 | 20 (+7 manifest files) |
| Shortcuts | 1 | 1 | 1 | 0 (own section of the file) |
| SSH Agent | 6 | 3 | 3 (+2) | 3 (+2) |
| Shared groups | 4 | 4 | 4 | 3 |
| **Settings screens, Mac** | | **102** | **104** | **95** |
| Secret Service page (Linux) | 5 | 0 | (5 in Not on Mac) | (5) |
| View menu / search menu / generator / dialogs | – | – | 7 / 2 / 22 / 3 | 7 / 2 / 22 / 3 |
| State the app keeps | – | – | 17 | 17 |
| Only in the settings file | – | – | 5 | 5 |
| Not on Mac | – | – | 14 | 14 |
| Debug builds only | 1 | 0 | 1 | 1 |
| **Total** | **117** | **102** | **175** | **166** |

Reconciliation: 175 IDs − 10 not in the defaults table (S-START-02, S-BRW-02 to -08, S-KEYS-01, S-ENTRY-11 Larsal only) + 1 (S-AT-07 holds two values) + 1 (S-ENTRY-09 holds two) − 1 (S-SHARE-01 and -02 share one) = 166. Values only in the settings file: 5 (S-CFG); 2 act in normal use, 1 only when upgrading from an old version, 2 never.

Differs in installed version (2.7.11): 158 stored values (no S-ENTRY-01, no S-BRW-22, none of the 6 Linux portal values); no Shortcuts page; 99 controls shown on Mac.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Settings file cannot be written | APP-01.12 |
| Settings file cannot be parsed | Reference: no message; values that cannot be read act as defaults (Verified 2026-10-28, V-A01-5, with the reference command line tool 2.7.11, which reads the same settings file through the same routine, pointed at demo files in a throwaway home: a line without `=` and a broken section header are skipped, good keys before and after them are still read, also in later sections; a value with an unclosed quote is not used; there is no message and no copy of the bad file; the next time the reference writes the file, the bad lines are gone). Larsal (D-01-1): defaults, the bad file renamed with a `.bad` suffix, one notice. |
| Value out of range or wrong type | APP-01.13 |
| Import file empty, unreadable or of another format | APP-01.11 error; nothing changes |
| Global shortcut refused by macOS | Field turns red with the reason; the value is still stored on OK (S-AT-07) |
| Proxy program missing while browser integration is on | Page error (APP-01.30) |
| No SSH agent socket | Page warning (APP-01.31) |
| A remembered vault, key file or folder was deleted | Reopen skips it (APP-01.17); a missing folder removes its role (APP-01.15) |
| Settings file edited by hand while Larsal runs | Larsal (D-01-1): the file is read at start only; the next write by Larsal replaces the edits. |
| Two copies running (reference with S-START-01 off) | Both write one settings file; the last writer wins. Larsal: never two copies (D-01-4). |

## Security notes

- The settings files hold no passwords, but they reveal which vaults exist, where key files are, which hardware key and slot opens a vault (S-STATE-01 to -06), and S-CFG-02. Larsal writes them owner-only (0600, folder 0700; AT-I06), atomically, and never logs their values with vault content (AT-C06).
- The reference keeps the shared-groups private signing key in the portable settings file in plain text and writes it into every settings export. Larsal keeps it in the Keychain (service `app.larsal.vault`, its own account and label, D-01-6) and never exports it. A stolen export must not let anyone sign shared groups as the user.
- Must never happen: a network request before the user turned the feature on (SN-01). Only S-START-09 (or the manual menu check) starts the update request, and only the user's click starts an icon download, only while S-ENTRY-11 is on (LD-64). The update request reveals the IP address and Larsal's version to the feed; it uses TLS with certificate checks (SN-03). S-PRIV-01 sends every looked-up domain to a third party.
- Settings that weaken protection, all off or safe by default: S-TIME-01/03 off; S-LOCK-02/03 off; S-CONV-02/03 off; S-VIEW-07 off; S-ENTRY-04 on (more copies); S-AT-03 off (types without asking, AT-G01); S-BRW-15, -16, -17, -22 (skip consent or site rules, AT-F06); S-BRW-19; S-LOCK-04 off; S-BRW-23 on with an S-BRW-24 path (the browsers start that program as Larsal's bridge, INT-01.9); S-FILE-08 = 1 (a crash during save can damage the vault, AT-I01). S-START-08 keeps key file paths next to vault paths in the settings file: on in the reference, off in Larsal (LD-51), because the path tells a thief which file is the second factor. E5-S9 shows a short warning next to each.
- S-START-04 must keep excluding S-LOCK-04 (APP-01.8); otherwise every unlock would lock again at once.
- An imported settings file is hostile input: Larsal limits its size (D-01-1), checks every type, and ignores unknown names. An import that lowers protection or turns a network feature on is listed and needs the user's Apply (APP-01.11, LD-54).
- Reset and import must not leave a value that the screen cannot show (APP-01.13).
- Tests and Mac QA use a throwaway settings folder, never the real one.

## Test cases

Demo paths are under `/tmp/spec-app01/`. "Mail" is a demo entry with user `demo@example.com`, password `pw1`.

| Case | Given | When | Then |
|---|---|---|---|
| APP-01.1 a | Empty settings folder | Larsal starts and reads S-TIME-02 and S-START-06 | 10 and 5; no settings file has been created yet |
| APP-01.2 a | Fresh Larsal install | Read S-TIME-04, S-START-08, S-START-09, S-FILE-05, S-FILE-06 | 300, off, off, on, `{FILE_NAME}.old.larsalvault` (reference: 900, on, on after Yes, off) |
| APP-01.3 a | S-TIME-02 = 10 | Open settings, set 30, Cancel; copy the password of "Mail" | Still 10; the clipboard clears after 10 s |
| APP-01.3 b | S-TIME-02 = 10, S-TIME-04 = 300 | Set 30 and 600, OK | Next copy clears after 30 s; the idle timer restarts at 600 s |
| APP-01.3 c | Global shortcut Ctrl+Option+A registered | Open settings, enter Ctrl+Option+B, Cancel | Ctrl+Option+A works again |
| APP-01.4 a | S-UI-01 = `system` | Pick another language, OK | About 0.2 s later a restart question; No keeps the stored value |
| APP-01.4 b | S-UI-01 = `system` | Pick another language, then `system` again, OK | No question |
| APP-01.5 a | S-FILE-05 on, S-FILE-06 = `bk/{FILE_NAME}.bak` | Uncheck S-FILE-05 | Pattern field and its folder picker disabled; pattern kept |
| APP-01.5 b | S-UI-10 on | Uncheck S-UI-10 | S-UI-11 and S-UI-12 disabled |
| APP-01.6 a | S-FILE-01, -02, -03 off | Check S-FILE-01 | S-FILE-02 and -03 checked and disabled; uncheck S-FILE-01: both enabled, still checked |
| APP-01.7 a | S-STATE-01 = [`/tmp/spec-app01/a.larsalvault`], S-STATE-02 maps it to `/tmp/spec-app01/a.larsalkey`, S-STATE-06 has 3 roles | Uncheck S-START-05, OK | S-START-07 and -08 off; S-STATE-01, -02, -03, -04, -06 empty |
| APP-01.7 b | S-START-05 on, S-STATE-06 has roles vault and attachments | Uncheck only S-START-08, OK | S-STATE-02, -03 and all of S-STATE-06 deleted; S-STATE-01 kept |
| APP-01.8 a | S-LOCK-04 on, S-START-04 off | Check S-START-04, OK | S-LOCK-04 unchecked, disabled, with a note; stored off |
| APP-01.8 b | File holds S-LOCK-04 on and S-START-04 on | Open settings | S-LOCK-04 shows unchecked |
| APP-01.9 a | S-TIME-02 = 30, S-VIEW-07 off, S-BRW-01 on, S-SSH-01 on, S-STATE-01 has 2 paths, launch at login on | Reset, confirm | S-TIME-02 = 10, S-VIEW-07 on, S-STATE-01 empty; S-BRW-01 and S-SSH-01 still on; launch at login still on |
| APP-01.9 b | Any values | Reset, then Cancel in the question | Nothing changes |
| APP-01.9 c | Custom shortcut for one action | Reset, confirm | Larsal: default shortcut at once and after restart. Reference: custom one until restart (Verified 2026-10-28, V-A01-6, from the source; see APP-01.9) |
| APP-01.10 a | Shared-groups identity exists; S-TIME-02 = 30; S-STATE-01 has a path | Export to `/tmp/spec-app01/out.json` | File holds S-TIME-02 = 30; no private key, no S-STATE value |
| APP-01.11 a | `/tmp/spec-app01/empty.json` is empty | Import it | Error naming the file; no value changed |
| APP-01.11 b | File holds S-TIME-02 = 45, an unknown name `X-99`, S-STATE-01; current S-TIME-02 = 10, S-TIME-04 = 600 | Import it, Apply in the list | The list names only S-TIME-02 (10 → 45); after Apply S-TIME-02 = 45; S-TIME-04 back to default 300 (shorter, not listed); `X-99` and S-STATE-01 ignored; this-Mac values unchanged |
| APP-01.11 c | Defaults; file holds S-TIME-03 off, S-BRW-15 on, S-TIME-02 = 5 | Import it | List names S-TIME-03 (on → off) and S-BRW-15 (off → on), not S-TIME-02 (shorter); Cancel is the default; Cancel: no value changed |
| APP-01.11 d | As c | Import it, Apply | S-TIME-03 off, S-BRW-15 on, S-TIME-02 = 5 |
| APP-01.11 e | Current S-TIME-04 = 60; file holds only S-UI-07 on | Import it | List names S-TIME-04 (60 → 300: missing value reads as the default, which is longer); Apply: S-UI-07 on, S-TIME-04 = 300 |
| APP-01.11 f | Defaults; file holds only S-UI-07 on and S-TIME-02 = 5 | Import it | No list; applied at once |
| APP-01.11 g | S-LOCK-04 on, other values default (S-ENTRY-11 off, S-BRW-23 off, S-BRW-24 empty); browser bridge on with manifests written by Larsal; file holds S-LOCK-04 off, S-ENTRY-11 on, S-BRW-23 on, S-BRW-24 = `/tmp/spec-app01/proxy` | Import it; Cancel; read the `path` of each enabled browser's manifest; quit and start Larsal | List names S-LOCK-04 (on → off), S-ENTRY-11 (off → on) and S-BRW-23 (off → on, with the new S-BRW-24 path); Cancel is the default; after Cancel no value changed and every manifest `path` is still Larsal's own bridge, also after the restart |
| APP-01.12 a | Settings folder made read-only (0500) | Open settings, change S-TIME-02, OK | Error naming the file on open and on OK; screen stays open; S-TIME-02 unchanged |
| APP-01.13 a | File holds S-TIME-02 = 0 | Reference: copy "Mail" password | Cleared at once. Larsal: reads 1 s |
| APP-01.13 b | File holds S-UI-04 = 7 | Start | Reference: text +4 points, screen shows a custom choice. Larsal: reads 4 |
| APP-01.13 c | File holds S-TIME-04 = `"abc"` | Larsal starts | S-TIME-04 reads 300 |
| APP-01.14 a | S-START-06 = 3, S-STATE-01 = [b, a, c] (`/tmp/spec-app01/x.larsalvault` names) | Open a, then open d | [a, b, c], then [d, a, b] |
| APP-01.14 b | S-START-05 off, S-STATE-01 has 2 paths (file edited) | Open a vault | S-STATE-01 deleted |
| APP-01.14 c | S-STATE-01 has 2 paths | Choose the clear-history item | Recent menu empty |
| APP-01.15 a | S-START-05 off | Open `/tmp/spec-app01/x.larsalvault` through Open; add an attachment from `/tmp/spec-app01/files/` | Vault role not stored; attachments role = `/tmp/spec-app01/files` |
| APP-01.15 b | S-STATE-06 vault role = `/tmp/spec-app01/gone` (deleted) | Open dialog for a vault | Starts in the home folder; at the next pick the role is set again |
| APP-01.16 a | S-START-08 on | Unlock `a.larsalvault` with password and `a.larsalkey`; lock; open the unlock view | S-STATE-02 maps a to `a.larsalkey`; the key file is pre-filled |
| APP-01.16 b | As above | Unlock a with the password only | a's entry in S-STATE-02 removed |
| APP-01.16 c | S-START-08 off | Unlock with a key file | S-STATE-02 not written |
| APP-01.17 a | S-START-07 on; a and b open, b shown | Quit; delete a; start | b opens (unlock view) and is shown; a is skipped |
| APP-01.17 b | S-START-07 off | Quit | S-STATE-04 and -05 deleted |
| APP-01.18 a | S-START-11 on, S-START-12 = 3; today 2026-10-25; "Old" expired 2026-10-20, "Soon" expires 2026-10-27, "Later" 2026-11-30 | First unlock | Search view shows Old and Soon, title says 3 days |
| APP-01.18 b | As above, already unlocked once | Lock, unlock | No search view |
| APP-01.18 c | S-START-12 = 0 | First unlock | Only Old; title says expired entries |
| APP-01.19 a | Reference: S-START-09 on, S-STATE-17 = 1792922400 (2026-10-25 10:00 UTC), now 09:00 UTC | Hourly tick | No request |
| APP-01.19 b | As a, now 10:00 UTC, feed answers | Tick | One request; S-STATE-17 = 1793527200 |
| APP-01.19 c | As b, the network is down | Tick | S-STATE-17 unchanged; tried again an hour later |
| APP-01.19 d | Reference first start, S-MSG-02 off | 0.5 s after start | Question; Yes is the default; No stores S-START-09 off and makes no request |
| APP-01.19 e | Fresh Larsal install | Run 2 hours with network capture | No connection, no question |
| APP-01.19 f | S-START-09 off, S-STATE-17 in the future | Choose Check for updates in the menu | One request; result shown |
| APP-01.20 a | Local 2.7.11 | Remote tags 2.8.0; 2.7.11 | Newer; not newer |
| APP-01.20 b | Local 2.10.0 / 2.8.0-beta1 / 2.8.0-beta1 | Remote 2.9.5 / 2.8.0 / 2.8.0-beta2 | Not newer / newer / newer |
| APP-01.20 c | Local 2.8.0-beta2 / 2.8.0 / 2.8.0-snapshot / 2.8.0 | Remote 2.8.0-beta1 / 2.8.0-beta1 / 2.9.0 / v2.9.0 | Not newer in all four |
| APP-01.21 a | S-ENTRY-11 on, S-PRIV-01 on; entry URL `https://login.example.com/a?q=1` | Download icon (network capture) | First request `https://icons.duckduckgo.com/ip3/login.example.com.ico`, then `…/ip3/example.com.ico`, then the site's own addresses |
| APP-01.21 b | S-ENTRY-11 on, S-PRIV-01 off, same entry | Download icon | No request to the icon service |
| APP-01.21 c | S-ENTRY-11 on, S-ENTRY-10 = 2; a demo server that never answers | Download icon | After 2 s the attempt stops, no icon, no further addresses tried |
| APP-01.21 d | Fresh settings (S-ENTRY-11 off); entry URL `https://login.example.com` | Look for the icon download actions (network capture) | The actions are not offered; no request is sent |
| APP-01.21 e | S-ENTRY-11 on, S-PRIV-01 off; entry URL `https://alice:demo-pw@login.example.com:8443/acct/home?q=1#x` | Download icon (network capture) | Requests only `https://login.example.com:8443/favicon.ico`, then `https://example.com:8443/favicon.ico`; no request or header holds `alice`, `demo-pw`, `/acct`, `q=1` or `x` |
| APP-01.22 a | S-ENTRY-04 off | Double-click the password cell of "Mail" | Editor opens; with S-ENTRY-04 on, `pw1` is copied |
| APP-01.22 b | S-ENTRY-05 = 1, S-ENTRY-08 on, S-ENTRY-09 minimize; "Mail" URL `https://example.com` | Double-click the URL cell | URL copied; window minimizes |
| APP-01.22 c | S-ENTRY-08 on | Select text in the notes preview, press Cmd+C | Text copied; window stays |
| APP-01.23 a | S-VIEW-07 on, S-CONV-01 off; "Blank" has an empty password | Look at the list | Mail: `●●●●●●`; Blank: empty. With S-CONV-01 on: Blank `●●●●●●` |
| APP-01.23 b | S-CONV-05 on; Mail notes `line1` newline `line2` | List, preview, editor | List notes cell `●●●●●●`; preview notes hidden with a show button; editor notes hidden with a reveal button. Off: list shows `line1` |
| APP-01.23 c | S-CONV-04 on; "Mail" has a one-time password | Select Mail | Code hidden until its button is pressed |
| APP-01.24 a | S-UI-07 on, light theme, password `aB3$` | Show it in the preview | a red, B dark green, 3 blue, $ black; dark theme: yellow, light green, light blue, white |
| APP-01.25 a | S-ENTRY-06 on; group "Bank" has standard icon 12 | New entry in Bank | Entry icon 12; with Bank icon 48 and no custom icon: icon 0 |
| APP-01.25 b | S-ENTRY-03 on; stored generator: length 16, lower and digits only | New entry | Password field holds 16 characters of a–z and 0–9 |
| APP-01.25 c | S-ENTRY-01 on; user names alice ×3, bob ×3, carol ×1 | Type `b` in the user name field | Inline completion `bob`; with S-ENTRY-01 off: no completion, the drop-down still lists alice, bob, carol |
| APP-01.26 a | S-ENTRY-02 off (default), recycle bin on | Delete "Mail" | Moved without a question; deleting it from the bin asks |
| APP-01.27 a | S-TIME-05 on, S-TIME-06 = 1; search `mail` | Click into the entry list, wait 60 s | Search text cleared |
| APP-01.27 b | As a | Click away, return to the search field at 30 s, wait 60 s | Not cleared |
| APP-01.27 c | S-SEARCH-02 off | Type `ma` | Search runs 0.5 s after the last key; with S-SEARCH-02 on: only on Return |
| APP-01.28 a | S-VIEW-01 auto, macOS light | Switch macOS to dark | Larsal turns dark at once, no restart |
| APP-01.28 b | S-UI-04 = 2, system size 13 | Start | Text 15 points |
| APP-01.29 a | Action A has Cmd+Shift+L, action B has Cmd+K | Give A Cmd+K, Overwrite, OK | A Cmd+K, B none; both stored; others not stored |
| APP-01.29 b | As a | Give A Cmd+K, Discard | Nothing changes |
| APP-01.29 c | A has a custom shortcut | Restore defaults in A's dialog, OK | A has its default; nothing stored for A |
| APP-01.30 a | S-BRW-01 on, Firefox box off | Check Firefox, OK | Larsal's manifest exists in Firefox's folder (INT-01); uncheck and OK: file removed |
| APP-01.30 b | S-BRW-01 on, S-BRW-23 on, S-BRW-24 = `/tmp/spec-app01/missing-proxy` | Open the page | Error about the missing proxy; field red |
| APP-01.31 a | S-SSH-01 on, `SSH_AUTH_SOCK` unset, S-SSH-02 empty | Open the SSH page | Warning: no agent socket |
| APP-01.31 b | Demo agent at `/tmp/spec-app01/agent.sock`; S-SSH-02 set to it | Open the page | "Connection works" status |
| APP-01.32 a | No identity stored; macOS login name `demo` | Open the shared groups page, OK | Signer `demo`, fingerprint shown; identity stored (Larsal: in the Keychain, service `app.larsal.vault`, account `share-identity`, label `Larsal shared groups identity`; it survives a quick unlock cleanup, APP-04 T47) |
| APP-01.32 b | Reference, S-SHARE-03 stored off | Open the page | Box shows checked; OK stores on (Verified 2026-10-28, V-A01-7, from the source; see APP-01.32). Larsal: shows unchecked |
| APP-01.33 a | S-CFG-02 = 3 | Set master password `password1` (Poor, FEA-05.4) | Refused as below the required quality; a Good password is accepted without the weak warning |
| APP-01.33 b | S-CFG-02 = 9 | Set a Weak password | Refused (acts as 4) |
| APP-01.34 a | S-CFG-01 empty; new unsaved vault; vault folder role `/tmp/spec-app01` | Save As | Proposes `/tmp/spec-app01/Passwords.larsalvault`; with S-CFG-01 = `demo.larsalvault` proposes that name |
| APP-01.35 a | S-FILE-01 off, S-FILE-03 off | Collapse group "Bank" | Vault marked modified; locking asks to save |
| APP-01.35 b | S-FILE-01 off, S-FILE-03 on | Collapse "Bank", lock | Not marked modified; saved quietly at lock |
| APP-01.36 a | S-FILE-07 off; the vault file is held so saving fails | Third failed save in a row | Question to turn safe saving off, Cancel the default; Turn off: this vault saved again with the S-FILE-08 method; S-FILE-07 still off; another open vault still saves safely (LD-52) |
| APP-01.37 a | Launch at login off | Check S-START-02, OK | macOS login item registered; settings file unchanged |
| APP-01.38 a | Unlock with an old-format key file | Tick the do-not-show-again box, close | S-MSG-01 on at once; next unlock shows no warning |
| APP-01.39 a | Reference source at the commit studied | Repeat the count method | Each number in the count table matches |

## How this was learned

Read in the reference source: the general and security tabs of the settings screen definitions and their logic (load, save, dependent controls, reset, import, export); the settings store's defaults table, scopes, file locations, migration map and import and export; the extra pages for browser integration, shortcuts, SSH agent, shared groups and Secret Service, with their screen definitions; and every place that reads a setting: main window, vault view, tab handling, search bar, preview panel, entry list, entry editor, file dialogs, welcome screen, unlock screen, clipboard, idle timer, Auto-Type, icon downloader, update checker, browser settings and manifest installer, SSH agent, shared groups settings, generator, vault key settings, macOS utilities. Controls were counted with a script over the screen definitions; stored values by counting the defaults table. The installed 2.7.11 was compared by diffing the source at the 2.7.11 tag and by searching the installed program file for the setting names and page strings (UTF-16). The app's window was not opened, no vault was used, and its settings folder was not read.
