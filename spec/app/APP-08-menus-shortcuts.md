# APP-08 Menus, shortcuts, menu bar icon

Status: reviewed
Epics: E5-S11
Parity rows: SR-03, SC-04, SC-05, SI-07

## What it does

This card lists every menu of Larsal's macOS menu bar, every item in them, its default shortcut, when it is enabled, and the card that owns what it does. It also owns the menus drawn inside the window (the vault switcher, the entry's "More actions" menu, right-click menus), the keys that act inside the window, custom shortcuts, the start view shown when no vault is open, closing and minimizing the window, the optional menu bar icon with its menu, the light and dark appearance, and the rules that make every control usable with VoiceOver and the keyboard.

Larsal follows the Mac conventions: one menu bar at the top of the screen, the Larsal menu with About, Settings and Quit, standard Edit and Window menus, Command-key shortcuts, title-case menu labels, and an ellipsis on items that ask for more input. Where design/mockup.html already shows a label or a shortcut, Larsal uses it.

Owners of what items do: locking APP-02, the clipboard APP-03, saving APP-05, unlocking APP-06, the new vault wizard APP-07, single instance and opening files APP-09, screen capture APP-10, settings APP-01, and the model and feature cards named in each row.

## Inputs and outputs

In: key presses and clicks on menus, the menu bar icon and the window; the session state (which vault is shown, locked or unlocked, what is selected, whether the editor or a sheet is open); settings S-UI-09 to S-UI-12, S-VIEW-01 to S-VIEW-07, S-KEYS-01 (APP-01); macOS appearance, Reduce Motion and VoiceOver.

Out: the actions of the owning cards; the menu bar icon's state; the window's appearance.

### Settings used

| APP-01 ID | Key | Larsal default | Rule |
|---|---|---|---|
| S-UI-09 | `window.close_hides` | off | APP-08.19 |
| S-UI-10 | `menubar_icon.show` | off | APP-08.20 |
| S-UI-11 | `menubar_icon.style` | monochrome | APP-08.20 |
| S-UI-12 | `menubar_icon.minimize_to` | off | APP-08.19 |
| S-VIEW-01 | `ui.theme` | auto (shown as System) | APP-08.24 |
| S-VIEW-03 to S-VIEW-07 | sidebar, details pane, keep on top, mask user names, mask passwords | APP-01 | APP-08.8 |
| S-KEYS-01 | `shortcuts.custom` | empty | APP-08.16 |

### Messages and texts

| ID | Where | Text (Larsal) |
|---|---|---|
| M08-01 | Start view heading and line | No vault is open. / Create a vault, open one, or import passwords from another app. |
| M08-02 | Start view list heading | Recently opened |
| M08-03 | Menu bar icon tooltip | Larsal: all vaults locked / Larsal: <n> vault unlocked / Larsal: <n> vaults unlocked |
| M08-04 | Asking before "Remove All Keys from SSH Agent…" | alert: "Remove All", "Cancel" (default). Message: Remove every key from the SSH agent? Details: This also removes keys that other programs added. |
| M08-05 | A custom shortcut that macOS keeps for itself | under the shortcut field, red: macOS uses this shortcut. Choose another one. |
| M08-06 | Keyboard Shortcuts sheet title | Keyboard Shortcuts |

## Rules

### The menu bar

APP-08.1 **Order and conventions.** The menu bar holds, in this order: Larsal, File, Edit, Vault, Entry, Group, View, Tools, Window, Help. Labels use title case; an item that opens a panel, sheet or question ends in "…". Items that cannot act right now are shown disabled, not removed, except the items marked "hidden when" below. macOS adds its own standard items (Services, AutoFill, Dictation, Emoji & Symbols, Enter Full Screen, the window list, the Help search field); Larsal does not change them. A shortcut is written ⌘ (Command), ⇧ (Shift), ⌥ (Option), ⌃ (Control). The reference's menus on Mac are Database, Entries, Groups, Tools, View and Help, plus the Larsal menu items its toolkit moves there; it has no Edit or Window menu.

APP-08.2 **Larsal menu.**

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `action.about` | About Larsal | – | always | The About window (version, licence; `copy.larsal_info` of APP-03.1) |
| `action.check_updates` | Check for Updates… | – | always; hidden in builds without network code (SN-05) | APP-01.19 |
| `action.settings` | Settings… | ⌘, | always | APP-01 settings screen |
| system | Services, Hide Larsal (⌘H), Hide Others (⌥⌘H), Show All | | | macOS |
| `action.quit` | Quit Larsal | ⌘Q | always | APP-02.11 |

APP-08.3 **File menu.**

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `action.new_vault` | New Vault… | ⇧⌘N (mockup) | always | APP-07 |
| `action.open_vault` | Open Vault… | ⌘O (mockup) | always | Open panel for `.larsalvault` and the reference's vault extension (all files with Options); APP-09.15 |
| `action.open_recent` | Open Recent ▸ | – | the recent list is not empty | One item per path of APP-01.14, shown by file name, with the folder name added after " — " when two names are equal; then "Clear Menu", which empties the list (APP-01.14) |
| `action.close_vault` | Close Vault | ⌘W | a vault is shown | Closes the shown vault (APP-02.15 flow for a close); with no vault open, ⌘W closes the window (APP-08.19) |
| `action.close_window` | Close Window | ⇧⌘W | always | APP-08.19 |
| `action.save` | Save | ⌘S | the shown vault is unlocked | APP-05.6; while the entry editor is open, saves the entry instead (the mockup's editor Save) |
| `action.save_as` | Save As… | ⇧⌘S | the shown vault is unlocked | APP-05.6 |
| `action.save_copy` | Save a Copy… | – | the shown vault is unlocked | APP-05.6 |
| `ACT-IMPORT` | Import… | – | always | FEA-08.1 |
| – | Export ▸ "CSV…" (`ACT-EXPORT-CSV`), "HTML…" (`ACT-EXPORT-HTML`), "XML…" (`ACT-EXPORT-XML`) | – | the shown vault is unlocked | FEA-09 |

APP-08.4 **Edit menu.** Undo (⌘Z), Redo (⇧⌘Z), Cut (⌘X), Copy (⌘C), Paste (⌘V), Select All (⌘A) act on the focused text field, as on every Mac; AppKit text fields take these keys through the native menu items, so the items must exist. Copy follows APP-03.7 and APP-03.19: with text selected in the shown vault it runs `copy.selection`; with no selection and one entry selected it runs `copy.password`; in a dialog's own field it is the plain copy. Then a separator and `action.find` "Find…" (⌘F, mockup): focuses the search field and selects its text (FEA-01); enabled when the shown vault is unlocked. Larsal has no undo for vault changes (the reference has none).

APP-08.5 **Vault menu.**

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `action.lock_vault` | Lock <name> (mockup "Lock <name>") | ⌘L (mockup) | the shown vault is unlocked | APP-02 |
| `action.lock_all` | Lock Everything (mockup "Lock everything") | ⇧⌘L | any vault is unlocked | APP-02 |
| `action.vault_settings` | Vault Settings… | ⇧⌘, | the shown vault is unlocked | MOD-12 |
| `action.change_credentials` | Change Credentials… | – | the shown vault is unlocked | MOD-12 opened at its credentials page (MOD-12.10) |
| `action.reports` | Reports | ⇧⌘R | the shown vault is unlocked | The reports view of the mockup's sidebar (FEA-05, FEA-06, FEA-07) |
| `action.passkeys` | Passkeys… | – | the shown vault is unlocked | INT-04 |
| `action.import_passkey` | Import Passkey… | – | the shown vault is unlocked | INT-04 |
| `ACT-MERGE` | Merge Another Vault… | – | the shown vault is unlocked | MOD-11 |

Remote sync (INT-09) adds its item here when the owner's scope for E11 includes it.

APP-08.6 **Entry menu.** "One entry" means exactly one entry selected in the list (or the entry editor open, for the copy items, as in the reference).

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `action.new_entry` | New Entry (mockup) | ⌘N (mockup) | unlocked, and the recycle bin is not the selected view | E5-S5 editor, new entry (MOD-01) |
| `action.edit_entry` | Edit Entry | ⌘E (mockup) | one entry | E5-S5 editor |
| `entry.clone` | Clone Entry… (mockup) | ⌘D | one entry, not in the recycle bin | MOD-10 |
| `entry.expire_now` | Expire Entry (mockup) | – | one or more entries | MOD-09 |
| `action.delete_entry` | Delete Entry (mockup) | ⌘⌫ | one or more entries | MOD-04 (to the bin, or delete for good inside it) |
| `action.restore_entry` | Restore Entry (mockup) | ⌘R | hidden when the selection holds no bin entry | MOD-04 |
| `copy.username` | Copy Username (mockup) | ⌘B (mockup) | APP-03.1 | APP-03 |
| `copy.password` | Copy Password (mockup) | ⌘C (mockup), through Edit > Copy | APP-03.1 | APP-03.7 |
| `copy.url` | Copy URL (mockup) | ⇧⌘U | APP-03.1 | APP-03 |
| – | Copy Field ▸ "Title" (`copy.title`, ⌘I), "Notes" (`copy.notes`), then one item per custom field by name (`copy.field`) | | one entry | APP-03 |
| – | One-Time Password ▸ "Copy One-Time Password" (`ACT-OTP-COPY`, ⌘T, mockup), "Copy Password with Code" (`ACT-OTP-COPY-PW`, ⌘Y), "Show Code" (`ACT-OTP-SHOW`, ⇧⌘T), "Show as QR Code" (`ACT-OTP-QR`; decided in spec/decisions.md LD-101 (2), mockup updated), "Add One-Time Code…" or, when the entry has one, "Change One-Time Code…" (`ACT-OTP-SETUP`, mockup; LD-100) | | FEA-04.24 | FEA-04 |
| – | Tags ▸ | | one or more entries | MOD-07.7 |
| `action.open_url` | Open URL (mockup) | ⌘U (mockup) | one entry with a URL | MOD-08.31 |
| `action.download_icon` | Fetch Site Icon (mockup; LD-100) | ⇧⌘D | one entry with a URL, or several entries | MOD-06.11 |
| `action.autotype` | Type Login (mockup; LD-100) | ⇧⌘V (mockup) | one entry with Auto-Type on | INT-05 |
| `action.autotype_username`, `action.autotype_password` | Auto-Type Username Only, Auto-Type Password Only (mockup) | – | one entry with that field | INT-05 |
| `action.ssh_add`, `action.ssh_remove` | Load into SSH Agent, Remove from SSH Agent (mockup; LD-100) | ⌃H, ⌃⇧H | hidden unless one entry with an SSH key and the agent feature on | INT-06 |
| `action.passkey_remove` | Remove Passkey (mockup) | – | hidden unless one entry with a passkey | INT-04 |
| `action.entry_up`, `action.entry_down` | Move Up, Move Down | ⌥↑, ⌥↓ | hidden while the list is sorted; one entry not at the top (bottom) | MOD-02.19, APP-01.35 |

APP-08.7 **Group menu.**

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `action.new_group` | New Group… (mockup "New group") | – | a group is selected, not in the recycle bin | MOD-02 |
| `action.edit_group` | Edit Group… | – | a group is selected | MOD-02 |
| `group.clone` | Clone Group… | – | a group other than the root and the bin is selected | MOD-10 |
| `action.delete_group` | Delete Group… | – | a group other than the root is selected | MOD-04 |
| `action.sort_groups_az`, `action.sort_groups_za` | Arrange Subgroups A to Z, Arrange Subgroups Z to A | – | hidden unless the group has subgroups | MOD-02.19 |
| `action.download_group_icons` | Fetch Site Icons for Group… (also in the group's context menu; no new Option A frame needed, LD-243 (1)) | – | the group (or All entries) has entries and is not the bin (LD-243 (1)) | MOD-06.11, for every entry of the group and its subgroups |
| `action.empty_bin` | Empty Recycle Bin… (mockup "Empty Recycle Bin") | – | hidden unless the recycle bin is selected | MOD-04 |

APP-08.8 **View menu.**

| ID | Item | Shortcut | Kind | Does |
|---|---|---|---|---|
| – | Appearance ▸ System, Light, Dark | – | one checked | S-VIEW-01; APP-08.24 |
| `action.toggle_sidebar` | Hide Sidebar / Show Sidebar (mockup) | ⌃⌘S | label flips | S-VIEW-03 |
| `action.toggle_details` | Hide Details / Show Details | – | label flips | S-VIEW-04 |
| `action.mask_usernames` | Mask User Names | ⇧⌘B | check mark | S-VIEW-06 (APP-01.23) |
| `action.mask_passwords` | Mask Passwords | ⇧⌘C | check mark | S-VIEW-07 (APP-01.23) |
| `action.keep_on_top` | Keep Window on Top | ⇧⌘A | check mark | S-VIEW-05 |
| `ACT-ALLOW-CAPTURE` | Permit Screen Capture | – | check mark | APP-10.4 |

The reference also offers a classic theme, compact mode and toolbar and menu bar toggles there; Larsal skips them (APP-01 D-01-8).

APP-08.9 **Tools menu.**

| ID | Item | Shortcut | Enabled when | Does |
|---|---|---|---|---|
| `ACT-GEN-OPEN-TOOL` | Password Generator (mockup's toolbar button) | ⌥⌘G | always | FEA-02: opens the toolbar generator; with no unlocked vault shown, in a small window of its own |
| `action.ssh_clear` | Remove All Keys from SSH Agent… | – | hidden unless the agent feature is on | M08-04, then INT-06 (SI-07: this removes keys of other programs too) |

APP-08.10 **Window menu.** Minimize (⌘M) and Zoom (macOS; Minimize follows APP-08.19). Then `action.next_vault` "Show Next Vault" (⌃Tab, also ⇧⌘]) and `action.prev_vault` "Show Previous Vault" (⌃⇧Tab, also ⇧⌘[), both wrapping around; then one item per open vault, named as in the vault switcher, with a check on the shown one, ⌘1 to ⌘8 for the first eight and ⌘9 for the last (`action.vault_n`). Then Bring All to Front and the window list (macOS). Reference: ⌘1 to ⌘9 the same; next and previous vault with ⌥Tab and ⌥⇧Tab on Mac, and with ⌘PageDown and ⌘PageUp (its toolkit's Control modifier, which is Command on Mac).

APP-08.11 **Help menu.** The macOS search field, then `action.help` "Larsal Help" (⇧⌘/), which opens the user guide bundled inside Larsal (available once E14 writes it; until then the item is hidden), and `action.shortcuts` "Keyboard Shortcuts" (⌘/), which shows APP-08.17. No Help item opens a web page before the owner has decided the name and publishing (D1, E14-S6; AGENTS.md rule 7). The reference's Help menu opens bundled guide pages, its website, its issue tracker and a donation page.

APP-08.12 **When items are enabled, in general.**
- While the shown vault is locked, every item that needs an unlocked vault is disabled (APP-02.18), and the Entry and Group menus are all disabled.
- While the entry editor is open, list and group actions are disabled; the copy items act on the edited entry; ⌘S saves the entry (APP-08.3). The mockup makes the sidebar and toolbar inert in that mode.
- While a sheet or alert is open on the main window, items that act on the vault are disabled (macOS does this for sheets).
- With no vault open, File > New, Open, Open Recent, Import, the Larsal menu, Tools > Password Generator and the Window and Help items are enabled.
- Enabled states update at once when the selection or state changes.

### Inside the window

APP-08.13 **In-window menus.**
- Vault switcher (mockup, the top-left name button with "Switch vault"): heading "Vaults"; one row per open vault with its tile, its name, a lock icon when locked and a check on the shown one (choosing a row shows that vault); then "Lock <name>" (⌘L, only while the shown vault is unlocked) and "Lock everything"; then "Open vault…" (⌘O) and "New vault…" (⇧⌘N). The same IDs as the menu bar items.
- "More actions" on an entry (mockup): the mockup's items in its order, which are the Entry menu items for that entry, with the mockup's sentence-case labels and shortcut hints (⌘B, ⌘C, ⌘T, ⌘U, ⇧⌘V, ⌫). For an entry in the recycle bin: "Restore entry" and "Delete permanently".
- Right-click on an entry row: the same items as "More actions". Right-click on a group in the sidebar: the Group menu items. Right-click on a tag: MOD-07.
- Escape closes an open in-window menu (mockup).

APP-08.14 **Keys inside the window** (not menu items; from the mockup unless marked).

| Key | Where | Does |
|---|---|---|
| ↑, ↓ | entry list, or the search field | Move the selection |
| Return | entry list | Edit the selected entry |
| Return | search field | FEA-01 and APP-01.27 |
| ⌫ or ⌦ | entry list, not typing | Delete the selected entries (as `action.delete_entry`) |
| Escape | in this order: an alert or sheet (Cancel), an open menu or popover, the entry editor (cancel, with the unsaved-changes question of E5-S5), a non-empty search (clear it) | as listed |
| ⌘S | entry editor | Save the entry |
| ⌃H | a focused password-kind field | Show or hide its text (Larsal and reference) |
| ⌃G | a focused password field that offers the generator | Open the generator popup (FEA-02; Larsal and reference) |
| ⌘Return | generator popup | Apply (FEA-02) |
| Tab, ⇧Tab | everywhere | Next and previous control (APP-08.25) |

The reference's F1 (groups), F2 (entries), F3 and F6 (search) are left out: Mac keyboards send media actions on those keys, and ⌘F and Tab cover them.

APP-08.15 **Shortcuts that differ from the reference on Mac.** The reference's ⌘-shortcuts (its Control shortcuts, which its toolkit shows as Command on Mac; Verified 2026-10-28, V-A08-1: the source never turns off its toolkit's swap of Control and Command on Mac and notes that its Meta key means Control there, and the shortcut guide in the installed 2.7.11 bundle tells Mac users to read Ctrl as Cmd) are kept except:

| Action | Reference | Larsal | Why |
|---|---|---|---|
| Open URL | ⇧⌘U | ⌘U | the mockup |
| Copy URL | ⌘U | ⇧⌘U | swapped with Open URL |
| Delete entry | forward delete | ⌘⌫ in the menu; ⌫ and ⌦ in the list | Mac keyboards; the mockup |
| Next and previous vault | ⌥Tab, ⌥⇧Tab, ⌘PageDown, ⌘PageUp | ⌃Tab, ⌃⇧Tab, ⇧⌘], ⇧⌘[ | the Mac tab convention |
| Hide window | ⇧⌘M (hides to its tray icon) | none; ⌘H hides Larsal, and the menu bar icon's menu hides the window | macOS owns ⌘H |
| Password Generator | none | ⌥⌘G | reachable without the toolbar |
| Sidebar | none | ⌃⌘S | the macOS sidebar convention |
| Focus keys F1, F2, F3, F6 | yes | none | APP-08.14 |

Kept as the reference: ⇧⌘N, ⌘O, ⌘S, ⇧⌘S, ⌘W, ⌘Q, ⌘, , ⇧⌘, , ⇧⌘R, ⌘L, ⇧⌘L, ⌘N, ⌘E, ⌘D, ⌘R, ⌥↑, ⌥↓, ⌘B, ⌘C, ⌘I, ⌘T, ⌘Y, ⇧⌘T, ⇧⌘D, ⇧⌘V, ⌃H, ⌃⇧H, ⇧⌘A, ⇧⌘B, ⇧⌘C, ⌘/, ⌘1 to ⌘9, ⌘M, ⌘F.

APP-08.16 **Custom shortcuts.** Every item with an `action.*`, `copy.*`, `entry.*`, `group.*` or `ACT-*` ID in the tables above can get a custom shortcut on the Shortcuts page (APP-01.29, stored in S-KEYS-01; only values that differ from the default are stored). System items (the Larsal menu's macOS items, the Edit menu's text items, Minimize, Zoom, Enter Full Screen) cannot. A combination macOS keeps for itself is refused with M08-05: ⌘Q, ⌘H, ⌥⌘H, ⌘M, ⌘Tab, ⌘Space, ⌘`, ⌃⌘F, ⌃⌘Q. Conflicts with another action follow APP-01.29. A change shows in the menus at once. When a custom shortcut takes ⌘C, Edit > Copy keeps ⌘C for text and the action runs only when no text is selected.

APP-08.17 **Keyboard Shortcuts sheet.** `action.shortcuts` shows a sheet (M08-06) listing every action of APP-08.2 to APP-08.11 that has a shortcut, grouped by menu, with its current shortcut (custom or default), followed by the keys of APP-08.14. It is built from the same table the menus use, so it is never out of date. "Done" or Escape closes it. The reference opens a bundled web page.

APP-08.18 **Start view.** When no vault is open in the session, the window shows a start view in the unlock screen's style (centred card on the mockup's background): Larsal's mark, M08-01, three buttons "New Vault…" (`action.new_vault`), "Open Vault…" (`action.open_vault`), "Import…" (`ACT-IMPORT`), and below them, when the recent list is not empty, M08-02 with one row per recent path (file name, the folder path in grey with `~` for the home folder). Return or a double click opens the row (APP-09.15); ⌫ removes the row from the list (APP-01.14), as does the right-click item "Remove from List". Reference: a welcome page with the same three buttons and a list of full paths, opened with Return or activation, removed with Delete or Backspace.

### Window, menu bar icon and Dock

APP-08.19 **Closing and minimizing the window.**
- Closing the main window (its red button, Close Window, or ⌘W with no vault open): with S-UI-09 off, Larsal quits (APP-02.11). With S-UI-09 on: the window hides to the menu bar icon when S-UI-10 is on, else it minimizes into the Dock.
- Minimizing (⌘M, the yellow button, Window > Minimize): with S-UI-12 on and S-UI-10 on, the window hides to the menu bar icon with no animation; else it minimizes into the Dock.
- Each of these counts as a minimize for the lock-on-minimize delay (APP-02.8).
Reference: the same, including the minimize into the Dock when no tray icon shows; closing to hide and hiding also start its lock-on-minimize delay. It also has ⇧⌘M to hide the window, which Larsal drops (APP-08.15).

APP-08.20 **The menu bar icon.** Shown while S-UI-10 is on, from Larsal's start (also with the start-minimized flag, APP-09.21) until quit. Look:
- `monochrome` (default): a template image, so macOS colours it for the light or dark menu bar. Two glyphs: "unlocked" while any vault in the session is unlocked, "locked" otherwise (also when no vault is open).
- `colorful`: Larsal's icon in colour while any vault is unlocked; the same icon in grey otherwise.
The icon changes at once on every "vault locked" and "vault unlocked" signal (APP-02, APP-06.22). Its tooltip is M08-03; it never shows a vault name. APP-01 S-UI-11 notes a dark-mode variant; with a template image macOS handles that, so Larsal picks none. Reference: monochrome or colourful icon with a locked variant; on Mac its monochrome icon is a mask image that macOS recolours, like a template image; its tooltip is the window title, which names the shown vault.

APP-08.21 **The menu bar icon's menu.** A click on the icon (any button) opens its menu; it never toggles the window directly. Items:
1. `action.toggle_window` "Show Window" while the window is hidden, minimized or not in front; "Hide Window" while it is shown in front. Show brings it to front (APP-09.22); Hide hides it to the icon (counts as a minimize, APP-02.8).
2. Separator, then `action.lock_all` "Lock Everything" (⇧⌘L), enabled while any vault is unlocked.
3. Separator, then `action.quit` "Quit Larsal" (⌘Q).
Reference: the same three items (toggle window, lock all, quit); on Mac a click only opens the menu.

APP-08.22 **Hidden to the menu bar icon.** While the window is hidden to the icon, Larsal is not in the Dock or the app switcher (it runs as an accessory app); showing the window brings both back. Launching Larsal again (Finder, Spotlight, `open`) shows the window (APP-09.22). If S-UI-10 is turned off while the window is hidden, Larsal shows the window, so Larsal is never left with no way back. Reference: it leaves the Dock when its window hides (Verified 2026-10-28, V-A08-2: every hide of its main window sets the prohibited activation policy, no Dock icon and no menu bar, and every show sets the regular one again; Larsal uses the accessory policy instead, which the SDK describes as no Dock icon and no menu bar while its windows can still be clicked and activated).

APP-08.23 **Dock.** A click on the Dock icon brings the window to front (APP-09.22). The Dock menu holds only the macOS items. Files dropped on the Dock icon open through APP-09.23.

### Appearance and access

APP-08.24 **Light and dark.** View > Appearance and the settings screen set S-VIEW-01: System (follow macOS, changing live, APP-01.28), Light or Dark. Every view, sheet, panel and in-window menu uses the mockup's design values for that theme (its "Design values" section); native menus and panels follow macOS. With macOS Reduce Motion on, Larsal skips the shake of APP-06.17 and the mockup's other motion (dialog fade, scan pulse). The reference also offers a classic theme; Larsal skips it (APP-01).

APP-08.25 **VoiceOver and keyboard access** (AT-K06).
- Every control has an accessible name: its visible label, or for an icon-only button its tooltip from the mockup (for example "Password generator", "Lock vault (⌘L)" read as "Lock vault", "Show password", "Copy username").
- Lists expose rows: an entry row reads its title and user name (the masked text of APP-01.23 is read as "hidden"); a password is read only after the user chose Show for it.
- States are exposed: selected, expanded, checked, disabled.
- Messages are announced: the unlock error line (APP-06.29), toasts, banners and the messages under fields are live regions.
- Every control can be reached with Tab in visual order; the focused control shows the mockup's focus ring; every action has a menu item or a key, so nothing needs a mouse.
- Native menus are used as they are, so VoiceOver reads them with no extra work.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| ⌘C with text selected in the notes of the detail view | `copy.selection` (APP-03.7), not the password. |
| ⌘C with a list row selected, no text selected | `copy.password`. |
| ⌘C in the search field with text selected | Plain copy of the search text (APP-03.19). |
| ⌘L while the shown vault is locked | Nothing; the item is disabled. ⇧⌘L locks the others. |
| ⌘W with no vault open, S-UI-09 off | Larsal quits (APP-02.11). |
| ⌘W on a locked vault | The vault closes; its quick unlock slot is removed (APP-04.16). |
| Ten vaults open | ⌘1 to ⌘8 show the first eight, ⌘9 the tenth. |
| A custom shortcut ⌘H | M08-05; not stored. |
| A custom shortcut ⌘B for Copy URL | APP-01.29 conflict question with Copy Username. |
| Menu bar icon on, close button pressed, S-UI-09 on | Hidden to the icon; not in the Dock; icon menu says "Show Window". |
| S-UI-09 on, S-UI-10 off, close button | Minimized into the Dock. |
| S-UI-10 turned off while hidden | The window shows. |
| Screen lock with the window hidden to the icon | Vaults lock (APP-02); the icon turns to "locked"; the window stays hidden. |
| Browser unlock request while hidden to the icon | The unlock panel shows (APP-06.27); Larsal stays out of the Dock until the main window shows. |
| macOS switches to dark mode while S-VIEW-01 is System | The window changes at once. |
| Reduce Motion on, wrong password | No shake; the message still shows and is announced. |
| Entry editor open, ⌘N | Disabled (APP-08.12). |
| Recent list path no longer exists | Choosing it shows M09-07 (APP-09.15). |
| Two recent files named `Personal.larsalvault` | Shown as "Personal.larsalvault — Documents" and "Personal.larsalvault — Work". |
| ⌃H while a password-kind field has focus, on an entry with an SSH key | Shows or hides the field's text (APP-08.14); "Load into SSH Agent" does not run. The reference does the same: the field's own shortcut wins while it has focus. Whether AppKit hands ⌃H to the focused text field before the menu item's key equivalent needs Mac QA (owner's go), V-A08-5: it takes a focused field in a key window, so a visible window, and the SSH agent menu item is not built yet (E5-S11, E9). |

### Not on Mac

- Windows and Linux: a menu bar inside the window, which can be hidden; a system tray icon where a click toggles the window and a double click always toggles it; Control in place of Command; the minimize-to-tray and close-to-tray options act on the tray.

## Lead decisions

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-A08-1 | Labels with the same words as the reference's: (1) five specific labels from the approved mockup (Auto-Type, one-time password setup, the two SSH agent items, the site icon item, the hardware key switch); (2) plain names of actions, from the mockup or chosen here because there is no other natural wording: "Copy Username", "Copy Password", "Copy URL", "Open URL", "New Entry", "Edit Entry", "Clone Entry…", "Delete Entry", "New Group…", "Edit Group…", "Clone Group…", "Delete Group…", "Empty Recycle Bin…", "Remove Passkey", "Import Passkey…", "Passkeys…", "Import…", "Settings…", "Password Generator", "Keyboard Shortcuts", "Check for Updates…", "Browse…". | (a) Keep them all. (b) Keep group (2); rename group (1) in the mockup and the menus. (c) Rename both groups. | Decided: spec/decisions.md LD-100, option (b) with the lead's own names: "Type Login", "Add One-Time Code…" / "Change One-Time Code…", "Load into SSH Agent" / "Remove from SSH Agent", "Fetch Site Icon", "Use a security key". The second review renamed three more in this card for the same reason: the one-time code QR item ("Show as QR Code"), "Move Up" / "Move Down", and "Arrange Subgroups A to Z" / "Z to A"; "Fetch Site Icons for Group…" follows LD-100. |

## Security notes

- **Clipboard keys**: ⌘C copies the password only when no text is selected (APP-03.7); a user who selects text and presses ⌘C never puts the password on the clipboard by surprise.
- **No secret on system surfaces**: menus, the menu bar icon, its tooltip and the Dock never show a vault name, a password or any vault content; the tooltip says only how many vaults are unlocked (APP-10.3).
- **Locking stays one key away**: ⌘L and ⇧⌘L, the vault switcher, and the menu bar icon's "Lock Everything", also while the window is hidden.
- **Screen capture** is only allowed from View > Permit Screen Capture, unchecked at every start (APP-10.4, SC-05).
- **Masking toggles** (S-VIEW-06, S-VIEW-07) change only what the list shows; passwords are masked by default (SC-04).
- **Removing every SSH key** asks first, because it also removes keys of other programs (SI-07, M08-04).
- **Hiding is not locking**: hiding or minimizing the window does not lock unless lock-on-minimize is on (APP-02.8, SR-03).
- **No web links** in menus before publishing (AGENTS.md rule 7).
- Parity rows: SR-03 (minimize and hide, with the lock-on-minimize delay), SC-04 (masking toggles), SC-05 (screen capture toggle), SI-07 (the clear-agent item). Attack check: AT-K06 (VoiceOver).

## Test cases

Menu tests read the native menu tree Larsal builds (`NSApp.mainMenu`); screen tests drive the window. Demo vaults from testdata/.

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-08.1 | Larsal started | Read the menu bar | Larsal, File, Edit, Vault, Entry, Group, View, Tools, Window, Help, in this order |
| T02 APP-08.2 | – | Read the Larsal menu | About Larsal; Check for Updates…; Settings… ⌘,; the macOS items; Quit Larsal ⌘Q |
| T03 APP-08.2 network | Build without network code | Read the Larsal menu | No Check for Updates… |
| T04 APP-08.3 | No vault open | Read the File menu | New Vault… ⇧⌘N, Open Vault… ⌘O enabled; Save, Save As…, Save a Copy…, Export disabled |
| T05 APP-08.3 recent | Two recent paths with the same file name | Open Recent | Names with " — <folder>"; "Clear Menu" empties the list |
| T06 APP-08.3 save in editor | Editor open with a change | ⌘S | The entry is saved (editor closes as the mockup's Save) |
| T07 APP-08.4 copy | `rich-v4.larsalvault` unlocked, one entry selected, notes text selected in the detail view | ⌘C | Clipboard holds the selected text; with no selection: the password (APP-03 markers) |
| T08 APP-08.4 find | Unlocked | ⌘F | Search field focused, text selected |
| T09 APP-08.5 | `password-only.larsalvault` locked | Read the Vault menu | Lock disabled; Vault Settings… and the rest disabled; Lock Everything disabled when nothing is unlocked |
| T10 APP-08.5 label | Vault "Demo" unlocked | Read | "Lock Demo" with ⌘L |
| T11 APP-08.6 enable | Unlocked, no selection; then one entry; then two | Read the Entry menu | Edit Entry disabled, enabled, disabled; Expire Entry disabled, enabled, enabled |
| T12 APP-08.6 hidden | One entry without SSH key or passkey; list sorted | Read | SSH items, Remove Passkey, Move Up and Move Down hidden |
| T13 APP-08.6 restore | A bin entry selected | Read | Restore Entry ⌘R shown and enabled |
| T14 APP-08.6 shortcuts | Read every Entry item | – | ⌘N, ⌘E, ⌘D, ⌘⌫, ⌘R, ⌘B, ⌘C, ⇧⌘U, ⌘I, ⌘T, ⌘Y, ⇧⌘T, ⌘U, ⇧⌘D, ⇧⌘V, ⌃H, ⌃⇧H, ⌥↑, ⌥↓ on the items of APP-08.6 |
| T15 APP-08.7 | The recycle bin selected | Read the Group menu | Empty Recycle Bin… shown; New Group… disabled |
| T16 APP-08.8 | – | Choose View > Mask Passwords twice | S-VIEW-07 off then on; the check mark follows; list cells change at once |
| T17 APP-08.8 capture | Fresh start | Read | Permit Screen Capture unchecked (APP-10.4) |
| T18 APP-08.9 | SSH agent feature off | Read the Tools menu | Password Generator ⌥⌘G only |
| T19 APP-08.9 ask | Agent on | Remove All Keys from SSH Agent… | M08-04, Cancel default; Cancel removes nothing |
| T20 APP-08.10 | Ten vaults open | ⌘9; ⌃Tab | The tenth shown; then the first (wraps) |
| T21 APP-08.11 | – | Read the Help menu | Keyboard Shortcuts ⌘/; no item opens a web address |
| T22 APP-08.12 locked | Shown vault locked | Read Entry and Group menus | Every item disabled |
| T23 APP-08.12 sheet | The new vault wizard open | Read the Vault menu | Disabled |
| T24 APP-08.13 switcher | Two vaults, one locked | Open the vault switcher | Rows with a lock icon on the locked one, a check on the shown one; Lock item only for an unlocked shown vault; Open vault… ⌘O; New vault… ⇧⌘N |
| T25 APP-08.13 more | Entry with user name, password, one-time password and URL | Open "More actions" | The mockup's items in its order with ⌘B, ⌘C, ⌘T, ⌘U, ⇧⌘V, ⌫ |
| T26 APP-08.14 keys | Entry list focused | ↓, Return, Escape, ⌫ | Next row; editor opens; editor closes; delete question |
| T27 APP-08.14 typing | Focus in the search field with text | ⌫ | Deletes a character, not an entry |
| T28 APP-08.15 | – | ⌘U and ⇧⌘U on an entry with a URL | Opens the URL; copies the URL |
| T29 APP-08.16 refuse | Shortcuts page | Assign ⌘H to Copy URL | M08-05; nothing stored |
| T30 APP-08.16 store | Assign ⌥⌘U to Copy URL, OK | Read S-KEYS-01 and the Entry menu | Only that action stored; the menu shows ⌥⌘U at once |
| T31 APP-08.17 | One custom shortcut set | ⌘/ | The sheet lists it with the custom keys, grouped by menu, followed by the window keys |
| T32 APP-08.18 | No vault open, three recent paths | Look; select a row; ⌫ | Start view with M08-01, three buttons, M08-02 and three rows; the row is removed from APP-01.14's list |
| T33 APP-08.19 close | S-UI-09 off | Red button | Quit flow of APP-02.11 |
| T34 APP-08.19 hide | S-UI-09 on, S-UI-10 on | Red button | Window hidden; Larsal not in the Dock; lock-on-minimize delay started when that setting is on |
| T35 APP-08.19 minimize | S-UI-12 on, S-UI-10 on | ⌘M | Hidden to the icon with no animation |
| T36 APP-08.20 | S-UI-10 on, one vault | Unlock; lock | Icon "unlocked", then "locked"; tooltip "Larsal: 1 vault unlocked", then "Larsal: all vaults locked" |
| T37 APP-08.20 template | Monochrome style | Inspect the icon image | Marked as a template image |
| T38 APP-08.21 | Window shown | Click the icon; choose the first item | Menu: Hide Window, Lock Everything, Quit Larsal; the window hides; the item now reads Show Window |
| T39 APP-08.22 | Hidden to the icon | Turn S-UI-10 off (settings from another route, test hook) | The window shows; Larsal is back in the Dock |
| T40 APP-08.24 | S-VIEW-01 System | Switch macOS to dark | The window uses the dark design values at once |
| T41 APP-08.24 motion | Reduce Motion on | Wrong password | No shake |
| T42 APP-08.23 | Larsal running, window minimized | Click the Dock icon; then drop `password-only.larsalvault` on the Dock icon | The window comes to front; the vault opens locked with its unlock view (APP-09.23) |
| T43 APP-08.25 | VoiceOver on (AT-K06) | Walk unlock, list, detail and editor | Every control is named; list rows read title and user name, never a masked password's text |
| T44 APP-08.7 group icons | A vault with group "Mail" (two entries with URLs), an empty group "Empty" and entries in the recycle bin; a test icon server | Open the Group menu and the group context menu with each of "Mail", "Empty" and the bin selected; choose Fetch Site Icons for Group… on "Mail" | Enabled for "Mail" only (never for the bin; LD-243 (1)); the fetch sets icons on the entries of "Mail" and its subgroups (MOD-06.11) |

## How this was learned

- Read the reference source: the main window's screen definition (menus, their items and order, default shortcuts, checkable items, menu roles that move items into the Mac Larsal menu), the main window's code (the shortcuts it adds itself: tab switching, minimize and hide; the Mac-only Control shortcuts for the SSH agent; the standard shortcuts it maps; the rule for enabling each item; the recent menu and its clear item; the Copy shortcut override that copies selected text; the function keys; the close, minimize and hide behaviour; the tray icon, its menu, its locked and unlocked icons, its click handling on Mac; the Help menu targets), the Mac utilities (leaving the Dock when the window hides), the welcome page, and the password field's Control-H and Control-G actions.
- The reference window was not run (it may read its real settings folder on this Mac). Shortcuts, the Mac mapping of Control to Command, the tray icon and the Dock behaviour are from the source (Verified 2026-10-28, V-A08-1 and V-A08-2; see APP-08.15 and APP-08.22). Verified 2026-10-28: Edit > Copy and Entry > Copy Password both showing ⌘C (V-A08-3: in a hidden AppKit probe with both items on ⌘C, the first matching item in menu order, Edit > Copy, ran; while it was disabled it still took the key, and Entry > Copy Password did not run; so only Edit > Copy may own ⌘C, as the built menus do, and it then copies the selection or the password, APP-08.4); switching between a regular and an accessory app and a template menu bar image (V-A08-4: the SDK lets `setActivationPolicy` set any policy since macOS 10.9, the built app already calls it, and `NSImage.isTemplate` exists since macOS 10.5; the icon on screen is for Mac QA in E5-S11). Still open: whether ⌃H in a focused text field reaches the field before the SSH agent menu item (V-A08-5, Mac QA).
- design/mockup.html: the vault switcher menu, the "More actions" menu and its shortcut hints, the toolbar (search with ⌘F, generator, "Lock vault (⌘L)", "New Entry"), the sidebar toggle, the key handling (⌘L, ⌘S in the editor, ⌘F, ⌘N, ⌘E, ⌘C, ⌘B, ⌘T, ⌘U, arrows, Return, Escape, Delete and Backspace), both themes and the design values.
- Second review (E1-S5): checked the menus again against the reference's main window definition and code (menu order and items, default shortcuts and the ones its code adds, the Control-for-Command mapping on Mac, the Mac-only Control shortcuts for the SSH agent, the enable rules of every item, close, minimize and hide, the tray icon, its menu, its Mac click handling and its mask image, the welcome page, the keyboard shortcuts help item). Fixed the reference's tab-switching keys on Mac (Command, not Control, with PageUp and PageDown) and the close-to-hide note. Compared every label with the reference's English UI strings and renamed the near matches (see D-A08-1). Applied LD-100.
