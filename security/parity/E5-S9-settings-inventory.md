# E5-S9 settings inventory (APP-01)

Story E5-S9, check: every setting has a control or a written reason why not. One row per APP-01 id (175 ids: every row and range of the card's tables; APP-01's count table says 174 because its Entry management line counts 10 of the 11 rows S-ENTRY-01 to -11). Control = the page, its frame in design/option-a/manifest.json and the control (switch names are the accessible names of the frame). Built 2026-10-28.

Store (D-01-1, LD-200): `crates/app-ffi/src/app_settings.rs`, two JSON files in `~/Library/Application Support/App` (`settings.json` portable, `state.json` this Mac; `_debug` names in debug builds; F02 and F03 override), atomic write, 0600, folder 0700, unknown keys kept, a bad file renamed `.bad` with one notice, every value checked on read (D-01-5). Option A draws no OK and Cancel: closing the window is OK, Escape is Cancel. Reset, Import and Export are built in Rust and the model (tests `app01_9_*`, `app01_10_*`, `app01_11_*`, Swift `reset`, `exportImport`) and wait for drawn buttons.

Summary: 85 ids have a drawn control; the rest are listed with their reason.

| Id | Control (page, frame, control) | Reason or note |
|---|---|---|
| S-START-01 | – | Not built: App always runs one copy (D-01-4, LD-47). |
| S-START-02 | General (settings-settings-general), Startup: "Open App at login", switch Login | OS state through SMAppService behind `LoginItem` (APP-09.28, D-01-7); shown disabled in debug builds (APP-09.29); never in the settings file. |
| S-START-03 | – | Not drawn in Option A; stored and read at start with F08 (APP-09.21, `starts_minimized`). Mockup request: a Startup row. |
| S-START-04 | – | Not drawn in Option A; stored; APP-01.8 applied on OK and on opening. Mockup request: a Startup row. |
| S-START-05 | General (settings-settings-general), Startup: "Remember recent vaults", switch Recent | APP-01.7 live and on OK; APP-01.14 recent list kept on every open. |
| S-START-06 | General (settings-settings-general), Startup: same row, stepper (Less, More), 1–25 | Cuts the recent list (APP-01.14). |
| S-START-07 | General (settings-settings-general), Startup: "Reopen the last vaults at start", switch Reopen | APP-01.17 / APP-09.20 built: kept at quit, reopened locked at start. |
| S-START-08 | – | Not drawn in Option A as its own control; default off (LD-51). The mockup's line under "Remember recent vaults" says key files are remembered: lead decision. Key file memory (APP-01.16) waits for that decision. |
| S-START-09 | General (settings-settings-general), Startup: "Check for updates", switch Updates (disabled) | Off by default, no request ever (D-01-2); the feed comes in E14, so the switch is drawn and waits. Card words: "once a week" (mockup "once a day"). |
| S-START-10 | General (settings-settings-general), Startup: "Include beta versions", switch Beta (disabled) | As S-START-09 (E14). |
| S-START-11 | General (settings-settings-general), Startup: "Show entries that expire soon after unlocking", switch Expiry | Stored; the search after the first unlock (APP-01.18) is a follow-up of FEA-01/MOD-09.3. |
| S-START-12 | General (settings-settings-general), Startup: same row, choice Expired only / Within 1, 3, 7, 14, 30, 90 days | Stored 0–90; the choice words are App's own (the mockup draws "Within 7 days"). |
| S-FILE-01 | General (settings-settings-general), Saving: "Save changes as you make them", switch Autosave | Card words (LD-167; mockup "Save after every change"). APP-01.6 live and on OK. Saving reads it in E5-S10. |
| S-FILE-02 | General (settings-settings-general), Saving: "Save when locking", switch Save on lock | Forced on and disabled while S-FILE-01 is on (APP-01.6). E5-S10. |
| S-FILE-03 | – | Not drawn in Option A; stored, forced on with S-FILE-01 (APP-01.6). Mockup request. |
| S-FILE-04 | General (settings-settings-general), Saving: "Reload the vault when another app changes it", switch Reload | E5-S10. |
| S-FILE-05 | General (settings-settings-general), Saving: "Keep a backup before saving", switch Backup | Default on (APP-01.2). E5-S10. |
| S-FILE-06 | General (settings-settings-general), Saving: the backup row's mono line | Shown read-only: `{FILE_NAME}.old.appvault` (card default; mockup `{DB_FILENAME}.old.appvault`). The pattern field and folder picker are not drawn: mockup request. |
| S-FILE-07 | General (settings-settings-general), Saving: "Safe saving", choice | Through a temporary file (off) / Temporary file moved into place / Straight into the vault file (App's words; the mockup draws only the first). E5-S10. |
| S-FILE-08 | General (settings-settings-general), Saving: the same choice | This-Mac value (0 or 1). |
| S-ENTRY-01 | – | Not drawn in Option A; stored. Effect in the editor (MOD-01.23) is a follow-up. |
| S-ENTRY-02 | General (settings-settings-general), Entries: "Ask before moving to the Recycle Bin", switch Confirm | Read when a vault opens (`askBeforeBin`, APP-01.26). |
| S-ENTRY-03 | General (settings-settings-general), Entries: "Make a password for every new entry", switch Autogen | Built: `begin_new` fills a password (never a passphrase) from the stored password options, or the built-in 32-character fallback when they are invalid (APP-01.25, FEA-02.19); test `app01_25_s_entry_03_new_entry_password`. |
| S-ENTRY-04 | General (settings-settings-general), Entries: "Double-clicking a row copies", choice Password / Nothing | Stored; the list's double-click (APP-01.22) is a follow-up with E5-S11. |
| S-ENTRY-05 | – | Not drawn in Option A; stored (APP-01.22). |
| S-ENTRY-06 | – | Not drawn in Option A; stored (MOD-06.3). |
| S-ENTRY-07 | – | Not drawn in Option A; stored. |
| S-ENTRY-08 | General (settings-settings-general), Entries: "Hide App after copying", switch Hide | Stored; the hide after copy (APP-01.22) comes with E5-S11. |
| S-ENTRY-09 | General (settings-settings-general), Entries: same row, choice Minimize / Move behind other windows | Disabled while S-ENTRY-08 is off (APP-01.5). |
| S-ENTRY-10 | – | Not drawn in Option A; stored (icon downloads, MOD-06.11). |
| S-ENTRY-11 | – | Not drawn in Option A; stored off (LD-64). |
| S-UI-01 | – | Not drawn in Option A; stored (`system`, `en`; D-01-3). |
| S-UI-02 | – | Skipped (D-01-8): the mockup's toolbar is fixed. |
| S-UI-03 | – | Skipped (D-01-8). |
| S-UI-04 | – | Not drawn in Option A; stored this-Mac, clamped −2..4 (APP-01.13). |
| S-UI-05 | – | Skipped (D-01-8). |
| S-UI-06 | – | Skipped: not on Mac (D-01-8). |
| S-UI-07 | General (settings-settings-general), Look: "Colour digits and symbols in passwords", switch Colour, with the sample | Stored; the detail pane colours as the mockup draws it today; following the switch (APP-01.24) is a lead decision. |
| S-UI-08 | General (settings-settings-general), Look: "Monospace font in notes", switch Mono notes | Stored; the notes font follows in a later pass. |
| S-UI-09 | General (settings-settings-general), Look: "Closing the window keeps App running", switch Hide on close | APP-08, E5-S11. |
| S-UI-10 | General (settings-settings-general), Look: "Show App in the menu bar", switch Menu bar | APP-08, E5-S11 (the icon); APP-09.21 minimizes until then. |
| S-UI-11 | General (settings-settings-general), Look: same row, choice Monochrome icon / Colourful icon | Disabled while S-UI-10 is off (APP-01.5). E5-S11. |
| S-UI-12 | – | Not drawn in Option A; stored. E5-S11. |
| S-AT-01 | Auto-Type (settings-settings-auto-type), Matching: "Match by window title", switch Title | Auto-Type reads it in E8. |
| S-AT-02 | Auto-Type (settings-settings-auto-type), Matching: "Match by website address in the title", switch URL | E8. |
| S-AT-03 | Auto-Type (settings-settings-auto-type), Matching: "Always ask which entry to type", switch Ask | E8. |
| S-AT-04 | – | Not drawn in Option A (W-06); stored, disabled rule with S-AT-03 in the model. |
| S-AT-05 | Auto-Type (settings-settings-auto-type), Matching: "Skip expired entries", switch Expired | E8. |
| S-AT-06 | Auto-Type (settings-settings-auto-type), Matching: "Lock again after typing", switch Relock | E8. |
| S-AT-07 | Auto-Type (settings-settings-auto-type), Shortcut: "Type the login for the window in front", ⌃⌥V and Change (disabled) | Default ⌃⌥V (LD-176). The shortcut recorder and its registration come with E8. |
| S-AT-08 | Auto-Type (settings-settings-auto-type), Timing: "Do not type the same login again within", stepper s | Mockup words kept until INT-05 (LD-167). E8. |
| S-AT-09 | Auto-Type (settings-settings-auto-type), Timing: "Wait before typing", stepper ms (step 100) | E8. |
| S-AT-10 | Auto-Type (settings-settings-auto-type), Timing: "Pause between keys", stepper ms | E8. |
| S-TIME-01 | Security (settings-settings-security), Timeouts: "Clear the clipboard after", switch Clipboard | Built: every copy reads it (`copy_value`). |
| S-TIME-02 | Security (settings-settings-security), Timeouts: same row, stepper s (step 5, 1–999) | Built: the copy's countdown. |
| S-TIME-03 | Security (settings-settings-security), Timeouts: "Lock after no use for", switch Idle lock | Built: `LockSettings(store:)` at start and after OK. |
| S-TIME-04 | Security (settings-settings-security), Timeouts: same row, stepper min | Default 300 s (APP-01.2). Built as S-TIME-03. |
| S-TIME-05 | Security (settings-settings-security), Timeouts: "Clear the search after", switch Clear search | Built: `SearchClearTimer` behind the search field (APP-01.27); test `AppSettingsEffectsTests` "APP-01.27 a, b". |
| S-TIME-06 | Security (settings-settings-security), Timeouts: same row, stepper min | Built as S-TIME-05. |
| S-LOCK-01 | Security (settings-settings-security), Locking: "Unlock with Touch ID", switch (disabled) | Quick unlock is E6-S3. |
| S-LOCK-02 | Security (settings-settings-security), Locking: "Lock when the screen locks", switch Screen lock | Built: LockSignals. |
| S-LOCK-03 | Security (settings-settings-security), Locking: "Lock when you switch user", switch User switch | Built: LockSignals. |
| S-LOCK-04 | Security (settings-settings-security), Locking: "Lock when the window is minimized", switch Minimize | Built: LockSignals; APP-01.8 with S-START-04. |
| S-CONV-01 | Security (settings-settings-security), Showing secrets: "Show dots for empty passwords", switch Dots | Stored; the list and pane follow (APP-01.23) in a later pass. |
| S-CONV-02 | Security (settings-settings-security), Showing secrets: "Hide passwords in the editor", switch Editor | As S-CONV-01. |
| S-CONV-03 | Security (settings-settings-security), Showing secrets: "Hide passwords in the detail pane", switch Preview | As S-CONV-01. |
| S-CONV-04 | Security (settings-settings-security), Showing secrets: "Hide one-time codes in the detail pane", switch Codes | As S-CONV-01. |
| S-CONV-05 | Security (settings-settings-security), Showing secrets: "Hide notes", switch Notes | As S-CONV-01. |
| S-PRIV-01 | – | Not drawn in Option A; stored off. The drawn Privacy row is APP-10's run-only capture switch (E6-S5, never stored). |
| S-BRW-01 | Browser Integration (settings-settings-browser-integration): "Let browsers use App", switch Browser | Both groups below follow it (APP-01.5). The bridge is E7. |
| S-BRW-02 | Browser Integration (settings-settings-browser-integration), Browsers: Safari | Stored; disabled until App is signed (INT-01.15). |
| S-BRW-03 | Browser Integration (settings-settings-browser-integration), Browsers: Chrome | The setup file is the state (INT-01.8); writing it comes with E7: disabled. |
| S-BRW-04 | Browser Integration (settings-settings-browser-integration), Browsers: Firefox | As S-BRW-03. |
| S-BRW-05 | Browser Integration (settings-settings-browser-integration), Browsers: Brave | As S-BRW-03. |
| S-BRW-06 | Browser Integration (settings-settings-browser-integration), Browsers: Vivaldi | As S-BRW-03. |
| S-BRW-07 | Browser Integration (settings-settings-browser-integration), Browsers: Opera | As S-BRW-03. |
| S-BRW-08 | – | Edge row: not drawn, waits for W-07. |
| S-BRW-09 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Show a notification", switch Notify | E7. |
| S-BRW-10 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Ask to unlock a locked vault", switch Unlock | E7. |
| S-BRW-11 | – | Not drawn in Option A (W-07); stored. |
| S-BRW-12 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Offer only the best matches", switch Best | E7. |
| S-BRW-13 | – | Not drawn in Option A (W-07); stored. |
| S-BRW-14 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Search every open vault", switch All vaults | E7. |
| S-BRW-15 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Never ask before giving access", switch Never ask | E7; listed by an import (LD-54). |
| S-BRW-16 | – | Not drawn in Option A (W-07); stored. |
| S-BRW-17 | – | Not drawn in Option A (W-07); stored. |
| S-BRW-18 | – | Not drawn in Option A (W-07); stored. |
| S-BRW-19 | Browser Integration (settings-settings-browser-integration), When a browser asks: "Allow passkeys on localhost", switch Localhost | E7. |
| S-BRW-20 | – | Skipped (D-01-8): no effect. |
| S-BRW-21 | Browser Integration (settings-settings-browser-integration), Advanced: "Rewrite the browser setup files at start", switch Rewrite | E7. |
| S-BRW-22 | – | Skipped (LD-189). |
| S-BRW-23 | Browser Integration (settings-settings-browser-integration), Advanced: "Use my own proxy program", switch Proxy | Card words (LD-167; mockup "Use a custom proxy location"). E7. |
| S-BRW-24 | – | Path field not drawn (W-07); stored; an import that changes it is listed (LD-200 (3)). |
| S-BRW-25 | – | Skipped (LD-189, D-INT01-6). |
| S-BRW-26 | – | Skipped (LD-189). |
| S-BRW-27 | – | Skipped (LD-189). |
| S-KEYS-01 | Shortcuts (settings-settings-shortcuts): Entries and App groups, each action with its keys | Read-only list; the shortcut dialog of APP-01.29 (Save, Cancel, Restore defaults, conflicts) is not drawn: mockup request. Stored as a map, checked on read. |
| S-SSH-01 | SSH Agent (settings-settings-ssh-agent): "Work with the SSH agent", switch SSH | Built: `set_ssh_agent` on OK and at start (INT-06.21). |
| S-SSH-02 | SSH Agent (settings-settings-ssh-agent), Agent: "Use a different socket", switch Socket (disabled); Status row shows the socket in use | The path field is not drawn (W-05). The status row asks the agent (APP-01.31). |
| S-SSH-03 | SSH Agent (settings-settings-ssh-agent), Agent: "Security key provider", Built-in | Shown; choosing another waits for W-05. |
| S-SHARE-01 | Shared Groups (settings-settings-shared-groups): "Import shared groups", switch Import | Shared groups are E11. |
| S-SHARE-02 | Shared Groups (settings-settings-shared-groups): "Export shared groups", switch Export | E11. |
| S-SHARE-03 | Shared Groups (settings-settings-shared-groups): "Do not show sharing messages", switch Quiet | Loads the stored value (D-01-10). E11. |
| S-SHARE-04 | Shared Groups (settings-settings-shared-groups), Your identity: signer, fingerprint, Export certificate… (disabled) | Key pair in the Keychain (D-01-6), E11; signer editing and Generate are not drawn. |
| S-VIEW-01 | General (settings-settings-general), Look: "Appearance" System / Light / Dark | Built: applied at once (APP-01.28); classic skipped (D-01-8). Debug builds: `APP_DEBUG_APPEARANCE` (Mac QA snapshots) wins. |
| S-VIEW-02 | – | Skipped (D-01-8). |
| S-VIEW-03 | – | View menu (APP-08, E5-S11); stored. |
| S-VIEW-04 | – | View menu (E5-S11); stored. |
| S-VIEW-05 | – | View menu (E5-S11); stored this-Mac. |
| S-VIEW-06 | – | View menu (E5-S11); stored. |
| S-VIEW-07 | – | View menu (E5-S11); stored on. |
| S-SEARCH-01 | – | Search field menu (FEA-01), not drawn; stored. |
| S-SEARCH-02 | – | Search field menu (FEA-01), not drawn; stored. |
| S-PWGEN-01 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-02 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-03 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-04 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-05 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-06 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-07 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-08 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-09 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-10 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-11 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-12 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-13 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-14 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-15 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-16 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-17 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-18 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-19 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-20 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-PWGEN-21 | – | Key stored and checked; the generator's control waits for W-10 (LD-204). |
| S-PWGEN-22 | Generator (E5-S6 frames) | Built: stored when the generator closes or applies, read when it opens (LD-204). |
| S-MSG-01 | – | Dialog flag; stored. The old key file warning sets it (APP-06). |
| S-MSG-02 | – | Skipped (D-01-2, D-01-8). |
| S-MSG-03 | – | Skipped (D-01-8). |
| S-STATE-01 | – | Kept on every open (APP-01.14) in state.json. The welcome screen's list is a follow-up (S-STATE-01 has no open time). |
| S-STATE-02 | – | Waits for S-START-08's decision (APP-01.16); deleted on OK while it is off. |
| S-STATE-03 | – | As S-STATE-02 (hardware keys, E10). |
| S-STATE-04 | – | Built (APP-01.17). |
| S-STATE-05 | – | Built (APP-01.17). |
| S-STATE-06 | – | Key checked; the file dialogs keep folders in a later pass; deleted per APP-01.7. |
| S-STATE-07 | – | Key checked; window frame left to macOS for now. |
| S-STATE-08 | – | As S-STATE-07. |
| S-STATE-09 | – | Key checked; no column choice in Option A. |
| S-STATE-10 | – | As S-STATE-09. |
| S-STATE-11 | – | Key checked; Option A's panes are fixed. |
| S-STATE-12 | – | As S-STATE-11. |
| S-STATE-13 | – | As S-STATE-11. |
| S-STATE-14 | – | Auto-Type chooser, E8. |
| S-STATE-15 | – | E8. |
| S-STATE-16 | – | E8. |
| S-STATE-17 | – | Update check, E14. |
| S-CFG-01 | – | File only (B); stored and checked; Save As reads it (APP-01.34) in E5-S10. |
| S-CFG-02 | – | File only (B, this-Mac); stored and clamped 0–4. Handoff: `vault_settings.rs` and `wizard.rs` (E5-S8) pass `min_quality: 0` today; they should read `security.min_master_quality` from the session's store (APP-01.33). |
| S-CFG-03 | – | Skipped (D-01-8). |
| S-CFG-04 | – | Skipped (D-01-8). |
| S-CFG-05 | – | Skipped (D-01-8). |
| S-NOMAC-01 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-02 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-03 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-04 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-05 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-06 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-07 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-08 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-09 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-10 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-11 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-12 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-13 | – | Not on Mac (Linux or Windows only). |
| S-NOMAC-14 | – | Not on Mac (Linux or Windows only). |
| S-DEBUG-01 | – | Skipped (D-01-8): debug builds only. |
