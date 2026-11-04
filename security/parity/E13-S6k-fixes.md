# E13-S6 part k: re-test of F-126 (security keys in Larsal's own screens, APP-06.8, MOD-06.11, M06-35) and the F-074 residual

Story: E13-S6 part k ([plan/epics.md](../../plan/epics.md)). Row: F-126 in [security/findings.md](../findings.md); the F-074 residual is LD-230 (1) and is recorded in the F-126 row. Rulings: LD-232 (4) (part k owns the part f leftovers), LD-239 (3) (part k takes the F-074 residual), LD-230 (1), W-19 and W-20 (looks Option A does not draw), OD-01 (software key only, no real device), W-08 (Mac QA), LD-220 (1) (allowed crossings to Swift).
Date: 2026-10-29 (the runs took place from 10:14 to about 10:40 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Item | Result | One line |
|---|---|---|
| F-126 (Medium): add, change and remove a security key | **fixed, re-tested** | The wizard's step 3 and the credentials page both have Option A's Security key row with a working Add… or Change…. The wizard makes a vault that opens only with the password and the key. The credentials page adds, changes and removes the key, and each change takes effect at the next save. A key that is not plugged in, or a slot that is not set up, is refused with M06-17 and changes nothing. Removing the last part is refused with M07-24. |
| APP-06.8: the automatic look | **fixed, re-tested** | The unlock screen follows larsal-hwkey's `KeyWatcher`. It looks at start and 0.5 s after a plug-in. "Look for Keys Again" looks once more and then shows M06-36. With exactly one item, that item is chosen. The watch goes away after the unlock. |
| MOD-06.11: icon downloads from the editor and the group | **re-tested: parked as W-20, as ruled** | Option A's editor Icon page draws only the logo set, and Option A draws no group download. Entry › Fetch Site Icon (⇧⌘D) downloads for the selected entry through `fetch_site_icons`. |
| M06-35 in the save progress line | **fixed, re-tested** | While a challenge waits, the save line reads "Waiting for a touch on the security key…". Each session change reads the flag from Rust again. |
| F-074 residual (LD-230 (1)): Change Now opens the whole credentials section | **fixed, re-tested** | Change Now opens a page with the Password, Key file and Security key rows, not the password card alone. Cancel goes back to the prompt. A new key file made on that page is saved and ends the prompt, and from then on the vault opens only with the password and that key file. |

All 5 items were re-tested, and none failed. Four advisories for the lead are listed at the end.

## Setup

- Private copy: `rsync -a --exclude target --exclude larsal-shots` of the tree to `/tmp/e13s6k-verify-copy`, with its own `CARGO_TARGET_DIR=/tmp/e13s6k-verify-target` and `-derivedDataPath /tmp/e13s6k-verify-dd`. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.
- `scripts/build-core.sh`: exit 0. `xcodebuild build-for-testing -scheme Larsal SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`.
- Demo data only: the larsal-ffi test vault `hardware_vault` (password `demo-pass` and the software key of demo secret D), `testdata/option-a-work-key-change.larsalvault` (password `demo-pass-8`, forced key change), and the Option A Personal, Work and Family demo vaults.
- No USB device was opened (OD-01). In the larsal-ffi unit tests, `KeyWatch` and `plugged()` use a test bus and the software key. The Swift tests swap in a fake watch through `KeyPicker.watching`, and `KeyPicker.reachesKeys` is false under XCTest. larsal-hwkey's `tests/watch.rs` registers the IOKit watch and only reads (LD-190). Nothing was shown on screen, and the general pasteboard was not used.
- My own repro tests were written in the private copy only and deleted with it: `security_keys::tests::verify_k_repro_key_only_and_wrong_slot` (Rust), and `VerifyKReproTests` "Verify k: unlock screen key watch, T19 note, and the watch ends after unlock" and "Verify k: on the forced page the key file row applies a new key, saves and ends the prompt" (Swift; one fake `KeyWatch` subclass built with `init(noHandle:)` counts `lookAgain` and `stop`).

## F-126: add, change and remove a security key (wizard and credentials page)

Steps (demo data):
1. Wizard: name, encryption (AES-KDF, 100 ms), password `orchid-meteor-pine-quartz-41` twice. Choose serial 7 slot 2, which is not plugged in, then Create Vault. Then Remove, choose the plugged-in key (serial 24531878, slot 2), and Create Vault again. Open the new file with the password alone, then with the password and the key.
2. Credentials page on `hardware_vault` (password plus key), unlocked with the key. Remove the key and save, then reopen with the password alone. Choose serial 7: refused. Add the key and save. Reopen with the password alone, then with the key.
3. Verify's own steps: on the same vault, choose slot 1 of the plugged-in key, which has only slot 2 set up. Then Use No Password, so the key is the only part, and press Remove on the key. Save, then reopen with the key alone.
4. Screens: wizard step 3 and Vault Settings › Security, offscreen.

Before (F-126 as found): neither the wizard nor the credentials page had a working row to add a key; the row was a 'later' control ("Security keys come in E10." in the old larsal-shots AX text of `vault-vault-settings-security`).

After:
- Step 1: serial 7 gives `Refused M06-17` and no file is written. After Remove and the plugged-in key, the result is `Created`. The password alone gives `Failed`, and the password with the key gives `Unlocked`. The new vault's settings show `security_key == Some(PICK)`.
- Step 2: Remove gives `Done` with `security_key == None`, and after the save the password alone gives `Unlocked`. Serial 7 gives `Refused M06-17`, with 0 changes. Add gives `Done`. After the save, the password alone gives `Failed`, and the key gives `Unlocked`.
- Step 3: slot 1 gives `Refused M06-17`, with the key unchanged and 0 changes. Use No Password asks M07-21, and after Use No Password the result is `Done`. Remove on the last part gives `Refused M07-24` ("Add a password, a key file or a security key."), and the key stays. After the save, the key alone gives `Unlocked`.
- Step 4: the wizard row reads "Security key", "A YubiKey or OnlyKey with challenge-response.", with Add… enabled, as Option A's `vault-new-vault-step-3` draws it. The credentials row reads "Security key", "Not used", with Add… enabled. After a pick, the wizard row shows the item's words, Change… and Remove. Remove clears the pick.
- Create Vault with a key chosen runs Rust's checks off the main thread (INT-07.13). While they run, `creating` is true. A key change Rust has already made is saved, and ends the forced prompt, even after its page closed (Checker 1 round's fixes).

Proof:
- `cargo test -p larsal-ffi --lib --features net` (copy, with my repro): `test result: ok. 160 passed; 0 failed; 3 ignored`. Includes `security_keys::tests::f_126_wizard_creates_a_vault_with_the_security_key`, `f_126_vault_settings_add_change_and_remove_the_security_key`, `f_126_key_watch_looks_at_start_after_a_plug_in_and_on_request`, `wizard::tests::f_126_m07_30_names_a_missed_touch`, `hwkey::tests::f_107_*` and `verify_k_repro_key_only_and_wrong_slot`, all `ok`.
- LarsalTests (copy): `SecurityKeyTests` `f126WizardSecurityKeyRow`, `f126SettingsSecurityKeyRow`, `f126CreateChecksRunOffTheMainThread`, `f126KeyChangeIsHandledAfterThePageCloses` passed (in the 51-test run below).
- Mutants (copy, one at a time, each restored and compared with `cmp`):
  - RM2, the wizard's check 6 refusal dropped (`Some(Err(_)) => None`): `f_126_wizard_creates_a_vault_with_the_security_key` FAILED at security_keys.rs:194.
  - RM4, the credentials page's key change keeps the old part (`change_key(None, None, None, …)`): `f_126_vault_settings_add_change_and_remove_the_security_key` FAILED at :260, and my repro FAILED at :315.
  - RM1, `plugged()` ignores the slot: only my repro FAILED (at :304). The shipped tests did not catch this; see advisory 1.
  - SM6, the credentials page's Add… disabled: `f126SettingsSecurityKeyRow` failed at SecurityKeyTests.swift:139, 'Expectation failed: await enabled(screen, "Add…") == true'.
  - SM7, the wizard row's Remove does nothing: `f126WizardSecurityKeyRow` failed at :93, 'model.securityKey == nil', and at :94.
  - SM13, the wizard's pick never reaches Rust (`core.setSecurityKey` dropped from `chooseSecurityKey`): no Swift test failed. See advisory 2.
- Screens: `NewVaultSnapshotTests` and `VaultSettingsSnapshotTests` passed. The fresh `vault-new-vault-step-3` shot sits beside `design/option-a/reference/light/vault-new-vault-step-3.png` with the same row: Yubico mark, title, words and Add…. The AX text of the fresh `vault-vault-settings-security` shot is 'Security key', 'Not used', 'Add…'.

## APP-06.8: the automatic look on the unlock screen

Steps: open the Personal demo vault locked on the unlock screen, with the fake watch. Then:
1. Hand the screen a first look that finds nothing.
2. Press "Look for Keys Again" twice.
3. Hand it a look with 3 slots.
4. Hand it a plug-in look with one slot.
5. Unlock with `demo-pass-7`.

Before (as found by part f): larsal-hwkey's `KeyWatcher` existed but no screen used it.

After:
- At start, `keyPicker.looking` is true and the row reads "Looking for keys…".
- After the empty look, the switch is off and the note is M06-36's "Larsal sees no security key. Plug one in and look again."
- Pressing "Look for Keys Again" calls the watch's `lookAgain` once. The second press while that look runs does nothing.
- With 3 slots: "Found 3 security keys." (T19), and none is chosen.
- After the plug-in look with one slot, that slot is chosen and the note goes (T17, T18).
- After the unlock, the unlock screen's `KeyPicker` is freed, and its watch is stopped or freed (no watch left running).
- In Rust, the watch looks at start, after a plug-in and on request, and gives no look after `stop`. larsal-hwkey looks 0.5 s or more after a plug-in.

Proof:
- `security_keys::tests::f_126_key_watch_looks_at_start_after_a_plug_in_and_on_request` ok.
- `cargo test -p larsal-hwkey`: `tests::t23_plug_in_starts_a_look_0_5_s_later ... ok`, `37 passed; 0 failed`, and `tests/watch.rs` `2 passed`.
- `SecurityKeyTests/f126UnlockScreenFollowsTheKeyWatch` passed, and my `VerifyKReproTests` unlock test passed.
- Mutants:
  - RM3, `KeyWatch::stop` does nothing: `f_126_key_watch_looks_at_start_after_a_plug_in_and_on_request` FAILED at security_keys.rs:152.
  - SM2, the unlock screen starts no watch: `f126UnlockScreenFollowsTheKeyWatch` failed at SecurityKeyTests.swift:62 ('FakeKeys.sinks.last'), and my repro failed at :41, :42 and :43.
  - SM3, no item chosen after a look: `f126UnlockScreenFollowsTheKeyWatch` failed at :66 ('unlock.pick == FakeKeys.item.pick'), and my repro failed at :59.

## MOD-06.11: the editor's and the group's icon download

Steps: read Option A (`design/option-a/mockup.js`). Then read the menus and the download code.

Result:
- Option A's editor Icon page offers the "Website logo … Fetched once from the logo set that ships with Larsal" choice and no download button. No frame draws a group download.
- W-20 parks both, as LD-232 (4) asks. The download for several selected entries waits too, because Larsal's list allows only one selection (`VaultModel.selection` is `String?`).
- Entry › Fetch Site Icon (⇧⌘D, LarsalCommandsVault.swift:61) calls `VaultModel.fetchSiteIcon()` (OpenURL.swift:57). That sends `fetchSiteIcons(vault:, entries: [id])` off the main thread and shows Rust's message as a toast.
- The W-20 wording in spec/decisions.md, the F-126 row and the E13-S6 line all match this code.

Proof: `MenuBarTests` (the item "Fetch Site Icon" with ⇧⌘D, and "Fetch Site Icons for Group…") passed in the final run. See advisory 3 for the group item.

## M06-35 in the save progress line

Steps:
1. Set the touch flag and read the shown vault's save line.
2. Clear the flag and read the line again.
3. Set the flag in Swift only, and send a session change through `WindowEvents.sessionChanged()`.

Before (as found): the save line never showed M06-35.

After: the save line is `(dirty: true, "Waiting for a touch on the security key…")` while the flag is set, and the normal words when it is clear. A session change reads `securityKeyWaits()` from Rust, so the flag set only in Swift goes back to false. In Rust, `TouchNeeded` sets the flag and `TouchEnded` clears it.

Proof:
- `SecurityKeyTests/f126SaveLineShowsTheTouchWait` passed. `hwkey::tests::f_107_touch_events_drive_m06_35` ok.
- Mutants:
  - SM4, the save line's M06-35 line dropped: failed at SecurityKeyTests.swift:156, 'words.dirty && words.text == KeyTouch.words'.
  - SM5, `sessionChanged` no longer reads the flag: failed at :166, '!left'.
  - SM8, the wizard's progress line always reads "Creating the vault…": no test failed. This is a one-line ternary; see advisory 2.

## F-074 residual: Change Now opens the whole credentials section (MOD-13.8)

Steps (copy of `testdata/option-a-work-key-change.larsalvault`, unlocked with `demo-pass-8`):
1. On the forced prompt, press Change Now.
2. Read the page, then press Cancel.
3. Press Change Now again, and use the password row's Change….
4. Verify's own steps: press Change Now. On the Key file row, make a new key file `Work-verify.larsalkey`. Then reopen the file with the password alone, and with the password and the key file.

Before (part d Verify, LD-230 (1)): Change Now opened the password card alone.

After:
- The page is titled "Credentials" and shows the Password, Key file and Security key rows. The Security key row reads "Not used" with Add…. `settings.sheet == nil`, so the password card is not opened on its own.
- Cancel sets `prompt.settings = nil`, and the prompt text "This vault requires a new master key…" shows again.
- On the second Change Now, the password row's Change… opens the password card (`.changePassword`).
- The new key file made on the page applies the new key. The vault saves and the prompt ends (`window.keyChange == nil`), and the file bytes changed. On reopening, the password alone does not unlock it, but the password with `Work-verify.larsalkey` gives `.unlocked` (MOD-13.8, MOD-13.9).

Proof:
- `SecurityKeyTests/f074ChangeNowOpensTheCredentialsPage` passed, and so did my `VerifyKReproTests` forced-page test. `WindowFixesTests` (F-074 T13, T14, MOD-13.10) passed.
- Mutants:
  - SM1, Change Now also opens the password card: failed at SecurityKeyTests.swift:186 ('settings.sheet == nil') and :192.
  - SM10, Cancel keeps the page: failed at :192, 'prompt.settings == nil'.

## Test runs

- Unchanged copy (only my repro added): `xcodebuild test-without-building` on `SecurityKeyTests`, `WindowFixesTests`, `WindowFixesMoreTests`, `NewVaultBehaviourTests`, `NewVaultChecksTests`, `NewVaultSnapshotTests`, `VaultSettingsBehaviourTests`, `VaultSettingsSnapshotTests` and `ParityLockTests`: `Test run with 51 tests in 9 suites passed after 74.115 seconds`.
- `VerifyKReproTests`: `Test run with 2 tests in 1 suite passed after 2.520 seconds`.
- Mutant batch A (SM1, SM2, SM4, SM6, SM7, SM8, each aimed at a different test): `Test run with 20 tests in 4 suites failed after 7.232 seconds with 10 issues`. Every failure was in the test aimed at its mutant, and no test that should pass failed.
- Mutant batch B (SM3, SM5, SM10, SM13): `Test run with 28 tests in 5 suites failed … with 4 issues`, again each in its own test.
- Restored copy: the Swift and Rust files were compared with `cmp` against the shared tree and were identical. The rebuild with warnings as errors gave `** TEST BUILD SUCCEEDED **`. `test-without-building` on `SecurityKeyTests`, `VerifyKReproTests`, `MenuBarTests`, `WindowFixesTests`, `WindowFixesMoreTests`, `NewVaultBehaviourTests`, `NewVaultChecksTests`, `NewVaultSnapshotTests`, `VaultSettingsBehaviourTests`, `VaultSettingsSnapshotTests` and `ParityLockTests` gave `Test run with 72 tests in 11 suites passed after 24.756 seconds`.

## Advisories for the lead (none blocks the sign-off)

1. **Test gap: the slot check in `plugged()`.** If `plugged()` is changed to ignore the slot, none of the shipped tests fails, because they only try a wrong serial (7). The code is right today: a key whose slot 1 is not set up is refused with M06-17 (my repro). Smallest fix: add the slot-1 case to `f_126_vault_settings_add_change_and_remove_the_security_key`.
2. **Swift glue lines with no test.** First, `chooseSecurityKey` handing the pick to Rust (`core.setSecurityKey`). If that line were dropped, the screen would show the key while the vault was made without it. Second, the wizard's M06-35 progress line. A Swift test cannot reach the first without a USB look (check 6 runs the real bus in the static library, OD-01). The Rust side is tested (`f_126_wizard_creates_a_vault_with_the_security_key`), and both lines read correctly. This would need a test bus in the static library, so I leave it as a note.
3. **The group download menu item already exists.** APP-08 `action.download_group_icons` ("Fetch Site Icons for Group…") is in the Vault menu and the group context menu, disabled. W-20 keeps it off because Option A draws no group download. Native menus are not Option A frames, so the lead may choose to wire it to `fetch_site_icons` for the group's entries (APP-08's rule: the group has entries and is not the bin) with no new look.
4. **Wording of the credentials row with a key.** Option A's `vault-vault-settings-security` frame shows a key: "YubiKey 5 NFC · slot 2 · challenge-response" and Change…. Larsal shows "Serial 24531878 · slot 2 · challenge-response", because the vault keeps the serial, not the model. The frame's demo state has no key ("Not used", Add…, which W-19 parks). The with-key wording is not named in W-19 and could be added there. Also carried from Checker 1: while "Creating the vault…" shows, the step 3 fields stay enabled. Typing then waits on the wizard's lock until the USB look or the write ends. Smallest fix: `.disabled(model.creating)` on the step 3 body.

Not checked with a real key (W-08, OD-01, Mac QA): the touch prompt, M06-35 during a real save, the 0.5 s look after a real plug-in, and how long a real key adds to Create Vault's checks.
