# E10-S1 Hardware keys (SI-08, SF-04 hardware-key part, AT-H03, AT-H04)

Story: E10-S1 Detect keys and slots; challenge-response. Card: [INT-07](../../spec/integrations/INT-07-hardware-keys.md), with [FMT-04](../../spec/format/FMT-04-key-flow.md). Decisions: OD-01, LD-173, LD-175, LD-188, LD-190.
Date: 2026-10-28.
Role: Verify. I did not build or review this story. Reference access: the reference CLI and the reference's hardware-key test vault (FMT-01 Vector HK), read only, from a copy.
Result: **signed** (re-check, same day), software-only proof per OD-01. The real-key checks stay open.

- **History.** The first pass found F1 (no plug-in or removal events) and did not sign. LD-190 built them in this story.
- **Re-check.** T22, T23 and T24 pass in the Builder's tests and in my own driver (section 8). The IOKit watch starts and stops cleanly on this Mac with 0 leaks. Nothing from the first pass regressed: vectors, interop, AT-H03, AT-H04, the release search.

- **Tests:** `cargo test -p larsal-hwkey`: 37 passed. The IOKit listing passed. The IOKit watch smoke test passed. T53 with a real key is ignored (OD-01), not counted as passed.
- **Own vectors:** python3 (`hmac`, `hashlib`, a direct CRC loop) gives the same values as larsal-hwkey run through my own simulated device. Checked: T03 answers, FMT-04.6-a and -d `R` and `C`, T13 CRC `ED74` and its 10 reports, the T16 reply (stored CRC `3939`, residual `F0B8`) and the T18 serial reply `017653a6` + `c78f`. The 14 reports Larsal wrote are byte for byte the ones python expected.
- **INT-07.32 interop:** a 20-byte key file holding the variable-mode answer opens the reference's hardware-key test vault in the reference CLI (exit 0, 1 group, 2 entries). The fixed-mode answer fails (exit 1). Larsal's key flow gives `C = df5d072b…bfa1` (FMT-04.6-e) and opens the same vault through larsal-format: 1 group, 2 entries. The other direction (T48) also works: the reference CLI opens a vault Larsal wrote with the hardware key, given python's answer as a key file.
- **AT-H03:** no key, or the key pulled after the 3rd write report, during an unlock and during a save, gives `HardwareKey(Missing)` and M06-17. The save writes nothing: the file's bytes and modification time are unchanged.
- **AT-H04:** another secret, or the wrong slot answering with another secret, gives `WrongKey` and M06-06: the same error and text as a wrong password.
- **NotPermitted** gives MI07-01. **Touch:** the touch wait ends at exactly 20 s on the test clock. A key that gives up after its own 15 s gives `TimedOut`, M06-18.
- **Release:** `software-key` has 0 normal feature edges. The release binary linking larsal-hwkey, the watcher included, has 0 simulator or software-key symbols and strings. It links no PC/SC framework (T45).
- **Plug-in looks (re-check):** the first look comes when the watcher starts. Plug-ins at 0 and 210 ms give one look, 505 ms after the last. A removal starts no look. Two requests during a look give one more look, not two. Dropping the watcher joins its thread.
- **This Mac:** IOKit sees 2 HID devices, 0 with a key vendor id. No hardware key is plugged in. The IOKit watch ran 20 starts and stops: no change was reported, every sink was dropped, and `leaks --atExit` found 0 leaks.

## Setup

- `. "$HOME/.cargo/env"`, `CARGO_TARGET_DIR=/tmp/v-e10s1-target`, toolchain 1.99.1, `--offline`.
- **Scratch:** `/tmp/v-e10s1/`. `HOME=/tmp/v-e10s1/home` for every run of the reference CLI.
- **Reference vault:** a copy of the reference's hardware-key test vault, `/tmp/v-e10s1/ref/hk.vault`, SHA-256 `566be617fe9972610a714593d080fd89c10977205be010fdaf4e9c6c128fad3b`. Its hash was the same after all runs.
- **Scripts:** `/tmp/v-e10s1/py/vec.py` (python vectors), run with `python3 -I`.
- **Driver:** `/tmp/v-e10s1/driver`, a small crate outside the project with path dependencies on larsal-hwkey, larsal-format, larsal-crypto, larsal-model and larsal-ffi. It does not turn on `software-key`.
- **My own simulated device:** written from INT-07.9 to INT-07.12, behind larsal-hwkey's public `Bus` and `Device` traits. The crate's own test double is `#[cfg(test)]` and was not used. The device's reply reports come from python (`replies.txt`). For random challenges, its "live" slots compute HMAC-SHA1 with larsal-crypto, and I wrote the framing and CRC myself. The clock is fake, through `Bus::now` and `Bus::sleep`.
- **No product file was changed.** No device was opened on this Mac: the IOKit listing reads properties only.

## 1. Builder tests and INT-07 case map

First pass: unit tests `33 passed`. Re-check after LD-190, `cargo test -p larsal-hwkey --offline`:
- unit tests: `37 passed; 0 failed` (new: `t22_challenge_waits_for_a_running_detection`, `t22_requests_during_a_look_fold_into_one_more`, `t23_plug_in_starts_a_look_0_5_s_later`, `t24_removal_starts_no_look`);
- `tests/real_key.rs`: `1 passed; 1 ignored` (`t53_real_key_detect_and_challenge ... ignored, T53: needs a real key …`);
- `tests/watch.rs`: `1 passed` (`t23_iokit_watch_starts_and_stops_without_a_key`);
- doc tests: 0.

E10-S1 owns the device side of INT-07: detection, slots, challenge-response and the test double. Screen, wizard, credential page, command line and remembered-key rows belong to E5-S3, E5-S8, MOD-12.10, E12 and APP-01.16. Those rows are marked "UI wiring" below, and their device half is mapped where it exists.

| Case | Covered by | Note |
|---|---|---|
| T01, T02 | `t01_t02_vault_opens_with_the_key_and_every_save_asks_again` | 2 saves and 2 opens send 4 frames with `38`, and each save's challenge is different |
| T03 | `t03_answers_in_variable_and_fixed_mode`; Verify driver | Python equal (section 2) |
| T04 | `t04_t34_at_h04_other_secret_or_mode_is_the_wrong_key_result` | `WrongKey`; M06-06 via larsal-ffi (section 4) |
| T05 | `t05_backup_key_with_another_serial` | |
| T06 | `t06_chosen_serial_absent_is_missing` | Only the serial command `10` reaches the other key. The card now says "no HMAC frame sent" (LD-190) |
| T07 | `t07_serial_0_asks_any_key`, `t07_serial_0_asks_the_first_usable_key` | |
| T08 | `t08_only_devices_with_the_frame_protocol_are_asked` | |
| T09 | `t09_model_names` | |
| T10 | `t10_fido_interface_first` | |
| T11 | `t11_refused_keyboard_interface_is_not_permitted`; Verify driver | MI07-01 shown end to end (section 4) |
| T12 | `t12_shared_open_closed_after_use` | In code, opens and closes use only `kIOHIDOptionsTypeNone` (LD-188 (3)). A real device: needs a real key |
| T13 | `t13_frame_reports_of_the_ks_challenge`; Verify driver | Python equal |
| T14 | `t14_serial_command_skips_zero_parts`, `t14_padded_test_challenge` | Python equal (CRC `5B6B`, `0A36`, reports) |
| T15 | `t15_busy_forever_fails_after_1150_ms` | |
| T16 | `t16_reply_reports_and_one_reset`; Verify driver | larsal-hwkey accepted python's reply reports; one reset at the end |
| T17 | `t17_flipped_crc_and_short_reply_are_bad_answers` | |
| T18 | `t18_status_and_serial`; Verify driver | Python's serial reply was accepted (the challenge for serial 24531878 ran). Detection item "YubiKey 5 · serial 24531878 · slot 2" |
| T19 | `t19_touch_after_3_s`; Verify driver | Device side covered. Showing M06-35 is UI wiring (APP-06) |
| T20 | `t20_untouched_key_gives_up_after_its_15_s`; Verify driver | |
| T21 | `t21_endless_touch_wait_ends_at_20_s`; Verify driver | |
| T22 | `t22_challenge_waits_for_a_running_detection`, `t22_requests_during_a_look_fold_into_one_more`; Verify driver | The lock (section 4) and the fold in `KeyWatcher` (section 8). Pressing the button is UI wiring |
| T23 | `t23_plug_in_starts_a_look_0_5_s_later`, `t23_iokit_watch_starts_and_stops_without_a_key`; Verify driver | The look 0.5 s after the last plug-in is in `KeyWatcher` (section 8). Starting and stopping the watcher with the view is UI wiring (APP-06). An IOKit plug-in event from a real key needs a real key |
| T24 | `t24_removal_starts_no_look`; Verify driver | Removal is reported (`Change::Removed`) and starts no look. Keeping the list until the next look is screen state |
| T25 to T28 | `t25_…`, `t26_…`, `t27_…`, `t28_…` | M06-36's text is APP-06 |
| T29 | `t29_hidden_serial_is_any_key` | Storing `0:2` in S-STATE-03 is UI wiring (APP-01.16) |
| T30 | `t30_items_sorted_by_serial` | |
| T31 | UI wiring (E12) | larsal-cli does not use larsal-hwkey yet. The touch events are covered by T19 |
| T32 | `t32_no_key_no_touch_event` | Device side covered. The command line text and exit code are E12 |
| T33 | `t33_clear_slot_bit_is_slot_not_configured` | |
| T34 | `t04_t34_…`; Verify driver | AT-H04 |
| T35 | `t35_at_h03_key_missing_or_removed`; Verify driver | Bytes and modification time unchanged (section 4). "Still open and changed" is UI wiring (APP-05) |
| T36 | UI wiring (APP-05) | Device side: a save with the key present works (T01, T02) |
| T37 | Not E10-S1 | The AT-C01 memory scan belongs to E6-S6 and E13-S4 (todo). Code read: the reply and the scratch report are `SecretBytes` (`read_reply`) |
| T38, T39, T40, T41, T42 | UI wiring (APP-01.16, APP-07, MOD-12.10, APP-05) | T40's "no test challenge": `HardwareKey::ask` sends none (T01's frame list has `38` only) |
| T43, T44 | UI wiring (E12, INT-10) | |
| T45 | Verify | `otool -L` of the release binary (section 5) |
| T46 | Verify driver; larsal-format `fmt_04_6_e_vector_hk` (E3-S3) | Variable opens; fixed gives `WrongKey` |
| T47 | Builder tests; Verify | `nm -u` of the unit-test binary: 0 IOKit imports. The IOKit listing binary has 8 (control) |
| T48 | Verify (section 3) | The reference CLI opens Larsal's vault |
| T49 | `t49_only_known_commands_are_sent` | |
| T50, T52 | UI wiring (fake driver, APP-06, APP-07, MOD-12) | |
| T51 | larsal-format `fmt_04_21_a_refused_before_the_device` (E3-S3); Verify driver | Through larsal-hwkey: `TooLarge(KdfCost)` with 0 reports written. With no key: `Missing` in 14 µs, against 572 ms for a full open with the KDF. So the key is asked before the KDF runs |
| T53 | **needs a real key** (OD-01) | Ignored test |

## 2. Independent vectors

Python (`python3 -I py/vec.py ref/hk.vault replies.txt`):

```
T03 variable 5744a1267b30e12442156bbd9d54715541765d89
T03 fixed    c66e7366f1946a047868cb828a4ed86cbfd02464
FMT-04.6-a R 42a98ddc572e2b0544d137fff9b9ad6085d9ec90dd88916e362d53b8e62cd0ec
FMT-04.6-a C 3d23a499d7507e100fadf6c03da0684c4b65b7f6e00f514dbbb3f3f86d100f75
FMT-04.6-d R 4b53360059a9e83ea2232a2fc274d9d04118d75dae079be95ec01b31a52c4ef3 C ee3fe4b7315239c2433795d805290e37b3d5b93fc8783a4f37904b13f5374850
T13 CRC ED74 stored 74ed
T13 reports 3481483a67fb3680 5da911c509542081 ce2bfd2161793b82 47d7a6561cedf983 21899e6320202084 2020202020202085 2020202020202086 2020202020202087 2020202020202088 203874ed00000089
T16 reply   5744a1267b30e140 2442156bbd9d5441 715541765d893942 3900000000000043 0000000000000040 | stored CRC 3939 | residual F0B8
T18 serial  017653a6 + c78f reports 017653a6c78f0040 0000000000000040
T14 serial frame CRC 5B6B 0000000000000080 00106b5b00000089
T14 test challenge CRC 0A36 5a3f3f3f3f3f3f80 3f3f3f3f3f3f3f81 … 3f3f3f3f3f3f3f88 3f30360a00000089
```

larsal-hwkey, through the driver's device (`v-e10s1-driver vectors`). The choice was `24531878:2`, so the serial is read first:

```
[y5] T03 answer 5744a1267b30e12442156bbd9d54715541765d89
[y5] WRITES 0000000000000080 00106b5b00000089 000000000000008f 3481483a67fb3680 5da911c509542081 ce2bfd2161793b82 47d7a6561cedf983 21899e6320202084 2020202020202085 2020202020202086 2020202020202087 2020202020202088 203874ed00000089 000000000000008f
[y5] reply reports read 017653a6c78f0040 0000000000000040 5744a1267b30e140 2442156bbd9d5441 715541765d893942 3900000000000043 0000000000000040
[y5] FMT-04.6 R 42a98ddc572e2b0544d137fff9b9ad6085d9ec90dd88916e362d53b8e62cd0ec C 3d23a499d7507e100fadf6c03da0684c4b65b7f6e00f514dbbb3f3f86d100f75
[y5f] T03 answer c66e7366f1946a047868cb828a4ed86cbfd02464
[y5f] FMT-04.6 R 4b53360059a9e83ea2232a2fc274d9d04118d75dae079be95ec01b31a52c4ef3 C ee3fe4b7315239c2433795d805290e37b3d5b93fc8783a4f37904b13f5374850
T18/T25 detect item: YubiKey 5 · serial 24531878 · slot 2 (needs touch false)
```

A shell comparison of the driver's `WRITES` with python's expected list (serial frame, reset, HMAC frame, reset) printed `WRITES equal python EXPECT-WRITES (14 reports)`. `R` and `C` come from larsal-format's public `hardware_part` and `composite_key`, with larsal-hwkey as the `ChallengeResponse`.

## 3. INT-07.32 interop without hardware

1. **Seed.** Python found the vault's KDF seed in its KDF map: `828824cb…8485d8`, equal to FMT-04.6-e.
2. **Answers.** Python computed the variable-mode answer `ec5f7c1427d8b26b9984228abb98621b1165ba18` and the fixed-mode answer `9c401f62…19c0`, each written as a 20-byte key file.
3. **Reference CLI, database info command, password `a`, `HOME=/tmp/v-e10s1/home`:**
   - `-k answer-var.key`: exit 0. "Cipher: AES 256-bit", "KDF: Argon2d (8 rounds, 131072 KB)", "Number of groups: 1", "Number of entries: 2".
   - `-k answer-fix.key`: exit 1, "Invalid credentials … (HMAC mismatch)".
   - No key file: the same error.
4. **Larsal, through the driver.** The device's slot 2 replies with python's variable-mode reports, choice `0:2`:
   ```
   INT-07.32 ref R 709b0674aa1124dab024c7d50e428badb26829ca8485e03844300daadff5bf6a C df5d072b8c138f85dea5d2f04ceefcf3c001f3c83c25d9a2a5c0f548fbd8bfa1
   INT-07.32 ref open (variable answer): Ok("OpenedVault { version: (4, 0), cipher: Aes256Cbc, compression: Gzip, kdf: \"Argon2d\", … groups: 1, entries: 2, … warnings: 0 }")
   T46 ref open (fixed answer): Err(WrongKey)
   ```
   `R` and `C` equal python and FMT-04.6-e. The open gives the same counts as the reference CLI.
5. **The other direction (T48).** The driver saved a vault, H, with larsal-format: password `demo-pass`, live slot 2 with secret D in variable mode, choice `24531878:2`. That gave 1,607 bytes, and H reopens with the key. Python read H's KDF seed (`cc6610f2…bb16`) and computed `HMAC-SHA1(D, seed)` = `7eba84063f86625716d3c69c340af2e103045f18` into `answer.key`. The reference CLI then opened H: with `-k answer.key`, exit 0 ("KDF: AES (1000 rounds)", 1 group, 0 entries); without the key file, exit 1.
6. **Re-check.** The reference vault with `answer-var.key` gave exit 0, 1 group and 2 entries; with `answer-fix.key`, exit 1. A new H of 1,943 bytes (larsal-format changed in the meantime under another story) has seed `0463a861…f0e2` and answer `0d6868f1…7a37`. With `answer.key` it gave exit 0 and 1 group; without the key file, exit 1. The driver's `R` and `C` were unchanged and the reference vault opened again (1 group, 2 entries).

## 4. AT-H03, AT-H04, NotPermitted, touch

`v-e10s1-driver attacks`. The messages come from larsal-ffi's `for_open_error` on the error larsal-format returned:

```
AT-H04 wrong password, right key: WrongKey -> M06-06 "Wrong password, key file or security key. Check them and try again."
AT-H04 another key (secret D in slot 2): WrongKey -> M06-06 "…" | same as wrong password: true
AT-H04 wrong slot (slot 1 answers with another secret): WrongKey -> M06-06 "…" | same as wrong password: true
AT-H04 same key, right slot 2: Ok("opened")
AT-H04 wrong slot (slot 1 not configured): HardwareKey(SlotNotConfigured) -> M06-19 "…"
AT-H04 wrong slot (slot 1 one-time password, silent): HardwareKey(SlotNotConfigured) after 1s -> M06-19 "…"
AT-H03 no key: HardwareKey(Missing) -> M06-17 "Your security key is not connected. Plug it in, then try again."
AT-H03 removed after 3rd write report, unlock: HardwareKey(Missing) -> M06-17 "…" (writes 3)
AT-H03 removed after 3rd write report, save: HardwareKey(Missing) -> M06-17 "…" | file bytes unchanged true | mtime unchanged true
NotPermitted: HardwareKey(NotPermitted) -> MI07-01 "macOS did not let Larsal reach your security key. Allow Larsal under System Settings › Privacy & Security › Input Monitoring, then try again." | interfaces tried [Keyboard]
NotPermitted detect: Err(NotPermitted)
touch forever: Err(HardwareKey(TimedOut)) M06-18 "…" | first touch report at 0ns, ended at 20s (waited 20s) | events [(TouchNeeded, 0ns), (TouchEnded, 20s)]
touch never: Err(HardwareKey(TimedOut)) M06-18 "…" | first touch report at 0ns, ended at 15.011s (waited 15.011s) | events [(TouchNeeded, 0ns), (TouchEnded, 15.011s)]
touch after 3 s: Ok("opened")  | first touch report at 0ns, ended at 3.011s (waited 3.011s) | events [(TouchNeeded, 0ns), (TouchEnded, 3.011s)]
```

- **The save test.** The vault file was H from section 3, on disk. The driver writes only when `save` returns bytes, as a caller does. `save` returned no bytes, so the file stayed as it was.
- **INT-07.13 lock** (`v-e10s1-driver lock`): real clock, two threads, one simulated key. Slot 1 is silent, so detection waits 1 s on it.
  ```
  T22 lock: detect Ok(1), challenge Ok("5744a126…5d89"); challenge asked at 110.031875ms, detection's last report at 1.008506208s, challenge's first report at 1.008573208s; interleaved: false
  ```
- **Re-check.** Every line above came back the same, the touch times and messages included. The lock line gave `challenge asked at 103 ms, detection's last report at 1.010311 s, challenge's first report at 1.010405 s; interleaved: false`. T51 gave the same two results.
- **T51** (`v-e10s1-driver t51`). The input is a copy of the reference vault with Argon2 iterations set to 1,000,000,001 and its header SHA-256 recomputed:
  ```
  T51 cost 1,000,000,001: TooLarge(KdfCost) | reports written to the key: 0
  T51 order: no key -> HardwareKey(Missing) in 14µs; with the key (KDF Argon2d 128 MiB x 8 runs) opened true in 572.396166ms
  ```

## 5. Release build: no simulator, no software key

- **Feature tree.**
  - `cargo tree --workspace -e features,normal | grep -c software-key`: `0`.
  - With dev edges: `2`, the dev-dependencies of larsal-format and larsal-hwkey.
  - `cargo tree -p larsal-hwkey -e features,normal`: `0`. Its normal dependencies are larsal-crypto, larsal-format (default features), thiserror, objc2-io-kit (`std`, `hid`) and objc2-core-foundation (`std`, `CFNumber`, `CFSet`, `CFString`).
- **Release rlib.** `cargo build --release -p larsal-hwkey -p larsal-cli` (workspace release profile).
  - The larsal-hwkey rlib has 0 strings matching `sim.rs|tests.rs|SimBus|SoftwareKey|SlotMode|touch_forever|busy_forever|flip_crc|short_reply|keyboard_refused`. Control: `usb/mod.rs` has 2.
  - The larsal-format rlib's code (LLVM bitcode member) has 0 `SoftwareKey`. `lib.rmeta` holds the names `software-key`, `SlotMode` and `SoftwareKey` once each, in rustc's symbol table next to `tests` and `hmac_sha1`. These are cfg names only, no code.
- **Release binary.** `/tmp/v-e10s1/rel` is a release binary that links detection and a challenge over `UsbBus`. It uses the workspace release profile with symbols kept so they can be searched, and is built only, never run.
  - `nm` matching `larsal_hwkey..*sim|SimBus|SimHandle|SoftwareKey|SlotMode`: 0. Control: 25 `larsal_hwkey` symbols.
  - `strings` matching `sim.rs|src/tests.rs|SoftwareKey|touch_forever|flip_crc|Larsal demo HMAC secret`: 0.
  - `otool -L`: IOKit, CoreFoundation, libSystem, libiconv. No PC/SC framework (T45).
- **Larsal CLI.** The release `larsal` binary has 0 of these strings.
- **Re-check.** The binary was rebuilt with `KeyWatcher` linked (30 symbols).
  - Simulator, software-key and `plug_in`/`pull_out` symbols: 0. Test strings: 0. `software-key` normal edges: 0.
  - `nm -u`: 13 IOHID imports. Among them are `IOHIDManagerRegisterDeviceMatchingCallback`, `…RemovalCallback`, `…ScheduleWithRunLoop`, `…UnscheduleFromRunLoop` and `…SetDeviceMatchingMultiple`. There is no `IOHIDManagerOpen` and no input report call.
  - The unit-test binary still has 0 IOHID imports (T47).
  - `otool -L` now also lists AppKit, Foundation and libobjc. They come from larsal-format → larsal-platform (`cargo tree -i objc2-app-kit`), a dependency another story added to larsal-format during this check, not from larsal-hwkey. Still no PC/SC framework.

## 6. IOKit listing on this Mac

- `cargo test -p larsal-hwkey --test real_key -- --nocapture` printed `IOKit: 2 HID devices, 0 with a key vendor id`, then `1 passed; 1 ignored`.
- `ioreg -r -c IOHIDDevice -l` shows 26 HID entries, 0 with vendor id 4176 (`1050`) or 7504 (`1D50`).
- So no hardware key is connected, and none was tested. The acceptance line now says "simulated key (OD-01), and a real key when the owner plugs one in".

## 7. LD-188 conditions (code read)

- (1) The workspace pins `=0.3.2` for both crates, `default-features = false`. The features are those of the approved table in `plan/architecture.md`.
- (2) Only `crates/larsal-hwkey/src/usb/` imports `objc2_io_kit` or `objc2_core_foundation` (`mod.rs` and, since LD-190, `watch.rs`). The new core-foundation features (`CFArray`, `CFDate`, `CFDictionary`, `CFRunLoop`) are already turned on by objc2-io-kit's `hid` (Cargo.toml comment, Checker note). LD-188 (3)'s LD-190 note lists the new calls.
- (3) Opens and closes use only `kIOHIDOptionsTypeNone`. There is no seize and no input report. Since LD-190, `usb/watch.rs` adds only the matching and removal callbacks, on the crate's own run-loop thread, and never opens the HID manager. LD-188 (3) carries that note, and the unsafe second review of the 8 new blocks is signed on the board.
- (5) Open, needs a real key.

## 8. Re-check after LD-190: plug-in looks and the IOKit watch

**KeyWatcher through my own driver** (`v-e10s1-driver watcher`):
- The bus is a new `Send` bus in the driver, with its own `watch`, `plug_in` and `pull_out`. Each look is noted by the time of its device listing.
- The keys are live simulated keys with secret D in slot 2. The watcher's 0.5 s is real time.

```
T22 fold: 2 requests at ~100 ms during the first look -> 2 looks, started at [0ns, 1.010304416s]; results ["1.010293833s: devices 1 items [\"YubiKey 5 · serial 24531878 · slot 2\"]", "2.015360166s: devices 1 items [\"YubiKey 5 · serial 24531878 · slot 2\"]"]
T23 look when the view appears: devices 0 items []
T23 plug-ins at 0 and 210.038584ms: look started 505.184333ms after the last plug-in (715.222917ms after the first); devices 2 items ["YubiKey 5 · serial 1000 · slot 2", "YubiKey 5 · serial 24531878 · slot 2"]; another look within 1.2 s: false; looks in all 2
T24 first look: devices 1 items ["YubiKey 5 · serial 24531878 · slot 2"]; after pull-out, a look within 1.5 s: false; looks in all 1
T24 look again after pull-out: devices 0 items []
KeyWatcher drop joined in 53.792µs; deliver channel closed: true
```

**IOKit watch on this Mac, no key plugged in** (`v-e10s1-driver iokit-watch`, then each binary under `leaks --atExit`):

```
IOKit watch: 20 starts and stops, slowest 236.654542ms (incl. 150 ms run); changes reported []; sinks all dropped: true
KeyWatcher over IOKit: first look Ok(Ok((0, 0))); drop joined in 91.437083ms; channel closed: true
Process 26605: 1419 nodes malloced for 152 KB
Process 26605: 0 leaks for 0 total leaked bytes.
```

- The watch test (`tests/watch.rs`, `--test-threads=1`) under `leaks --atExit` gave `1136 nodes malloced for 124 KB`, `0 leaks for 0 total leaked bytes`.
- Afterwards no driver or test process was left.
- So the watch thread stops, its sink drops (the channel closes), nothing leaks, and the devices present at the start are not reported as plug-ins.
- Code read of `src/watch.rs`:
  - queued requests are taken before the next look, so any number of requests during a look give one more look;
  - a plug-in sets the look 0.5 s ahead, and a later plug-in moves it on;
  - `Change::Removed` does nothing;
  - drop sends Stop and joins.

## Failures

**F1 (first pass) resolved by LD-190.**
- The first pass found no device plug-in or removal events: INT-07.14 and INT-07.30, T23.
- LD-190 built them in this story:
  - `Bus::watch` and `Change::{Arrived, Removed}`;
  - `KeyWatcher` (`src/watch.rs`): a look at start, a look 0.5 s after the last plug-in, folding of requests, joined on drop;
  - the IOKit callbacks in `src/usb/watch.rs`;
  - plug-in and pull-out in the simulated device;
  - tests for T22, T23 and T24, and the IOKit watch smoke test.
- Re-checked in section 8. No failure is left.

## Open (needs a real key, OD-01)

T53; V-INT07-1 to V-INT07-5; LD-188 condition 5 (how long one `GetReport` or `SetReport` call blocks when the key is pulled mid-call); T12 on a real device; interop rows B10 to B12.

## Open points (do not block)

- **O1 and O2 of the first pass are closed.** The crate now has its own lock test (`t22_challenge_waits_for_a_running_detection`). T06 and T44 say "no HMAC frame sent".
- **O3. Plug-in on real hardware needs a real key.** The plug-in itself, the address filter for keys present at the start, and a replugged key were seen only through the simulated device and the IOKit watch without a key. Add it to the real-key run of T53.
- **O4. The panicking-sink note** (unsafe review note (b)): today's sinks only send on a channel. A future sink that can panic would unwind through CFRunLoop frames in debug builds.

## CPU

| Step | CPU (user) | Wall clock |
|---|---|---|
| Test build and run | 80 s | 12 s |
| Driver build | 307 s | 34 s |
| Release build | 97 s | 41 s |
| Release binary | 23 s | 9 s |
| Driver runs (each) | under 3 s | |
| Re-check: test build and run | 82 s | 15 s |
| Re-check: driver build | 303 s | 51 s |
| Re-check: release binary | 32 s | 14 s |
| Re-check: driver runs and `leaks` (each) | under 6 s | |

In all about 16 CPU minutes. No single run over 30 minutes.

While another story was editing it, larsal-format did not build for about one minute (07:41). The re-check waited for it with one build retry, then ran on the settled sources. No product file was touched.

## Clean-up

- `/tmp/v-e10s1-target` deleted.
- The only background process I started was one build-retry loop (re-check). It ended by itself once the build passed. The reference CLI, the driver and `leaks` ran in the foreground.
- `ps -axo pid,ppid,stat,command | grep -E "v-e10s1-driver|watch-c33" | grep -v grep` printed nothing.
- `/tmp/v-e10s1/` (driver, python, demo files, the vault copy) is kept.
