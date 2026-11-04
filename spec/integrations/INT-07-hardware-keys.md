# INT-07 Hardware keys

Status: reviewed (LD-173, LD-175)
Epics: E10-S1 (detection, slots, challenge-response, the test double); used again by E3-S3's key flow (FMT-04), E5-S3 (unlock screen, APP-06), E5-S8 (new vault wizard, APP-07), the vault settings credential page (MOD-12.10) and E12 (command line, INT-10)
Parity rows: SI-08, SF-04, SR-12, SR-04, SR-07; attacks AT-A01, AT-H03, AT-H04

## What it does

A vault can need a hardware key as one part of its composite key, next to or instead of a password and a key file. App asks the key a question that depends on the vault file and mixes the 20-byte answer into the composite key. Without the right key, with the right secret in the right slot, the vault does not open.

The mode is HMAC-SHA1 challenge-response, the mode the reference uses and the one YubiKey-compatible devices offer in their two configuration slots. App sends a 64-byte challenge built from the vault's seed (FMT-04.8, FMT-04.9); the device returns HMAC-SHA1 of it under a 20-byte secret that never leaves the device. Every save makes a new seed, so every save asks the key again.

This card covers the device side: which devices, how App finds them and their slots over USB on macOS, how a challenge runs, touch, timeouts, what happens when the key is missing, the device messages, the command line forms, and the software-only test double the owner chose (spec/decisions.md OD-01). In the screens the term is "security key" (LD-101); in cards and code it is "hardware key".

Who owns what: the key math (challenge, padding, `R`, where `R` goes in version 3 and 4) is FMT-04; the order of steps in an open is FMT-05.7; the unlock screen's security key row, its messages M06-17 to M06-20, M06-33, M06-35 and M06-36 are APP-06; the wizard's key part is APP-07.15; the credential page is MOD-12.10; quick unlock with a hardware key is APP-04.12; remembering the key per vault is APP-01.16 (S-START-08, S-STATE-03); the command line flag names are INT-10.

Public facts a Builder needs: HMAC-SHA1 (RFC 2104, FIPS 180-4); USB HID feature reports (USB Device Class Definition for HID 1.11, GET_REPORT and SET_REPORT); the frame protocol facts of INT-07.9 to INT-07.12, written here so no other source is needed.

## Inputs and outputs

| Input or output | Type | Notes |
|---|---|---|
| Challenge | exactly 64 bytes | Built by FMT-04.8 and FMT-04.9 from the 32-byte seed |
| Answer | exactly 20 bytes, secret | Becomes `R = SHA256(answer)` (FMT-04.6) |
| Key choice | serial (unsigned 32-bit, 0 = any key) and slot (1 or 2) | Not secret. Remembered as `serial:slot` in S-STATE-03 while S-START-08 is on (APP-01.16) |
| Detection result | list of items, each: model, serial or "unknown", slot, needs touch (yes or no) | Shown in the form "<model> · serial <serial> · slot <n>" (LD-101) |
| Events | "touch needed", "touch ended", "device arrived" | For the screens and the command line |
| Failure | one `HardwareKeyReason` of `app-format/error.rs` | `Missing`, `TimedOut`, `SlotNotConfigured`, `BadAnswer`, `Failed`, and `NotPermitted` (D-INT07-3, decided: spec/decisions.md LD-173) |

Limits: at most 8 devices listed at once (the reference: 4); a write step waits at most 1,150 ms; a reply must start within 1,000 ms unless the device says it waits for a touch; a touch wait ends after at most 20 seconds (D-INT07-4).

## Rules

### Mode and key flow

INT-07.1 **The mode.** App uses only HMAC-SHA1 challenge-response in slot 1 or slot 2. It does not use the device's one-time password output, FIDO2 or its `hmac-secret` extension, PIV, OpenPGP, passkeys, or the Yubico OTP challenge mode. A slot set up for anything else is not a usable slot (INT-07.15).

INT-07.2 **One challenge, one answer.** Each key derivation that involves the hardware key sends one 64-byte challenge (FMT-04.8, FMT-04.9) and expects exactly 20 bytes back (FMT-04.10). The answer becomes `R` (FMT-04.6). A challenge runs at: each unlock (FMT-05.7 step 4b; also a Touch ID quick unlock, APP-04.12), each save (FMT-04.17), creating a vault (APP-07), and the first save after the credentials change (MOD-12.10). Detection's test challenge (INT-07.15) never gives an answer that is used.

INT-07.3 **Slot programming modes.** A slot is programmed either to hash all 64 bytes it receives (fixed) or to drop the trailing bytes that equal the last byte before hashing (variable). App always sends the same 64 bytes and never needs to know the mode (FMT-04 Edge cases). A vault made with a slot in one mode opens only while the slot keeps that mode; reprogramming the slot, even with the same secret in the other mode, is a wrong key.

INT-07.4 **One key per vault, backup keys allowed.** A vault uses at most one hardware key (FMT-04.6; the reference's screens and command line also allow one). Several physical keys whose chosen slots hold the same secret in the same mode give the same answer, so each of them opens the vault alone. That is how users keep a backup key (Yubico's `ykman otp chalresp` takes the secret as hex, so the same secret can be written to a second key). App cannot tell such keys apart by their answer and does not try.

INT-07.5 **Which key is asked.** A key choice is a serial number and a slot. Serial 0 means "the first usable device found" (INT-07.15 order); the reference's command line uses 0 when no serial is given. With a serial, only the device with that serial is asked; when it is not connected the result is `Missing`, even if another device is plugged in (reference). So a backup key with another serial works when the user picks it in the list, or with serial 0.

### Devices and USB on macOS

INT-07.6 **Devices App talks to.** USB devices with these vendor and product ids, the ones whose keyboard (OTP) function speaks the frame protocol of INT-07.9:

| Vendor | Product ids | Model name App shows |
|---|---|---|
| `1050` (Yubico) | `0010` | YubiKey ‹major firmware version› |
| `1050` | `0110`, `0111`, `0114`, `0116` | YubiKey NEO |
| `1050` | `0401`, `0403`, `0405`, `0407` | YubiKey ‹major firmware version› (4 or 5) |
| `1050` | `0410` | YubiKey Plus |
| `1D50` | `60FC` | OnlyKey |

The other Yubico product ids (`0112`, `0113`, `0115`, `0402`, `0404`, `0406`) have no OTP function and are skipped. The major firmware version comes from the status report (INT-07.11). The model name has no form factor (D-INT07-5). Reference difference: its names also list the enabled functions (OTP, FIDO, CCID) and add the firmware major to OnlyKey.

INT-07.7 **Which interface.** A device shows up as one or more HID interfaces. App opens, in this order: the FIDO interface (primary usage page `F1D0`, usage `01`), else the keyboard interface (primary usage page `01`, usage `06`). Reason (from the reference's macOS driver, and macOS policy): macOS asks the user before an app may open a keyboard, but not a FIDO device. A key with its FIDO function turned off can only be reached through its keyboard interface; when macOS refuses that open, the reason is `NotPermitted` (D-INT07-3, LD-173) with MI07-01. Check with Verify on a real device which permission macOS asks for (Input Monitoring is expected).

INT-07.8 **Access.** App uses the IOKit HID manager: it lists matching devices, opens the chosen interface without seizing it (other apps keep working), exchanges 8-byte feature reports with report id 0, and closes the device after each operation. No driver, no helper and no entitlement is needed for an app outside the App Sandbox (E5-S1: App is not sandboxed); a sandboxed build would need the USB device entitlement. The code that calls IOKit lives in `app-hwkey/usb/`, the only place where this crate may hold `unsafe` (architecture, Rust rule 2).

INT-07.9 **Writing a frame.** Every command is one 70-byte frame: 64 bytes of payload (the challenge, always 64 bytes after the padding of FMT-04.9; the serial command's empty payload is 64 zero bytes), 1 command byte, 2 bytes of CRC, 3 zero bytes. The CRC is computed over the 64 payload bytes only: start `FFFF`; for each byte, XOR it into the low byte, then 8 times: shift right by one and, if the bit shifted out was 1, XOR with `8408`. It is stored low byte first. Commands: `30` HMAC-SHA1 with slot 1, `38` HMAC-SHA1 with slot 2, `10` read the serial number (empty payload). The frame goes out in 10 feature reports of 8 bytes: bytes 0 to 6 hold the next 7 frame bytes, byte 7 holds `80` plus the part number 0 to 9. A part whose 7 bytes are all zero is skipped, except the first and the last. Before each report App reads reports until the device has cleared bit `80` of byte 7 (it is still busy while the bit is set), for at most 1,150 ms; else `Failed`.

INT-07.10 **Reading a reply.** After the last part App reads feature reports and looks at byte 7:
- `40` set (reply pending): the report carries 7 reply bytes in bytes 0 to 6; byte 7's low 5 bits count the reports from 0. App keeps reading while `40` is set; when a report arrives whose low 5 bits are 0 again after the first, the reply is complete.
- `20` set (waiting for a touch): the device blinks and waits; byte 7's low 5 bits give the seconds it will still wait. App raises "touch needed" (INT-07.19) and keeps reading until `40` appears or the touch wait ends (INT-07.12).
- Neither within 1,000 ms after the frame: `SlotNotConfigured` for an HMAC command (the slot does not do challenge-response; check with Verify on a real device, V-INT07-3), `Failed` for the serial command.
- An HMAC reply is 20 bytes plus 2 CRC bytes, received as 28 bytes (4 reports); a serial reply is 4 bytes plus 2 CRC bytes (one report). The device stores the ones' complement of the CRC of INT-07.9 over the reply bytes, low byte first, so the CRC of INT-07.9 over the reply bytes and their 2 CRC bytes must give `F0B8`; else `BadAnswer`. The simulated device of INT-07.30 builds its replies the same way. More or fewer reports than expected: `BadAnswer`.
- When it is done, or when it gives up, App writes one reset report (7 zero bytes, then `8F`) so the device leaves reply mode.

INT-07.11 **Status and serial.** A plain feature report read gives the status in bytes 1 to 6: firmware major, minor and build version, programming sequence number, and a 16-bit "touch level" word stored low byte first whose bit `01` means slot 1 is configured and bit `02` means slot 2 is configured (from firmware 2.1). The serial number is the 4 reply bytes of command `10` in big-endian order. A device whose serial cannot be read gives serial 0 (INT-07.16, D-INT07-6).

INT-07.12 **Timing.** One write step: at most 1,150 ms. Start of a reply: at most 1,000 ms. While the device reports a touch wait, App waits as long as the device does, up to 20 seconds in all (D-INT07-4); the device's own default is 15 seconds. When the device stops waiting without a reply, or the 20 seconds pass, the result is `TimedOut`. Reads are polled with a growing pause, 1 ms doubling up to 500 ms (the reference's driver does the same).

INT-07.13 **One device operation at a time.** Detection and challenges never run at the same time, in App or in the command line tool (a process-wide lock, as the reference). A challenge that arrives during a detection waits for it. A second detection request during a detection runs once more after it (the reference drops it). Everything runs off the main thread; the screens get events.

### Detection

INT-07.14 **When App looks.** When the unlock view appears; 0.5 s after a device with a vendor id of INT-07.6 is plugged in while the unlock view, the wizard's key part or the credential page shows (IOKit device-matching callback); and when the user presses "Look for keys again" (APP-06.8, APP-07.15, MOD-12.10). Removing a device does not start a look (reference); a challenge to a removed device fails with `Missing` (INT-07.20).

INT-07.15 **What App does for each device**, in the order IOKit lists them, at most 8:
1. Read the status (INT-07.11) and the serial.
2. For slot 1, then slot 2: skip the slot when its "configured" bit is clear.
3. A YubiKey NEO or older (product id `0116` or lower): list the slot without a test, because these devices always wait for a touch on such a test (reference). Needs touch: unknown, shown as no.
4. Any other device: send a test challenge of 1 random byte to the slot, padded to 64 bytes by the rule of FMT-04.9 (63 bytes of `3F`, as the reference does), without waiting for a touch. A reply: the slot is listed, needs touch no. A touch wait (bit `20`): the slot is listed, needs touch yes; App writes the reset report at once, so no touch is ever asked during detection. Anything else (the slot holds a one-time password configuration, or fails): the slot is not listed.
5. A device counts as "found" even when no slot is listed (for the M06-36 text "keys without a usable slot").

INT-07.16 **List items.** One item per listed slot, in the form "<model> · serial <serial> · slot <n>" (LD-101), for example "YubiKey 5 · serial 24531878 · slot 2". A serial of 0 shows as "serial unknown". Items are sorted by serial, then slot. The "needs touch" fact is not shown in the item (LD-101 form); App uses it only to show M06-35 at once when the challenge starts. Reference difference: it names the touch need ("Press" or "Passive") in each item.

INT-07.17 **What the screens get.** The list, the number of devices found, and whether any device was found without a usable slot. APP-06.8 and M06-36 decide what the unlock screen shows; the wizard and the credential page show the same list and texts (APP-07.15, MOD-12.10).

### Challenge

INT-07.18 **Running a challenge.** App finds the chosen device (INT-07.5), opens it (INT-07.7), sends the frame with command `30` or `38` and the 64-byte challenge, reads the reply, checks it, closes the device, and returns the 20 bytes. The steps of FMT-04.10 and FMT-04.21 decide when this happens relative to the KDF: App asks after the cost check and before the KDF, so the user never touches the key for a file that is then refused.

INT-07.19 **Touch.** "Touch needed" goes to the caller within 200 ms after the device reports its touch wait, or at once when detection said the slot needs touch. The unlock screen shows M06-35 (APP-06.15); a save or create shows M06-35 in its progress line; the command line prints INT-10's M10-18 to standard error once. "Touch ended" follows when the challenge ends in any way, and the text goes away. App never shows a touch request before it knows the device is there. Reference difference: its command line prints the touch request before it looks for the device, so it shows even with no key plugged in (observed with the installed command line tool 2.7.11).

INT-07.20 **Failures and their reasons.**

| What happened | Reason | Message |
|---|---|---|
| No device of INT-07.6 connected; the device with the chosen serial not connected; the device removed during the challenge | `Missing` | M06-17 |
| The touch wait ended without a touch (INT-07.12) | `TimedOut` | M06-18 |
| The chosen slot's "configured" bit is clear, or the device answers the HMAC command with no reply at all within 1,000 ms (an OTP slot) | `SlotNotConfigured` | M06-19 |
| The reply's CRC fails, or it is not 20 bytes | `BadAnswer` | M06-20 |
| macOS refuses to open the keyboard interface (INT-07.7) | `NotPermitted` (D-INT07-3, LD-173) | MI07-01 |
| Any other IOKit or USB error, a write step that never finishes | `Failed` | M06-20 |

A device that answers but holds another secret gives a normal 20-byte answer; that is a wrong key, found by the header check like a wrong password (FMT-04.10, AT-H04), never a hardware key error. A reason never carries key material; it may carry the IOKit error number for the debug log.

INT-07.21 **Key removed during use.** During an unlock: `Missing`, nothing is decrypted. During a save: the save stops before anything is written and the file on disk stays byte-for-byte as it was (FMT-04.17, AT-H03); the vault stays open and changed, and the user can plug the key in and save again (APP-05). During detection: the device is simply not listed.

INT-07.22 **Secrets.** The 20-byte answer goes straight into App's secret type in Rust, is turned into `R` and wiped (FMT-04.19, SR-07). The challenge is not secret (it is in the file header). Serial numbers, slots and model names are not secret and may appear in the screens and the debug log. No secret crosses to the Swift layer (AGENTS rule 4). The random byte of the test challenge comes from `app-crypto::random`.

INT-07.23 **Remembered key.** After each unlock attempt with a hardware key, the vault's entry in S-STATE-03 becomes `serial:slot` of the chosen item, written only while S-START-08 is on (APP-01.16; LD-51: off by default). The unlock screen preselects it when it is in the list (APP-06.8). Quick unlock keeps only which device and slot to ask, never an answer (APP-04.4).

### Creating, changing and removing a vault's key

INT-07.24 **Adding a key.** In the wizard (APP-07.15) and on the credential page (MOD-12.10 step 6) the user picks an item from the detection list. The key must still be connected when the user confirms (else M06-17). No extra test challenge runs: the first real challenge is at the write, with the new seed, so the user touches the key once (APP-07.15). If that challenge fails, nothing is written (APP-07, APP-05) and the credentials stay as they were.

INT-07.25 **Changing or removing the key.** Change: pick another item; the next save uses it. Remove: the next save writes the vault without `R` (FMT-04.18), so after that save the old key is no longer needed. Either change takes effect only with that save; until then the file on disk still needs the old key. MOD-12.10 step 9 warns that older backup copies still need the old credentials.

INT-07.26 **Key missing later.** Unlock: M06-17 with focus on the list or "Look for keys again" (APP-06.17). Save (also auto-save and save on lock): the save fails with the reason in `MSG-SAVE-FAILED` (APP-06.30), the file stays as it was (INT-07.21); a lock that needs a save follows APP-02 and LD-50. Lock without a save needs no key. Opening the vault on a Mac without the key is impossible by design; App says nothing more than M06-17 (and, when the user did not turn the row on, the wrong-key message, AT-A01).

### Command line

INT-07.27 **Command line forms.** INT-10 owns the flag (`--hw-key`, U03, INT-10.14) and its messages. Its value is `SLOT` or `SLOT:SERIAL`: the slot is `1` or `2`; the serial is a decimal number from 0 to 4,294,967,295 (0 = any key, INT-07.5). Anything else is INT-10's M10-02, exit code 1, before any password prompt or file read (reference difference: the reference prompts for the password first). The command line looks for devices once (no events), prints INT-10's M10-18 when touch is needed (INT-07.19), and maps every reason to the APP-06 text on standard error with exit code 1 (M06-17 also when the device with the given serial is not plugged in).

### Not in App

INT-07.28 **Out of scope.** App does not talk to smart card readers or NFC (PC/SC), so a key held to an NFC reader is not found (D-INT07-2; the reference does both on macOS). App does not combine several hardware keys in one vault (INT-07.4). App does not program slots or create secrets; users do that with Yubico's tools.

### Testing without hardware (OD-01)

INT-07.29 **Layer 1: software key.** `app-format`'s software challenge-response key (a 20-byte secret and a slot mode, variable or fixed) answers exactly like a programmed slot (FMT-04.6-a, FMT-04.6-d, FMT-04.15-b, FMT-04.15-c, FMT-04.6-e). It stands in for the device wherever the key math is tested. It is compiled only into tests; the release build never offers it.

INT-07.30 **Layer 2: simulated device.** A test transport behind the same interface as the IOKit code (read one feature report, write one feature report, list devices, device arrived and removed events). It emulates a device by INT-07.9 to INT-07.12: vendor and product id, firmware version, serial (or a hidden serial), each slot as one of empty, HMAC-SHA1 variable, HMAC-SHA1 fixed, or one-time password, a 20-byte secret per slot, touch required per slot, and a script: touch after N ms of a fake clock, or never (then it stops waiting after its own 15 s); remove the device after report k; flip a CRC byte; send a short reply; stay busy (bit `80`) forever. `app-hwkey`'s protocol code runs against it unchanged. It is compiled only into tests.

INT-07.31 **Layer 3: fake driver.** For the screens (APP-06, APP-07, MOD-12) a fake of the whole driver returns scripted detection lists, touch events and results (APP-06's "fake hardware key driver").

INT-07.32 **Proof against the reference without hardware.** A 20-byte key file is the hashed key file kind (FMT-18), so its key file part equals `SHA256(answer)`, which is exactly `R`. So the reference opens any App vault made with a hardware key when it is given the password and a 20-byte key file holding the answer App's software key gives for the file's current seed (FMT-04 Edge cases; Verify observed this in Sprint 2 with the reference's own hardware-key test vault). The other direction uses the reference's hardware-key test vault (FMT-01 Vector HK) with App's software key in variable mode.

INT-07.33 **Real device later.** A check with a real key (detection, touch, removal during a save, interop rows B10 to B12) waits for the owner (OD-01). Until then the facts of INT-07.7 to INT-07.12 are from the reference's driver and are marked "check with Verify on a real device".

### Messages

App's own wording. The unlock screen's texts are APP-06's (M06-17 to M06-20, M06-33, M06-35, M06-36); the command line texts are INT-10's (M10-02, M10-18); this card adds:

| ID | Where | Rule | App text |
|---|---|---|---|
| MI07-01 | line, unlock and the key parts | INT-07.7, INT-07.20 | macOS did not let App reach your security key. Allow App under System Settings › Privacy & Security › Input Monitoring, then try again. |
| MI07-02 | save progress line and `MSG-SAVE-FAILED` reasons | INT-07.19, INT-07.26 | Uses M06-35 while waiting; the reasons in `MSG-SAVE-FAILED` are APP-06.30's ("the security key is not connected", "the security key was not touched in time", "the security key slot is not set up for challenge-response", "App could not use the security key"), plus, for `NotPermitted`, "macOS did not let App reach the security key" (finding R07-2) |

## Edge cases and errors

- **Vault needs a key, the user did not turn the row on:** the composite key lacks `R`: wrong key, M06-06 (APP-06, AT-A01). App cannot know a vault needs a hardware key; nothing in the file says so.
- **Two keys plugged in, both with a usable slot 2:** two items; the user picks one; with a remembered `serial:slot` that one is preselected (APP-06.8).
- **Backup key with another serial while the remembered serial is absent:** the backup's item shows; the remembered one does not; the switch stays off until the user picks (APP-06.8, T65 there).
- **Slot needs touch and the user touches late:** the device gives up after its own wait (15 s by default); `TimedOut`, M06-18; the next attempt asks again.
- **User touches during detection:** nothing happens; detection never waits for a touch (INT-07.15).
- **Device also used by another app at the same moment** (Yubico Authenticator, a browser using FIDO): feature report exchanges may collide; the result is `Failed` or `BadAnswer` and a retry works. Check with Verify on a real device.
- **Key plugged in during an unlock that is already waiting for a touch:** no effect; the running challenge is for the device found at its start.
- **Slot reprogrammed after the vault was made:** wrong key (INT-07.3).
- **Firmware older than 2.2:** cannot do HMAC-SHA1 challenge-response; its slots fail the test and are not listed.
- **OnlyKey:** listed when it answers the test; its serial may be 0 (check with Verify; untested, as the `challenge_response` crate also marks it).
- **Hostile device** (a USB device claiming Yubico's ids): it can only return wrong answers (wrong key), malformed replies (`BadAnswer`), or hang (bounded by INT-07.12). App never trusts its model name beyond display.
- **Not on Mac.** The reference on Linux uses libusb or hidraw and a udev rule; on Windows the HID API; on all systems also PC/SC readers, including NFC, with their own application ids and display names from the card's answer-to-reset bytes.

## Lead decisions

Decided: spec/decisions.md LD-173, all seven as recommended (D-INT07-1 with `objc2-io-kit`, reviewed under AT-J03 at the story).

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT07-1 | How App reaches the device over USB | (a) App's own code over the IOKit HID manager in `app-hwkey/usb/`, from the facts of INT-07.7 to INT-07.12, with bindings from `objc2-io-kit` and `objc2-core-foundation` (same family and licenses as the approved `objc2` crates; AT-J03 review) or a few hand-written declarations; (b) the `challenge_response` crate (MIT or Apache-2.0) | (a). The reference and Yubico's own macOS code reach the device through the HID manager and prefer the FIDO interface to avoid the keyboard permission (INT-07.7). `challenge_response` (0.5.46) uses `rusb` by default, which links the C library libusb (LGPL-2.1, outside the `deny.toml` allowlist), and its pure-Rust `nusb` backend is marked experimental and talks raw USB, not the HID manager. The protocol is small (one frame type, one reply type). The architecture already plans `unsafe` only in `app-hwkey/usb/`. The facts in this card suffice; Builders do not need any vendor source |
| D-INT07-2 | Smart card readers and NFC (PC/SC) | leave out; or build as the reference | Leave out for now: on a Mac the USB path covers every YubiKey with its OTP function on; NFC needs a separate reader. Add as a later story if users ask |
| D-INT07-3 | New reason `NotPermitted` (INT-07.7, INT-07.20) | add it to `HardwareKeyReason` with MI07-01; or report `Failed` | Add it: `Failed` tells the user to replug, which does not help when macOS blocks the keyboard interface; MI07-01 names the fix |
| D-INT07-4 | Longest touch wait (INT-07.12) | 20 s; or follow the device without an App limit (the reference adds up to 256 s once the device waits) | 20 s: the device's own default is 15 s, so 20 s never cuts a real wait short and bounds a hostile device |
| D-INT07-5 | Model name (INT-07.6) | "YubiKey ‹major›"; or read the form factor ("YubiKey 5 NFC", as the mockup's sample) through another device interface | "YubiKey ‹major›": the form factor needs a second protocol for no gain in safety; the mockup's sample stays a known difference (AT-K05, owner approval) |
| D-INT07-6 | Devices whose serial cannot be read (INT-07.11, INT-07.16) | list them as "serial unknown" with serial 0 (= any key); or skip them as the reference's window app does | List them: the reference's command line already treats 0 as any key, and skipping makes such a key unusable in the window |
| D-INT07-7 | Several hardware keys combined in one vault (FMT-04.6 allows the math) | no; or yes | No: parity with the reference's screens and command line; backup keys (INT-07.4) cover the real need |

Check with Verify (needs a real device, OD-01): V-INT07-1 the FIDO interface accepts the frame protocol on YubiKey 4 and 5 (INT-07.7); V-INT07-2 the permission macOS asks for the keyboard interface; V-INT07-3 the reply report numbering of INT-07.10 on a real device; V-INT07-4 the touch wait seconds in byte 7; V-INT07-5 an OnlyKey's serial and test answer.

## Security notes

- **SI-08, SF-04:** a hardware key is one part of the composite key, alone or with a password and a key file (FMT-04). A wrong key, another key with another secret, or a reprogrammed slot gives exactly the wrong-key result of a wrong password (AT-A01, AT-H04). A missing or failing key gives a hardware key reason, never `WrongKey`, and stops before the KDF (FMT-04.10, AT-H03).
- **SR-07 and AGENTS rule 4:** the answer and `R` exist only in Rust secret types and are wiped at once (INT-07.22).
- **SR-12:** the remembered `serial:slot` reveals which key opens which vault; it is written only while S-START-08 is on (off by default, LD-51).
- **SR-04:** quick unlock never stores an answer; the key is asked again (APP-04.12).
- **Every save asks the key** (FMT-04.17); a vault never silently loses its hardware-key part (FMT-04.18).
- **The secret never leaves the device** (Yubico: "Secrets cannot be extracted from the YubiKey once configured"). A copy of the vault file is useless without the key or another key with the same secret. A backup key with the same secret is exactly as strong a factor.
- **USB access and macOS permissions:** App opens only the interfaces of INT-07.6 devices, exchanges only feature reports, and never reads input reports, so the keystrokes a key types in its one-time password mode never reach App. App never asks for Input Monitoring on its own; it names that setting only in MI07-01, after macOS refused the keyboard interface.
- **What must never happen:** a touch request shown for a device that is not there; a detection that waits for a touch; a save that writes a file after a failed challenge; an answer in a log or error; a hang on a misbehaving device (INT-07.12); an exclusive grab that stops the user's other key apps.
- **Proven standard (AGENTS rule 9):** HMAC-SHA1 challenge-response in slot 1 or 2 is what the reference uses, what Strongbox supports for the same vault format (its issue 95: challenge-response supported over USB-C, NFC and Lightning), and what Yubico's own tool programs (`ykman otp chalresp`: "Program a challenge-response credential to a YubiKey slot 1 or 2", option "Require touch on the YubiKey to generate a response"). Slot 2 is the usual choice because slot 1 holds the factory one-time password configuration. Password managers with a server account, such as Bitwarden, use FIDO2 security keys for sign-in, not to encrypt a local vault, so they are no model here.

## Test cases

Demo secret D: the 20 ASCII bytes `App demo HMAC secret` = `4170702064656d6f20484d414320736563726574` (FMT-04). Simulated device Y5: Yubico `1050:0407`, firmware 5.4.3, serial 24531878 (`017653a6`), slot 1 one-time password, slot 2 HMAC-SHA1 variable with D, touch off. Variants: Y5t (slot 2 touch on), Y5f (slot 2 fixed mode), Y5h (serial hidden), NEO (`1050:0116`, firmware 3.4, slot 2 HMAC with D), OK (`1D50:60FC`). Demo vault H (`hk-demo.appvault`, password `demo-pass`, slot 2 of Y5, made by App with the software key of D in variable mode). Seed `KS` of FMT-04.6-a where a test needs fixed bytes. All on the fake clock.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-07.2 | H; Y5 | Unlock with `demo-pass` and Y5 slot 2 | Exactly one HMAC frame sent; H opens |
| T02 INT-07.2 | H open; Y5 | Save twice | Two HMAC frames, each with the seed of the file being written (different each time) |
| T03 INT-07.3 | `KS` of FMT-04.6-a; Y5 and Y5f | Challenge each | Y5: `5744a1267b30e12442156bbd9d54715541765d89`; Y5f: `c66e7366f1946a047868cb828a4ed86cbfd02464` (FMT-04.6-a, FMT-04.6-d) |
| T04 INT-07.3 | H made with Y5 (variable) | Unlock with Y5f (same secret, fixed) | Wrong-key result M06-06, not a hardware key error |
| T05 INT-07.4 | H; a second simulated device, serial 1000, slot 2 = D variable | Unlock choosing serial 1000 slot 2 | H opens |
| T06 INT-07.5 | H; only the serial-1000 device plugged in; choice `24531878:2` | Unlock | `Missing`, M06-17; no HMAC frame sent to the serial-1000 device |
| T07 INT-07.5 | Same; choice `0:2` | Unlock | H opens with the serial-1000 device |
| T08 INT-07.6 | Simulated devices `1050:0402` (no OTP), `1050:0407`, `1234:5678` | Look for keys | Only the `0407` device is asked; one item |
| T09 INT-07.6 | Y5, NEO, OK, a `1050:0010` device with firmware 2.4 | Look | Model names "YubiKey 5", "YubiKey NEO", "OnlyKey", "YubiKey 2" |
| T10 INT-07.7 | Y5 with both a FIDO and a keyboard interface | Challenge | The FIDO interface is opened; the keyboard interface never |
| T11 INT-07.7 | Y5 with only a keyboard interface, whose open returns "not permitted" | Unlock | `NotPermitted`, MI07-01 |
| T12 INT-07.8 | Y5 | Challenge, while a second test client holds the same device open | Both opens succeed (no seize); App closes its handle after the challenge |
| T13 INT-07.9 | `KS` of FMT-04.6-a, slot 2 | Record the reports App writes | CRC `ED74` stored as `74 ED`; 10 reports with byte 7 = `80` to `89`; bytes 0 to 6: `3481483a67fb36`, `5da911c5095420`, `ce2bfd2161793b`, `47d7a6561cedf9`, `21899e63202020`, then `20202020202020` four times, then `203874ed000000` |
| T14 INT-07.9 | The serial command `10` (empty payload); a 1-byte test challenge `5a` to slot 1 | Record the reports App writes | Serial: CRC `5B6B`; parts 1 to 8 are all zero and skipped; reports sent: `00000000000000`+`80` and `00106b5b000000`+`89`. Test challenge: payload `5a` and 63 bytes `3f`, CRC `0A36`; all 10 reports sent: `5a3f3f3f3f3f3f`+`80`, `3f3f3f3f3f3f3f`+`81` to `88`, `3f30360a000000`+`89` |
| T15 INT-07.9 | Y5 that keeps bit `80` set | Challenge | `Failed` after 1,150 ms of the fake clock |
| T16 INT-07.10 | Y5 answering T13 | Read | Reply reports `5744a1267b30e1`+`40`, `2442156bbd9d54`+`41`, `715541765d8939`+`42`, `39000000000000`+`43`, then a report with `40` and count 0; the 22 reply bytes check to `F0B8`; answer as T03; one reset report `00000000000000`+`8F` written |
| T17 INT-07.10 | Y5 with one CRC byte flipped; Y5 sending only 3 reply reports | Challenge | `BadAnswer`, M06-20, both |
| T18 INT-07.11 | Y5 | Read status and serial | Major 5, minor 4, build 3; slot 1 and slot 2 configured bits set; serial reply `017653a6` + `c78f`, serial 24531878 |
| T19 INT-07.12 | Y5t, the touch comes after 3 s | Unlock H | "Touch needed" within 200 ms of the first report with bit `20`; M06-35 shows; H opens after the touch; M06-35 gone |
| T20 INT-07.12 | Y5t, never touched | Unlock H | The device stops waiting after its 15 s; `TimedOut`, M06-18 |
| T21 INT-07.12 | A device that reports bit `20` forever | Unlock H | `TimedOut` after 20 s of the fake clock (D-INT07-4) |
| T22 INT-07.13 | Detection running on a slow simulated device | Start an unlock challenge; press "Look for keys again" twice | The challenge waits for the detection; one more detection runs after it, not two |
| T23 INT-07.14 | Unlock view shown, no device | Plug in Y5 (simulated arrival event) | A look starts 0.5 s later; Y5 slot 2 listed |
| T24 INT-07.14 | Unlock view shown, Y5 listed | Remove Y5 | No new look; the list keeps the item until the next look |
| T25 INT-07.15 | Y5 (slot 1 OTP, slot 2 HMAC) | Look | One item, slot 2; slot 1 got a test challenge and failed; no touch asked |
| T26 INT-07.15 | Y5t | Look | Slot 2 listed with needs touch yes; the reset report was written right after the first report with bit `20`; no "touch needed" event |
| T27 INT-07.15 | NEO with slot 2 touch on | Look | Slot 2 listed without a test challenge |
| T28 INT-07.15 | A device whose two slots are both one-time password slots | Look | Device found, no item; M06-36 "No slot on the plugged-in security key is set up for challenge-response." |
| T29 INT-07.16 | Y5h | Look | Item "YubiKey 5 · serial unknown · slot 2"; choosing it stores `0:2` in S-STATE-03 (S-START-08 on) |
| T30 INT-07.16 | Y5 and the serial-1000 device | Look | Items sorted: serial 1000 first, then 24531878 |
| T31 INT-07.19 | Command line, Y5t touched after 2 s | Open H with `--hw-key 2` | M10-18 printed once to standard error, after the device was found; the vault opens |
| T32 INT-07.19 | Command line, no device | Open H with `--hw-key 2` | No touch text; M06-17's text on standard error; exit 1 |
| T33 INT-07.20 | Y5 whose slot 2 configured bit is clear | Unlock H with slot 2 | `SlotNotConfigured`, M06-19 |
| T34 INT-07.20 | A device with D' (another secret) in slot 2 | Unlock H | Wrong-key result, the same message as a wrong password (AT-H04) |
| T35 INT-07.21 | H open, changed; Y5 removed after the 3rd write report of the save's challenge | Save | `Missing`; the file's bytes and modification time unchanged (AT-H03); the vault still open and marked changed |
| T36 INT-07.21 | H open; Y5 removed | Plug Y5 back in, save | Saved; opens again with Y5 |
| T37 INT-07.22 | Debug build with the wipe hook; Y5 | Unlock H, then scan the process memory for the answer `5744a126...5d89` and for `R` `42a98ddc...d0ec` | Not found after the open finished (AT-C01 method) |
| T38 INT-07.23 | S-START-08 on | Unlock H with Y5 slot 2 | S-STATE-03 has `24531878:2` for H's path; with S-START-08 off: nothing written |
| T39 INT-07.24 | Wizard step 3 with Y5 slot 2 chosen; Y5 removed before Create Vault | Create Vault | M06-17; nothing written |
| T40 INT-07.24 | Wizard with Y5t chosen | Create Vault, touch after 1 s | One challenge only (no test challenge); M06-35 during it; the vault written and opened |
| T41 INT-07.25 | H; credential page, Remove the security key | Save; open H with the reference command line tool and `demo-pass` only | Opens (no hardware key part any more) |
| T42 INT-07.26 | H open, auto-save on, Y5 removed | Edit an entry | Auto-save fails with "the security key is not connected" in `MSG-SAVE-FAILED`; the file unchanged |
| T43 INT-07.27 | `--hw-key` values `3`, `2:abc`, `2:4294967296`, `0`, `2:` | Run | M10-02, exit 1, before the password prompt, each |
| T44 INT-07.27 | `--hw-key 2:999` with only Y5 plugged in | Open H | M06-17's text; exit 1; no HMAC frame sent to Y5 |
| T45 INT-07.28 | The `app-hwkey` crate, its dependencies and the linked frameworks of the app | Review the code and `otool -L` of the app binary | No PC/SC framework linked and no PC/SC call (D-INT07-2) |
| T46 INT-07.29 | The reference's hardware-key test vault, password `a`; the software key with its secret `1ce30fd78d20dcfa40b50c18779afb0f02288db7` in variable mode | Open | Opens (FMT-04.6-e); with the same secret in fixed mode: wrong-key result |
| T47 INT-07.30 | The simulated device with each script of INT-07.30 | Run T13 to T21 against it | Every result as listed; no real USB call is made (the IOKit layer is not linked in the test binary) |
| T48 INT-07.32 | H made by App with D in variable mode; read `KS` from H; answer = HMAC-SHA1(D, KS); write the 20 bytes to `answer.key` | Run the reference command line tool's database info command on H with `demo-pass` and `-k answer.key` (HOME under `/tmp`) | Opens and prints the vault info |
| T49 INT-07.1 | Y5 whose slot 2 holds a challenge configuration of another kind (not HMAC-SHA1) | Look, then unlock H choosing `24531878:2` from S-STATE-03 | Slot 2 not listed; the unlock gives `SlotNotConfigured` or `TimedOut`, never an answer; App sent no command other than `10`, `30`, `38` and the reset report |
| T50 INT-07.17 | Fake detection result: Y5 slot 2, plus a device found without usable slots | Show the unlock screen's row, the wizard's key part and the credential page | The same one item in all three; "Look for keys again" gives the same M06-36 text in all three |
| T51 INT-07.18 | A vault that needs a hardware key and whose KDF cost is above the CRY-02.14 ceiling; Y5 | Open | `TooLarge`; no frame reaches the device (FMT-04.21-a); with a normal cost: the frame is sent before the KDF starts (spy order) |
| T52 INT-07.31 | Unlock screen test with the fake driver: list [Y5 slot 2], challenge result `TimedOut` | Unlock | M06-18; focus on the list (APP-06.17) |
| T53 INT-07.33 | Waits for OD-01: a real key with D in slot 2, variable mode | Run T01, T19, T25, T35 and interop row B11 with the reference command line tool | Results as listed for the simulated device |

## How this was learned

- Read in the reference source (development branch): the hardware key front object (the USB and smart card interfaces, the shared lock, the 200 ms touch timer, the found-keys map, the challenge that tries USB first, then smart cards); the USB driver (the vendor and product id lists, the maximum of 4 keys, the serial-or-any open, the status read and the slot "configured" bits, the 1-byte test challenge without blocking, the NEO exception, the item texts, the padding to 64 bytes, the reply of 20 bytes, the error mapping); the third-party USB core it ships (frame layout, CRC, the part writes and the busy bit, the reply reading with the pending, touch-wait and count bits, the reset report, the serial command, the status layout, the timeouts, the macOS backend that prefers the FIDO interface because macOS asks before an app opens a keyboard); the smart card driver (application ids, reader filtering, display names), only to describe what App leaves out; the challenge-response key class; the macOS device listener (arrival callbacks for the two vendor ids); the unlock form's key part (the three look triggers, the 0.5 s delay, the touch message, the 2 s note), the key part of the credential editor (its look, test challenge and errors); the command line tool's key option parsing and touch prompt.
- Ran the installed command line tool 2.7.11 with HOME under `/tmp/spec-int07/` on a copy of the reference's hardware-key test vault, password `a`, no device connected: with slot 2 and with `2:123` it printed its touch request, then failed to find the key (serial 0, serial 123), exit 1; with slot 3 it rejected the slot after the password prompt; without a key option it gave the wrong-credentials message.
- Computed the frame, CRC and reply vectors of T13, T16 and T18, and the answers of T03, with python3 (`hmac`, `hashlib` and a direct CRC loop); they match FMT-04.6-a and FMT-04.6-d.
- Read the existing `app-format` key code only for its interface names (the challenge-response trait, the software key, the reason list), not as a source of behavior.
- Proven standard (AGENTS rule 9), read 2026-10-28: Yubico, "Challenge-response" in the YubiKey SDK manual (https://docs.yubico.com/yesdk/users-manual/application-otp/challenge-response.html): challenges up to 64 bytes, 20-byte HMAC-SHA1 response, optional touch, secrets cannot be extracted; Yubico, `ykman` OTP commands (https://docs.yubico.com/software/yubikey/tools/ykman/_sources/OTP_Commands.rst.txt): `chalresp` for slot 1 or 2 with `--touch`; Strongbox issue 95 (https://github.com/strongbox-password-safe/Strongbox/issues/95): YubiKey challenge-response supported; the `challenge_response` crate documentation (https://docs.rs/challenge_response): version 0.5.46, MIT or Apache-2.0, `rusb` (libusb) by default, `nusb` experimental, OnlyKey and NitroKey untested.
- No device was used and no slot of any key was touched (OD-01).

## Review 2026-10-28

Second Spec review. Checked against the reference source (the USB driver, the front object with its lock and 200 ms touch timer, the third-party USB core: frame writer, wait loop, reply reader, reset report, serial read, status bits, and its macOS backend), FMT-04 (the challenge, padding and every hardware-key vector), FMT-18 (a 20-byte key file is the hashed kind), APP-06 (M06-17 to M06-20, M06-35, M06-36, APP-06.30), INT-10 (U03, INT-10.14, M10-02, M10-18), LD-173, OD-01 and the lock frame `lock-locked-password-key-file-security-key` (row "Security key", item "YubiKey 5 NFC · serial 24531878 · slot 2", the known difference of D-INT07-5). Recomputed with python3 (`hmac`, `hashlib`, a direct CRC loop): T03's two answers, T13's CRC `ED74` and 10 reports, T16's reply reports (CRC complement `3939`, residual `F0B8`), T18's serial CRC bytes `c78f`, `R` of T37, and the new T14 vectors. Ran the installed command line tool with HOME under `/tmp` on a copy of the reference's hardware-key test vault, no device: `-y 2` and `-y 2:123` print the touch request, then fail to find the key, exit 1; `-y 3` and `-y 2:abc` are refused after the password prompt, exit 1; with a 20-byte key file holding the variable-mode answer it opens (INT-07.32), with the fixed-mode answer it gives the wrong-credentials result. No device was used.

Fixes made (13): the Inputs table, INT-07.7, INT-07.20, T11 and the Lead decisions intro follow LD-173 (`NotPermitted` is decided); INT-07.15 step 4: the reference pads the 1-byte test challenge by the FMT-04.9 rule (63 bytes of `3F`), it does not zero-fill it; INT-07.9's payload wording follows; T14 rewritten: the skipping of all-zero parts is now shown with the serial command, and the padded test challenge has its own vectors; INT-07.10 says the device stores the ones' complement of the CRC, low byte first, which a Builder of the simulated device needs; INT-07.6 names the reference's model-name difference; MI07-02 gains the `NotPermitted` reason; T46's Given named the demo secret D instead of the test vault's secret; a security note on USB access and the Input Monitoring permission.

Findings, each with a proposed ruling (the default rule of spec/decisions.md applies until the lead rules):

| ID | Finding | Proposed ruling |
|---|---|---|
| R07-1 | INT-07.27 and T43 send bad `--hw-key` values (`3`, `0`, `2:abc`, `2:`, `2:4294967296`) to M10-02, but M10-02's `<problem>` list in INT-10 has no case for a bad value (only unknown option, missing value, missing or extra argument). | INT-10 adds the problem "<value> is not a slot (1 or 2) with an optional serial number" to M10-02, for `--hw-key` and `--hw-key-from`; the INT-10 owner makes the change. |
| R07-2 | `NotPermitted` (LD-173) has no home outside this card: `app-format/error.rs` lists five reasons, APP-06's message table has no line for it (APP-06.18's exhaustive match needs one), and APP-06.30 has no save reason. APP-06.30's table also still says "hardware key" in its four hardware-key reasons, while LD-101 (3) and APP-06's own T62 say "security key". | E10-S1 adds `NotPermitted` to `HardwareKeyReason`; APP-06 takes MI07-01 as the unlock line for it and the reason "macOS did not let App reach the security key" in APP-06.30; APP-06.30's four reasons read "security key" as MI07-02 quotes them. The APP-06 owner makes the change. |
