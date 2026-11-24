# APP-04 Quick unlock

Status: reviewed
Epics: E6-S3
Parity rows: SR-04, SR-07

## What it does

After the user has unlocked a vault once with its full credentials, Larsal can unlock it again with Touch ID (or an Apple Watch) after it locks, without typing the master password. Larsal keeps the vault's key components in its own memory, encrypted with a random key; that random key is stored in the macOS Keychain behind biometrics. Neither part alone opens anything. Quick unlock lasts at most until Larsal quits, and it stops when the Mac's enrolled fingerprints change.

This card says when quick unlock is available and offered, what is stored and where, how a Touch ID attempt that fails or is cancelled behaves, and every event that removes the stored key. The unlock view itself is APP-06; locking is APP-02; the key components are FMT-04; hardware keys are INT-07.

## Inputs and outputs

In:
- A successful full-credential unlock in Larsal's unlock form (APP-06), with the components the user gave: password, key file, hardware key.
- The app setting below (APP-01 owns the inventory; if APP-01 gives a different ID, APP-01 wins).
- macOS LocalAuthentication (can Touch ID or a watch be used now; the biometry domain state) and the Keychain.

Out:
- Per vault: a quick unlock **slot**, made of a memory part and one Keychain item (APP-04.4, APP-04.5).
- On a quick unlock: the rebuilt key components, used once for a normal open, then wiped.

### Settings

| ID | Meaning | Reference default | Larsal default | Values |
|---|---|---|---|---|
| `quick_unlock.enabled` | Offer Touch ID unlock for vaults unlocked before in this session | on | on | on / off. The switch is greyed out when quick unlock is not available right now (APP-04.1). |

The reference keeps this setting per computer, not in its roaming settings; Larsal's settings are per Mac anyway. The reference's settings text names Touch ID and the Windows system together; Larsal's text is "Unlock with Touch ID"; APP-01 (S-LOCK-01) shows the same label (Decided: spec/decisions.md LD-200 (7)).

## Rules

APP-04.1 **Available.** Quick unlock is available when all of these hold, checked anew every time (never cached), because a closed lid or a removed watch changes the answer:
1. `quick_unlock.enabled` is on;
2. Larsal is a signed build that can use the data protection Keychain (Verified 2026-10-28, V-A04-2, with a small ad hoc signed probe on this Mac and a demo item: adding an item to the data protection Keychain returned `errSecMissingEntitlement` (-34018) and wrote nothing, while a query for an item that does not exist returned `errSecItemNotFound` (-25300); so a query alone cannot tell such a build apart, the add can; such a build treats quick unlock as not available);
3. LocalAuthentication says biometric authentication can be evaluated now (Touch ID enrolled and usable), or that companion authentication with a paired Apple Watch can be evaluated now.
The Mac's login password alone does not make quick unlock available in Larsal. The reference source counts the login password too (so it offers quick unlock on every Mac with a password); the installed version 2.7.11 counts only Touch ID or a watch. Lead decision D-A04-1, see APP-04.5.

APP-04.2 **The setting switch.** The switch for `quick_unlock.enabled` is in the security settings. It is greyed out, keeping its stored value, when APP-04.1 points 2 and 3 do not hold at the time the settings screen opens. Turning it off removes every slot at once (APP-04.16).

APP-04.3 **When a slot is made.** After a successful unlock (the vault is open), Larsal makes a slot for that vault, silently (no question, no notice), when all of these hold:
- quick unlock is available (APP-04.1);
- the vault has no slot yet in this Larsal session;
- the user gave the credentials in Larsal's unlock form (main window or the unlock dialog of a browser or Auto-Type request);
- the unlock did not come from quick unlock itself, and did not use credentials passed on the command line or on standard input (APP-09).
If making the slot fails, the unlock still succeeds, no slot exists, and Larsal shows nothing; it logs a reason code without any secret. The reference also makes the slot silently after every such unlock and skips it in the same cases.

APP-04.4 **The memory part.** Larsal collects the key components of the vault: `P` when the vault uses a password, `F` when it uses a key file (FMT-04.1, FMT-04.3), and, when it uses a hardware key, which device and slot to ask (no secret). Never a hardware-key answer, never `R`, never the composite key `C`, never a derived key: those depend on the file's KDF seed, which changes on every save (FMT-04.8, FMT-04.17). Larsal writes these items in its own private layout (it never leaves memory, so no format is shared with any other program), then encrypts them with AES-256-GCM under a fresh random 32-byte key `W` and a fresh random 12-byte nonce, both from the one random source in larsal-crypto (AT-B04). The ciphertext with its 16-byte tag and the nonce stay in Larsal's memory, in the session's entry for that vault, in a secret type (SR-07). `W` goes into the Keychain item (APP-04.5) and is then wiped from memory. The plain components are wiped right after encryption. The reference uses the same split (AES-256-GCM, a 32-byte key and a 16-byte nonce, both stored in the item as hex text). AES-GCM is not in the approved crate list: lead decision D-A04-2 (recommended: add the RustCrypto `aes-gcm` crate, which builds on the approved `aes` crate, through the AT-J03 review; alternative: `chacha20poly1305` on the approved `chacha20`). Not yet ruled: spec/decisions.md LD-156 (7) decides it at the start of E6-S3 from proven apps.

APP-04.5 **The Keychain item.** One generic password item per slot:

| Attribute | Value |
|---|---|
| Class | generic password |
| Service | `app.larsal.vault` |
| Account | a random 16-byte value as 32 lowercase hex characters, new for every slot (not derived from the vault, its id or its path) |
| Label | `Larsal quick unlock` (no vault name, no path) |
| Data | `W`, 32 raw bytes |
| Accessible | when the Mac is unlocked, this device only (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`): never in backups, never moved to another Mac |
| Synchronizable | no (never in iCloud Keychain) |
| Keychain | the data protection Keychain (`kSecUseDataProtectionKeychain`) |
| Access control | biometry, **current set** (`kSecAccessControlBiometryCurrentSet`), **or** the companion watch, per D-A04-1 |

Every query and every deletion of quick unlock items matches the service `app.larsal.vault` **and** the label `Larsal quick unlock` (plus the account when it means one slot), never the service alone. Other Larsal items under the same service, such as the shared-groups identity (APP-01 D-01-6), are never read or deleted by this card (Decided: spec/decisions.md LD-49).

Lead decision D-A04-1, who may open the item: (a) current biometry set only; (b) current biometry set or a paired Apple Watch (the installed reference adds the watch when one is usable at slot time, the source always); (c) as (b), or the Mac's login password (the reference source, when the Mac can ask for it). Recommended: (b). The watch is added only when companion authentication is usable when the slot is made; a Mac with a watch but no Touch ID gets a watch-only item. Option (c) would let anyone who knows the Mac's login password stand in for the master password while Larsal runs, and it lets the item outlive a fingerprint change. Newer SDKs name the watch constraint "companion" (Verified 2026-10-28, V-A04-3: the macOS 26.2 SDK offers `kSecAccessControlCompanion` from macOS 15 and keeps `kSecAccessControlWatch`, deprecated in macOS 15, with the same bit value (1 << 5); Larsal's floor is macOS 14, so Larsal uses the old name before macOS 15, or the shared value). Decided: spec/decisions.md LD-200 (as recommended).

APP-04.6 **Never a weaker item.** If the Keychain refuses the item with the constraints of APP-04.5, Larsal does not try again with fewer constraints; there is simply no slot (APP-04.3). Larsal never stores an item that can be read without user presence. The reference retries once without the biometry constraint after a refusal, which can leave an item guarded only by the watch or the login password. Differs from the reference on purpose.

APP-04.7 **Binding to the enrolled fingerprints.** When it makes a slot with the biometry constraint, Larsal also reads the biometry domain state (`LAContext.evaluatedPolicyDomainState` after a successful biometric `canEvaluatePolicy`, which shows no prompt; newer SDKs offer the same value as the biometry state hash; Verified 2026-10-28, V-A04-4: the macOS 26.2 SDK marks `evaluatedPolicyDomainState` deprecated in macOS 15 and names `LAContext.domainState.biometry.stateHash`, available from macOS 15, as its replacement; on macOS 14, Larsal's floor, only the old property exists) and keeps it with the slot (it is not secret). Before every quick unlock attempt Larsal reads it again. If it differs, a fingerprint was added or removed: Larsal deletes the slot (memory part and item) without asking for Touch ID, shows the password form, and shows `MSG-QU-GONE` (APP-04.14). This works even where macOS would still accept the watch branch of the item (AT-K02). For a watch-only item there is no domain state and no such check.

APP-04.8 **Which vault a slot belongs to.** A slot belongs to the vault's entry in Larsal's session (the open vault, wherever its file now is). Larsal writes nothing into the vault file for quick unlock. The reference instead keys slots by a 16-byte vault id kept in the outer header's public custom data (FMT-02.13) under the key `4B 50 58 43 5F 50 55 42 4C 49 43 5F 55 55 49 44` (stored encoded, name rule). When a version 4 vault has no such id, the reference makes a random one during the unlock and marks the vault changed, so the next save writes it (with saving after every change on, at once). For version 3 files it uses the first 16 bytes of SHA-256 of the file path as UTF-8. The installed version 2.7.11 keys slots by the SHA-256 of the file path. Larsal keeps that header item unchanged when it reads it (FMT-02.13) but never adds or uses it. Lead decision D-A04-3 (recommended: as written; an unlock must not change the file). Decided: spec/decisions.md LD-200 (as recommended).

APP-04.9 **When the Touch ID form is offered.** The unlock view of a locked vault (APP-06) shows the Touch ID form instead of the password form when the vault has a slot and quick unlock is available (APP-04.1). The form, as in design/mockup.html: the vault tile, "Unlock <name>", the file path, the button "Unlock with Touch ID" with a fingerprint icon (it has the focus, so Return presses it), and the link "Use password instead". Larsal re-checks availability each time the window is shown or becomes active: when quick unlock is not available right now (lid closed in clamshell mode with no watch, setting off), the password form shows and the slot is **kept**; when it is available again, the next show or activation brings back the Touch ID form. A vault that was just opened (never unlocked in this session) has no slot, so it always starts with the password form.

APP-04.10 **What starts a Touch ID attempt.**
- Main window: only the user pressing the button (or Return). Larsal never starts the system prompt by itself there.
- The unlock dialog that Larsal opens for a browser bridge or Auto-Type request (INT-01, INT-05): when it shows the Touch ID form and no unlock is running, the attempt starts by itself 0.1 seconds after the dialog appears.

APP-04.11 **The attempt.** Larsal reads the item with an operation prompt in its own words, `MSG-QU-PROMPT` "unlock “<file name>”" (macOS shows it in its system sheet, after Larsal's name). Every attempt asks; Larsal never passes an earlier successful authentication context, so there is no grace period. The read runs off the main thread; while it waits, the form is disabled and the button reads "Checking…" (design/mockup.html). Only one attempt runs at a time; a second press while one runs does nothing.

APP-04.12 **Success.** Larsal gets `W`, decrypts the memory part (the tag must check), and rebuilds the components. If the vault uses a hardware key, Larsal asks it exactly as in a normal unlock: it must be present and is challenged with the file's current seed (FMT-04.8, INT-07). Then the normal open runs: the KDF (about 1 second by default), header check and so on (FMT-04, APP-06). `W` and the plain components are wiped right after they are used. The slot stays for the next lock; no new slot is made (APP-04.3). The key file is not read during a quick unlock (`F` is stored), so a quick unlock works while the key file's drive is unplugged.

APP-04.13 **Cancel.** When the user cancels the system sheet, or macOS cancels it (for example another app comes to the front, or the screen locks), Larsal shows no error, runs no KDF, and stays on the Touch ID form; the slot is kept. The reference treats a cancel as success with an empty key: it builds a composite key with no components, runs the full KDF on it, and shows its wrong-credentials message (observed in the source; Verified 2026-10-28, V-A04-1: a cancelled Keychain read is returned as success with no key data; the unlock form turns the empty data into a key with no parts, and the vault open has no guard for an empty key, so the full KDF runs and the wrong-credentials text follows). In Larsal an empty set of components is refused before any KDF anyway (spec/decisions.md LD-13). Lead decision D-A04-4 (recommended: as written). Decided: spec/decisions.md LD-200 (as recommended).

APP-04.14 **Other outcomes.**

| Outcome | Larsal does | Message |
|---|---|---|
| The biometry domain state changed (APP-04.7), the item is missing or invalidated, or the memory part fails its tag check | Delete the slot (memory part and item); show the password form | `MSG-QU-GONE` "Touch ID is no longer set up for this vault. Enter your password." |
| Authentication failed (unknown finger, too many tries), biometry locked out, Touch ID not usable right now, or the system does not allow the prompt | Keep the slot; stay on the Touch ID form; the user may try again or use the password | `MSG-QU-FAILED` "Touch ID did not unlock the vault. Try again or use your password." |
| Touch ID worked but the open fails with `WrongKey` (the vault's credentials were changed elsewhere, or another vault file was put at this path) | Delete the slot; show the password form | `MSG-QU-KEY-CHANGED` "The credentials of this vault have changed. Enter them to unlock." |
| Touch ID worked but the open fails for another reason (file missing, `Corrupt`, hardware key missing or wrong) | Keep the slot; show the open error as APP-06 does | the APP-06 message |

The reference shows one message for every read failure (a prefix saying that quick unlock could not authenticate, followed by an empty detail; in the installed version the prefix names Touch ID instead), stays on the Touch ID form, and keeps the slot. After a wrong key it shows the wrong-credentials message and also keeps the slot. In both cases the user can only leave with its Cancel button (APP-04.15). Lead decision D-A04-5 (recommended: as in the table). Decided: spec/decisions.md LD-200 (as recommended).

APP-04.15 **Use password instead.** The link "Use password instead" (and the Escape key on the Touch ID form) deletes the slot, memory part and item, and shows the password form. After the next successful password unlock, APP-04.3 makes a new slot. The reference's Cancel button on its Touch ID form (also on Escape) does the same.

APP-04.16 **When the slot is removed.**

| Event | Larsal | Reference (source) |
|---|---|---|
| The vault locks (any trigger, APP-02) | Kept: this is what quick unlock is for | Kept |
| The vault is closed (from unlocked or locked) | Deleted: memory part and item | Memory part removed, only if quick unlock is available at that moment; the item stays in the Keychain |
| Larsal quits normally | Every slot deleted, items included, before exit | Memory parts are gone with the process; items stay |
| Larsal crashed or was killed | At the next start, before any vault opens, Larsal deletes every item with service `app.larsal.vault` and label `Larsal quick unlock` (their memory parts are gone, so they are useless); other items under that service stay (LD-49) | Items stay until a slot for the same vault id replaces them |
| `quick_unlock.enabled` turned off | Every slot deleted at once | Not offered while off, but memory parts are kept and offered again when the setting is turned back on |
| The vault's credentials changed in its security settings (MOD-12) | That vault's slot deleted; the next password unlock makes a new one | Memory part removed |
| A fingerprint added or removed | Deleted at the next attempt, before any prompt (APP-04.7) | The item stops working (failure message); memory part kept until Cancel |
| "Use password instead" (APP-04.15) | Deleted | Deleted (its Cancel button) |
| `WrongKey` after a good Touch ID | Deleted (APP-04.14) | Kept |
| Quick unlock not available right now | Kept (APP-04.9) | Kept |
| Time passing | No limit (APP-04.17) | No limit |

AT-K03 depends on the Larsal column: after the setting is turned off, the vault is closed or Larsal quits, no item with service `app.larsal.vault` and label `Larsal quick unlock` (for that vault, or at all) is left in the Keychain, and items with other labels under that service are still there.

APP-04.17 **No time limit.** A slot has no expiry of its own; it ends at the latest when the vault closes or Larsal quits. D-A04-6 Decided (spec/decisions.md LD-55): no limit, as the reference.

APP-04.18 **Several vaults.** Each open vault has its own slot, item and memory part. Removing one never touches another, except for the setting switch and quit, which remove all.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| First unlock of a vault after Larsal starts | Always the password form (no slot yet). After it succeeds, a slot is made silently. |
| Unlock with the password passed on standard input (APP-09) | No slot made; the next lock shows the password form. |
| Mac mini with no Touch ID and no watch | Not available; the setting switch is greyed out; the password form always shows. |
| MacBook used closed with an external display, no watch | Touch ID not usable: password form shown, slot kept; opening the lid and activating the window brings back the Touch ID form. |
| A watch is the only way (no Touch ID) | A watch-only item (D-A04-1 (b)); no domain state check. |
| The user adds a fingerprint in System Settings while the vault is locked | Next press: no prompt, slot deleted, password form, `MSG-QU-GONE` (AT-K02). |
| Another Mac account | Its own Keychain; Larsal's items of one account are never visible to another. |
| Vault password changed by another device, file synced, vault locked here | Touch ID works, open gives `WrongKey`: slot deleted, password form, `MSG-QU-KEY-CHANGED`. |
| Vault uses a hardware key that is unplugged | Touch ID works, the hardware key is missing: the APP-06 hardware-key error; slot kept, so after plugging the key in the user can try again. |
| Two presses on the button in a row | One attempt (APP-04.11). |
| The screen locks while the system sheet is open | Counts as a cancel (APP-04.13); the screen lock also locks other vaults (APP-02.5). |
| The Keychain is locked or not reachable (the Mac's login keychain state) | Treated as "not usable right now": `MSG-QU-FAILED`, slot kept. |
| Leftover items from a crash, Larsal starts | All quick unlock items (service plus label, LD-49) deleted before any vault opens (APP-04.16); the shared-groups identity stays. An item that cannot be deleted is logged without its data; it is useless without the lost memory part. |
| Settings screen opened while the lid is closed | The switch is greyed out but keeps its value; existing slots are kept. |

### Not on Mac (reference behavior on other systems, for later ports)

- Windows: Windows Hello. A Windows Hello credential signs a random challenge; a key derived from the signature encrypts the vault key in memory. The setting text names it. On a failed read with an error text, the slot is removed.
- Linux: the freedesktop authorization service guards a vault key kept encrypted in memory.

## Security notes

- **Two parts, each useless alone.** The memory part is encrypted; the Keychain item holds only the random key `W`, behind biometrics, on this Mac only, never synced, never in backups. A memory dump of a locked Larsal shows only ciphertext (AT-C01: no demo master password, no `P` in the clear, no derived key). A copy of the Keychain item without Larsal's memory opens nothing.
- **What must never happen:** a slot that survives quit, close or turning the setting off (AT-K03); a slot that still works after a fingerprint change (AT-K02, APP-04.7); an item readable without user presence (APP-04.6); quick unlock bypassing a hardware key (APP-04.12); the vault file changed by an unlock (APP-04.8); `W`, `P`, `F` or the plain memory part in a log, an error or the screen layer (SR-07, AT-C06).
- The memory part must stay out of swap like other key material (architecture, `memory.rs`; AT-C05).
- Quick unlock is a convenience that trades the master password for a fingerprint while Larsal runs. Anyone whose fingerprint is enrolled on this Mac (or who wears the paired watch, with D-A04-1 (b)) can unlock a locked vault until Larsal quits. The default stays on for parity with the reference; the settings text should make this clear (APP-01).
- The reference leaves Keychain items behind after close and quit; Larsal deletes them (APP-04.16), which is what AT-K03 checks.
- Parity rows: SR-04 (quick unlock behind biometrics, dropped when biometrics change), SR-07 (key material protected in memory). Attacks: AT-K02, AT-K03, AT-C01, AT-C05, AT-C06.

## Test cases

Unit tests use the larsal-platform quick unlock trait with a fake LocalAuthentication (scripted answers: available or not, domain state, success, cancel, failure kinds) and a fake Keychain (records attributes; can refuse). AT-K02 and AT-K03 run on this Mac with a signed build and demo vaults only. Demo vault A: password `demo-master-A`, no key file. Demo vault K: password `demo-master-K` plus key file `demo.larsalkey`. Demo vault H: password plus a simulated hardware key (software challenge-response, as for OD-01).

| Case | Given | When | Then |
|---|---|---|---|
| T01 APP-04.1 | Setting on, fake: biometrics usable | Ask availability | Available |
| T02 APP-04.1 passcode only | Setting on, fake: no biometrics, no watch, device password usable | Ask availability | Not available (D-A04-1) |
| T03 APP-04.1 watch | No biometrics, companion usable | Ask availability | Available |
| T04 APP-04.1 not cached | Biometrics usable, then the fake turns it off | Ask twice | Available, then not available |
| T05 APP-04.1 unsigned | Fake Keychain answers "missing entitlement" | Ask availability | Not available |
| T06 APP-04.2 | Biometrics not usable | Open settings | Switch greyed out, still shows on |
| T07 APP-04.3 | Available, A locked, no slot | Unlock A with `demo-master-A` in the form | A open; one item added; no prompt; no notice |
| T08 APP-04.3 stdin | Same | Unlock A with the password from standard input (APP-09) | No item added |
| T09 APP-04.3 no duplicate | A has a slot; user uses "Use password instead", unlocks | Count items | Exactly one (the old one deleted, a new one made) |
| T10 APP-04.3 failure | Fake Keychain refuses the add | Unlock A | A open; no slot; no message; log has a reason code and no secret |
| T11 APP-04.4 | Unlock K | Inspect the memory part (test hook) | Ciphertext of the length of the private layout plus a 16-byte tag; 12-byte nonce; no 32-byte run equal to `P` or `F` in it |
| T12 APP-04.4 hardware key | Unlock H | Inspect the plain layout before encryption (test hook) | Holds `P` and the device and slot to ask; holds no 20-byte answer and no `R` |
| T13 APP-04.5 | Unlock A | Read the fake Keychain's record | Class generic password; service `app.larsal.vault`; account 32 lowercase hex characters; label `Larsal quick unlock`; data 32 bytes; accessible when unlocked, this device only; not synchronizable; data protection Keychain; access control biometry current set or companion |
| T14 APP-04.5 fresh account | Unlock A, "Use password instead", unlock again | Compare the two accounts | Different |
| T15 APP-04.5 watch only | No biometrics, companion usable | Unlock A | Item access control: companion only |
| T16 APP-04.6 | Fake Keychain refuses any item with the biometry constraint | Unlock A | No second add attempt with fewer constraints; no slot |
| T17 APP-04.7 AT-K02 | A has a slot with domain state `S1`; fake now reports `S2` | Press "Unlock with Touch ID" | No prompt; item deleted; password form; `MSG-QU-GONE` |
| T18 APP-04.7 same state | Domain state unchanged | Press the button, fake succeeds | Unlock proceeds |
| T19 APP-04.8 | Version 4 demo vault without the public id item; quick unlock on | Unlock, lock, quick unlock, close | File bytes unchanged by these steps (same hash before and after) |
| T20 APP-04.8 kept | Demo vault whose header has the public id item (made by the reference command line tool or a test builder) | Open, change an entry, save | The header still holds the item with the same 16-byte value |
| T21 APP-04.9 | A unlocked once, then locked | Look at the unlock view | Touch ID form: "Unlock with Touch ID" focused, "Use password instead" link |
| T22 APP-04.9 unavailable | A has a slot; fake: biometrics not usable, no watch | Activate the window | Password form; item still present; fake turns biometrics back on; activate again: Touch ID form |
| T23 APP-04.10 | A locked with a slot, main window | Wait 5 s | No prompt started |
| T24 APP-04.10 dialog | A locked with a slot; a browser request opens the unlock dialog | Dialog shown at t = 0 | Prompt starts at t = 0.1 (± 0.1) |
| T25 APP-04.11 | Press the button | During the fake's delay | Form disabled; button reads "Checking…"; prompt text `MSG-QU-PROMPT` holds the file name |
| T26 APP-04.11 no reuse | Two quick unlocks in a row (lock in between) | Count prompts | Two |
| T27 APP-04.12 | Fake succeeds | Press the button | A open; KDF ran once; slot still present; no second item |
| T28 APP-04.12 key file absent | K has a slot; `demo.larsalkey` moved away | Quick unlock | K opens |
| T29 APP-04.12 hardware key | H has a slot; simulated key present | Quick unlock | Key challenged once with the file's current seed; H opens |
| T30 APP-04.13 | Fake answers "user cancel" | Press the button | No error shown; KDF not run (spy); Touch ID form still shown; slot present |
| T31 APP-04.14 gone | Fake Keychain: item not found | Press the button | Slot deleted; password form; `MSG-QU-GONE` |
| T32 APP-04.14 tag | Test hook flips one byte of the memory part | Quick unlock | `MSG-QU-GONE`; slot and item deleted; no open attempted |
| T33 APP-04.14 failed | Fake: authentication failed | Press the button | `MSG-QU-FAILED`; Touch ID form; slot present |
| T34 APP-04.14 wrong key | A's password changed to `demo-master-A2` by another copy of Larsal, file replaced, A locked here | Quick unlock | `WrongKey`; slot deleted; password form; `MSG-QU-KEY-CHANGED` |
| T35 APP-04.14 hardware key missing | H has a slot; simulated key absent | Quick unlock | The APP-06 hardware-key error; slot present |
| T36 APP-04.15 | A locked with a slot | Click "Use password instead" | Item deleted; password form; unlock with the password makes a new item |
| T37 APP-04.15 Escape | Same | Press Escape on the Touch ID form | Same as T36 |
| T38 APP-04.16 lock | A has a slot | Idle lock, screen lock, Cmd+L | Item present after each |
| T39 APP-04.16 close AT-K03 | A has a slot | Close A | No item with service `app.larsal.vault` and label `Larsal quick unlock` for A (Keychain query on this Mac) |
| T40 APP-04.16 setting off AT-K03 | A and K have slots | Turn `quick_unlock.enabled` off | No item with service `app.larsal.vault` and label `Larsal quick unlock` left; turning it back on offers no Touch ID form until the next password unlock |
| T41 APP-04.16 quit | A and K have slots | Cmd+Q | No item with service `app.larsal.vault` and label `Larsal quick unlock` left after exit |
| T42 APP-04.16 crash sweep | Two quick unlock items left by a killed Larsal, plus the shared-groups identity item (made by a test helper) | Start Larsal | Both quick unlock items deleted before the first vault opens; the identity item still present |
| T47 APP-04.5 matching (LD-49) | Shared-groups identity item exists (service `app.larsal.vault`, its own account and label); A and K have slots | Close A; turn `quick_unlock.enabled` off; quit; start again | After each step the identity item is still present and unchanged; every deletion the fake Keychain recorded named the label `Larsal quick unlock` |
| T43 APP-04.16 key change | A unlocked with a slot | Change A's password in its security settings, save, lock | Password form (slot gone); after unlocking with the new password, a new item |
| T44 APP-04.17 | A has a slot | Fake clock moves 72 hours, press the button | Prompt shown; unlock works (no expiry) |
| T45 APP-04.18 | A and K have slots | "Use password instead" on A | K's item still present |
| T46 APP-04.4 AT-C01 | Debug build with memory scan; A has a slot and is locked | Scan memory | No `demo-master-A`, no `P` (32-byte SHA-256 of it), no `W`, no derived key found |

## How this was learned

- Read the reference's macOS quick unlock routine: how it makes the random key and nonce, encrypts the key components with AES-256-GCM and keeps the result in memory, how it builds the Keychain item (class, account built from a fixed product prefix and the vault id, accessibility, no sync, access control flags for biometry, watch and login password, the retry without biometry), how it reads the item with an operation prompt, what it does on a user cancel, and what its availability check counts.
- Read the shared quick unlock interface and the factory that picks the platform implementation; skimmed the Windows and Linux implementations for the "Not on Mac" list.
- Read the unlock form: when it stores a slot after an unlock, when it blocks that (credentials passed in from outside, unlocks done by quick unlock), how it builds the key from a slot, its failure message, the Touch ID page and its Cancel button (Escape), the reset on show or activation, and the automatic start in the separate unlock dialog after 100 ms.
- Read the vault's composite key serialization (which components it holds, and that a hardware key is stored only as device and slot), the vault's public id (header public custom data, creation on first use, the version 3 fallback from the file path), the vault view's close handler (slot reset), and the vault security settings (slot reset after a credential change).
- Read the settings screen definition and defaults table for the setting, its default and when its switch is greyed out.
- Compared with the tag of the installed version 2.7.11: slots keyed by a hash of the file path, availability from Touch ID or watch only, watch added only when usable, the Touch ID failure message of APP-04.14 (also found in the installed binary's strings).
- No Touch ID prompt, Keychain item or real vault was used. V-A04-1 to V-A04-4, AT-K02 and AT-K03 are left to Verify on this Mac with a signed build and demo vaults.
