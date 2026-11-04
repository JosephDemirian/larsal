# E1-S7 Security parity search

Story: E1-S7 Security parity matrix complete.
Date: 2026-10-25 (Sprint 1).
Result: the matrix in [plan/security.md](../../plan/security.md) now has 80 rows (57 before, 23 added; the lead later added SD-12 under LD-53, so 81). 18 rows were confirmed as written, 39 were corrected, and none were removed. Every security behavior found in the search maps to a row, except the platform-only behaviors listed at the end, which do not exist on macOS.

## What was searched

The reference source studied was the development branch at commit 09e34ba8. The installed reference app is version 2.7.11. All reading was read only. No vault was opened. The reference app's window was not started and its settings folder was not read. The command line tool was used only to print its help, and the installed app bundle only to show its code signature. No network service was contacted.

## Method

The search went through the reference source one topic at a time. For each topic, a text search found every place in the source that uses the topic's library calls, settings or operating system calls. Each place was then read in context to see when the behavior runs, what its default is and what the user sees. The topics:

1. **Random values.** Every call to the shared random source and every direct use of the crypto library's generator: vault saves, the KDF seed, key files, passkeys, SSH key generation, the shared groups signing key, quick unlock, hardware-key test challenges and the attachment wipe.
2. **Crypto.** The cipher, hash and KDF wrappers; the start-up self-test; the browser bridge box; passkey signing; shared groups signing; the SSH key code; the importers that decrypt (the OPVault format, the encrypted JSON export, the legacy version 1 vault format); and the encryption settings screen with its warnings.
3. **Memory wiping and protected memory.** The global allocator override, wiping buffers in the key classes, explicit wipes in quick unlock and key files, and how protected fields are held in memory.
4. **Locking.** Every caller of the lock routines: idle timer, screen lock and user switch listeners, minimize, quit, the single-instance lock request, the browser lock request, and relock after Auto-Type. Also what the lock routine itself does, and what can stop it.
5. **Clipboard.** The clipboard helper, every copy site in the app and the command line tool, the macOS pasteboard type marker, the clear timer and its triggers.
6. **Keychain and other secret stores.** Every Keychain call (only quick unlock uses it on macOS) and its access-control flags. Also the Linux and Windows secret stores, recorded below as platform only.
7. **Debugger, crash and core dump settings.** The start-up hardening routine, the build flags that silence debug output, signal handlers, and any crash reporter (none was found).
8. **File saving, backups and temp files.** The save routine and its three modes, the backup and restore helpers, the save-retry prompt, the change-on-disk watcher and reload prompts, every file permission call, every temporary file and folder (attachments, remote sync), and every export writer.
9. **Network.** Every network request and DNS lookup, plus the build options that remove network code: the update check, the icon downloader, the online breach check, and the browser-triggered icon download. Also TLS and redirect handling.
10. **Permissions.** Accessibility and Screen Recording requests (Auto-Type), USB and smart-card access (hardware keys), local sockets (single instance, browser bridge, SSH agent), the entitlements file, and launch at login.
11. **Browser bridge.** The local server, the relay program, the native messaging manifests, every request handler, association storage, the site access prompt, URL matching, passkeys, and the bridge settings with their defaults.
12. **SSH agent.** Adding and removing keys, constraints, lock and quit handling, per-entry settings and their defaults, and the key generator.
13. **Auto-Type.** Start conditions, window matching, the picker, focus checks, sequence limits, special placeholders and the macOS typing calls.
14. **Hardware keys.** The challenge-response path, its buffers and the drivers.
15. **Shared groups.** Import, export, signing, the signature check (and its history in the reference: removed in version 2.7.0) and the activation settings.
16. **Process start-up.** The main start-up routine, launch flags, the single-instance check, the crypto self-test and the screen-capture default.
17. **Logging of sensitive data.** Every log call near passwords, keys, titles, URLs or messages, and how release builds filter debug output.
18. **Settings.** The full settings inventory, read for every setting with a security effect and its default.
19. **Command line tool.** Password prompts, the copy command, show, analyze (offline breach check), export, and start-up hardening.
20. **Release.** The signing, notarization and release-signature steps, checked against the code signature of the installed bundle.

## Behaviors found and their rows

| # | Behavior found | Row |
|---|---|---|
| 1 | Vault ciphers: AES-256-CBC, Twofish-CBC, ChaCha20 | SF-01 |
| 2 | KDFs: Argon2d, Argon2id, AES-KDF; settings in the file | SF-02 |
| 3 | KDF benchmark to a target time (1 s default, 0.1 to 5 s) | SF-03 |
| 4 | Composite key from password, key file and hardware-key response | SF-04 |
| 5 | Header hash and header HMAC before decrypting | SF-05 |
| 6 | Block HMAC stream (version 4); hashed blocks (version 3) | SF-06 |
| 7 | Fresh master seed, IV or nonce, field stream key and KDF seed or salt on each save | SF-07 |
| 8 | Random padding item (64 to 512 random bytes, hex) written to the vault custom data on every save | SF-07 |
| 9 | Save fails when the derived key equals the previous one (KDF not rerun) | SF-07 |
| 10 | Inner stream cipher for protected fields | SF-08 |
| 11 | Per-field protection flags | SF-09 |
| 12 | One-time password secrets and passkey private data always stored protected | SF-09 |
| 13 | Key file kinds read; new key files with 32 random bytes and a check value | SF-10 |
| 14 | New key files saved read-only for the owner | SF-10, SD-09 |
| 15 | Optional gzip inside the encryption | SF-11 |
| 16 | Public header data carries no secrets | SF-12 |
| 17 | Master key change reminder and force values are read, kept and written, the key change time is recorded, and no reminder is ever shown | SF-13 |
| 18 | Encryption settings warn about more than 10,000 Argon2 iterations and fewer than 100,000 AES-KDF rounds; a failed change leaves the KDF unchanged | SF-14 |
| 19 | Start-up known-answer self-test of SHA-256, SHA-512, AES-256-CBC, AES-KDF, Twofish, Salsa20 and ChaCha20, plus a minimum crypto library version; fatal on failure (app and command line tool) | SF-15 |
| 20 | No-password warning, weak-password warning, optional minimum password quality, refusal of an empty key | SF-16 |
| 21 | Refusal of the vault itself as its own key file; warning for a vault-like key file and for the old key file format | SF-16 |
| 22 | Unlock with an empty password field offers a retry with an empty password | SF-16 (key rules), APP-06 |
| 23 | Encrypted importers: the OPVault format, the encrypted JSON export, the legacy version 1 vault format; their MAC compares are not constant time; Argon2 costs read from the import file are not bounded | SF-17 |
| 24 | Idle lock: on, 15 minutes, at least 10 seconds; only in-app input counts as activity | SR-01 |
| 25 | Screen lock and user switch locks; no sleep trigger on macOS (the Linux listener has one) | SR-02 |
| 26 | Lock on minimize, delayed 1 to 20 seconds by the clipboard countdown; cannot be combined with minimize after unlock | SR-03 |
| 27 | All vaults locked before quitting | SR-03 |
| 28 | Quick unlock: AES-256-GCM wrapping key in a Keychain item (this device only, not synchronized, current biometric set, or Apple Watch, or the Mac login password); the encrypted key lives only in memory; a retry without the biometric flag when the first store fails | SR-04 |
| 29 | Quick unlock reset on vault close, master key change, and "use password" | SR-04 |
| 30 | Quick unlock stores only the hardware-key slot, so the key is still needed | SR-04 |
| 31 | Debugger attach denied and core dumps off, release builds only, app and command line tool; failure only logged | SR-05 |
| 32 | Secure keyboard input while a password field has focus; Caps Lock warning | SR-06 |
| 33 | Global allocator override wipes every freed heap block; wiping buffers for key parts; explicit wipes in quick unlock and key file code | SR-07 |
| 34 | Expired and soon-expiring (3 days) entries shown after unlock | SR-08 |
| 35 | Single instance through an owner-only local socket and a lock file; second launch hands over paths; the lock flag; password at launch only from standard input | SR-09 |
| 36 | Auto-open of vaults listed in a dedicated group, with credentials from its entries and a computer-name filter; also an entry URL scheme that opens a vault | SR-10 |
| 37 | Command URLs run a program after a confirm (No default, passwords masked, answer remembered per entry); other URLs go to the system handler | SR-11 |
| 38 | Recent vaults, key file paths and hardware-key slots remembered as plain paths; erased when the option is turned off | SR-12 |
| 39 | Command line prompts without echo, reads standard input, hides protected values unless asked | SR-13 |
| 40 | Release builds drop debug output; warnings hold lengths, ids and codes; debug-level merge lines hold entry titles | SR-14 |
| 41 | Owner-only local sockets in the user's temp folder (browser bridge, single instance); no listening network port | SR-15 |
| 42 | Lock closes the vault's dialogs, clears the clipboard value, removes SSH keys, drops the vault and keeps only the header | SR-16 |
| 43 | A save-or-discard question, or an edit-in-progress question, can hold a lock until answered | SR-16 |
| 44 | Clipboard clear after 10 seconds, only if the value is still there; countdown; copied selections included | SC-01 |
| 45 | macOS concealed pasteboard type on every copy | SC-02 |
| 46 | Clipboard value cleared on lock and on quit | SC-03 |
| 47 | Passwords masked in the list, entry view and editor; options to hide usernames, notes and one-time codes | SC-04 |
| 48 | Every window hidden from capture by default; menu toggle and launch flag for the current run; warning if hiding fails | SC-05 |
| 49 | Strength meter while typing | SC-06 |
| 50 | Command line copy: system copy tool, no marker, unconditional clear after the timeout while the command runs | SC-07 |
| 51 | Search box cleared a set time after focus loss (off, 5 minutes) | SC-08 |
| 52 | Atomic save by default; non-atomic temp-file save and direct-write save as options; the offer to turn off safe saves after three failures | SD-01 |
| 53 | Save writes through symbolic links, keeps the creation time, refuses overlapping saves, never saves a locked or keyless vault | SD-01 |
| 54 | Backup before save (off by default) to a path pattern, with the vault's permissions; restore when a non-atomic swap fails | SD-02 |
| 55 | Change-on-disk watcher; silent reload or prompt; merge, ignore or discard choices; a save refuses to overwrite a file changed since it was read | SD-03 |
| 56 | History limits: 10 items, 6 MiB | SD-04 |
| 57 | Recycle bin; no confirm when moving to it (default), confirm when deleting for good | SD-05 |
| 58 | Unknown data kept on save | SD-06 |
| 59 | Export warning for CSV, HTML and XML; passkey export with plain private keys and no warning | SD-07 |
| 60 | Placeholder and reference depth limit of 10 | SD-08 |
| 61 | File permissions for vaults, attachments, temp files, key files, backups; exports left at default permissions | SD-09 |
| 62 | Auto-save after every change, before lock and quit, and silent save of non-data changes | SD-10 |
| 63 | Attachments opened in another app: owner-only temp file, change prompt, random overwrite then delete | SD-11 |
| 64 | Password generator from the OS random source with rejection sampling | SG-01 |
| 65 | Generator options | SG-02 |
| 66 | Passphrases: 7,776-word list, 7 words by default, custom lists deduplicated with a minimum size, signed-list headers skipped | SG-03 |
| 67 | Health Check: weak, reused, expired; exclude from reports | SG-04 |
| 68 | Online breach check: on request, caution text, 5-character SHA-1 prefix, unique passwords, minimal user agent, recycled and empty skipped, excluded still sent | SG-05 |
| 69 | Offline breach check in the command line tool; the outside lookup tool gets full SHA-1 hashes as arguments | SG-06 |
| 70 | Browser bridge: X25519 with XSalsa20-Poly1305 boxes, relay program, owner-only socket, manifests limited to the official extension ids, named association stored in the vault, size limits | SI-01 |
| 71 | Browser bridge does not track used nonces | SI-01 |
| 72 | Site access prompt; remembered allow and deny per entry and host; HTTP authentication always asks; always-allow option; one prompt at a time; closed on lock | SI-02 |
| 73 | URL matching rules, including the special lookup scheme by id or path | SI-03 |
| 74 | Entry and group browser options; expired entries denied; extra string fields | SI-04 |
| 75 | Passkeys: https only (localhost with an option), relying party id check, challenge and user id limits, three algorithms, confirm with countdown, protected storage, overwrite question | SI-05 |
| 76 | Auto-Type: target window fixed at start, stop on focus change, never into the app itself, picker rules, sequence limits, picker closed on lock, relock after Auto-Type (option) | SI-06 |
| 77 | SSH agent: add on unlock, lifetime and confirm constraints, remove on lock and quit, remove all when turned off, ownership conflict refusal | SI-07 |
| 78 | SSH key generator (RSA, ECDSA, Ed25519) from the system random source | SI-07, SG-01 |
| 79 | SSH settings flag to save the key attachment to a temp file: kept in the entry, never acted on | SI-07 (no behavior) |
| 80 | Hardware-key challenge-response; responses in wiping buffers | SI-08, SR-07 |
| 81 | Shared groups: per-share password, activation settings off by default, export signs with RSA-2048, import ignores the signature since version 2.7.0 | SI-09 |
| 82 | Bridge save and update of logins; update question; placeholders refused; references followed | SI-10 |
| 83 | Bridge one-time code by entry id with no site check | SI-11 |
| 84 | Bridge lock request, unlock dialog trigger, Auto-Type request without association, delete with a question, create group, password generator, full entry list (option, off) | SI-12 |
| 85 | Remote sync with user commands stored in the vault, timeouts, temp copy left behind | SI-13 |
| 86 | Accessibility and Screen Recording requests for Auto-Type | SI-14 |
| 87 | No network until the user acts; the update question on first start | SN-01 |
| 88 | Icon download triggers, URL clean-up, redirects, timeout, outside icon service option | SN-02 |
| 89 | Browser extension can ask for an icon download when it saves a login | SN-02 |
| 90 | System TLS with certificate checks, no ignored errors; plain http icon fetches for http entries | SN-03 |
| 91 | Update check every 7 days at most, manual check, beta option | SN-04 |
| 92 | Build options that remove network code and update checks | SN-05 |
| 93 | Hardened runtime, notarization, one entitlement (Keychain access group); observed on the installed bundle | SB-01 |
| 94 | Release files signed with a detached signature plus a SHA-256 digest file | SB-03 |

## Facts that differ in the installed version

| Topic | Source rule | Installed version 2.7.11 |
|---|---|---|
| Shared groups signature check | Not checked (removed in 2.7.0) | The same: 2.7.0 and later carry the change. SI-09 holds for both. |
| Command line copy timeout | 10 seconds, 0 means never | The same: shown in the installed tool's help. |
| Command line show | Protected values hidden unless asked | The same: shown in the installed tool's help. |
| Offline breach check | Hash list file or outside lookup tool | The same: shown in the installed tool's help. |
| Signing | Hardened runtime, notarization | The same: seen in the installed bundle's signature. |
| Source version | The source is the next release (2.8.0 beta) on a newer UI toolkit major version | 2.7.11. The rows below come from the source's change log, security fixes section included. |
| Placeholders in logins saved by the bridge (SI-10) | Refused | Saved as given. Fixed as a security issue in the next release. |
| Bridge message encrypt and decrypt (SI-01) | Bounds checked | Out-of-bounds writes, fixed as a security issue in the next release. |
| Legacy version 1 vault importer (SF-17) | Fixed | A use-after-free and an integer overflow with an out-of-bounds read on crafted files. |
| Icon download redirects (SN-02) | At most 5 | The limit is ignored. |
| Quick unlock with the Mac login password (SR-04) | Offered when Touch ID is not available | Not offered: Touch ID or Apple Watch only. |
| Remote sync (SI-13), SSH key generator (SI-07), bridge entry list (SI-12) | Present | Not present. |
| Wiping of decompression buffers (SR-07) | Improved in the next release | Older behavior. |
| Installed crypto library (SR-07) | Not in the source tree | Imports `mlock` and `mmap`, so its wiping buffers come from a page-locked pool. |

No other row was checked against the installed app, because its window may not be started. A Verify agent can check the screen rows (SR-04, SC-04, SC-05) on the installed version, using a throwaway settings folder (LD-34).

## Found, but not on macOS (no row)

| Behavior | Platform | Why no row |
|---|---|---|
| Process access-control list that blocks memory reads by other processes | Windows | Not on macOS. SR-05 covers the macOS equivalent. |
| Safe DLL search path; crypto library config variables pointed at an invalid path | Windows | Not on macOS |
| Settings enforced by machine policy (registry); locked settings in the settings screen | Windows | macOS has no reference equivalent. Recorded for APP-01. |
| Quick unlock with the Windows biometric sign-in, or with the Linux desktop's authorization service and kernel keyring | Windows, Linux | SR-04 covers Touch ID |
| Desktop secret-store provider on the Linux desktop message bus (exposes vault entries to other apps, with prompts) | Linux | Not on macOS |
| Process marked not dumpable | Linux | SR-05 covers the macOS calls |
| Clipboard history and cloud clipboard opt-out flags; desktop clipboard manager hint | Windows, Linux | SC-02 covers the macOS marker |
| Screen lock and sleep listeners on the Linux desktop message bus | Linux | SR-02 |
| Auto-Type through the Linux display systems or Windows input | Linux, Windows | SI-06 covers macOS |
| SSH agent through the Windows agent program and its named pipe | Windows | SI-07 covers the Unix socket |
| Socket path moved for sandboxed Linux packages | Linux | SR-15 covers macOS |

## Checked, and not a security behavior (no row)

- Hiding or minimizing the window after a copy (off by default): a convenience. The setting is recorded for APP-01.
- Launch at login (a launch agent file in the user's library folder): no secret is involved.
- Network interface polling turned off at start-up: performance only.
- One-time code shown as a QR code and copied as a link: the screen part is covered by SC-05, the copy by SC-01.
- Copy on double click (off by default): covered by SC-01 and SC-02 when used.

## Open points for the lead

1. SR-16: may an automatic lock (idle, screen lock) wait on a save-or-discard question, as in the reference? The proposal is no: save when auto-save is on, otherwise lock and keep the unsaved changes in an encrypted recovery copy, or ask after the next unlock.
2. SI-09: should App check shared groups signatures with trust per signer, which the reference stopped doing in 2.7.0? The matrix proposes yes. Files from the reference would then need a trust step.
3. SI-11: should App limit one-time codes over the bridge to entries the site may access? The proposal is yes.
4. SR-04: should App accept the Mac login password and Apple Watch for quick unlock, as the reference does? This choice belongs to card APP-04.

## Second review (Spec reviewer, 2026-10-25)

Read the source again for each row, checked the installed bundle's crypto library imports, and read the source's change log. Rows corrected in place (facts only; App's target unchanged):

| Row | Correction | Where seen |
|---|---|---|
| SR-07 | Only blocks freed through C++ delete are wiped; toolkit string and byte-array buffers are freed with plain free. Key-part buffers are page-locked by the crypto library. | The global allocator override; the key classes; the installed crypto library's imports |
| SR-14 | Release builds keep warnings, and merge conflict warnings name entry titles; one importer warning names a title and a field value. | The merge routine; the importers |
| SD-08 | Not every loop ends (MOD-08.19, MOD-08.20). | Spec MOD-08 runs with the command line tool |
| SR-04 | Option on by default; key parts, not one key; the Keychain item stays after a reset. | The quick unlock code and its callers |
| SR-11 | Text cut to 400 characters, only a literal password placeholder masked, only a remembered Yes skips the question. | The open-URL routine (spec MOD-08 review) |
| SC-05 | On macOS the hide call always reports success, so the failure warning never shows. | The macOS window helper |
| SI-06 | Relock after Auto-Type option (off) added. | The settings table |
| SI-11 | Current vault only, unless the search-all-vaults option is on. | The bridge one-time code handler |
| SI-12 | Lock and the generator also need no association; the entry list is source only. | The bridge request handlers |
| SI-10, SI-13, SN-02 | Source-only behavior marked. | Change log |

Blocking items sent to the lead, now ruled and applied (spec/decisions.md LD-57, LD-61, LD-63, LD-64, LD-65, LD-67): recycle bin entries kept out of search and Auto-Type only by group flags (SD-05, SI-06); SSH agent turned off removes only keys marked for removal (SI-07); the shared-groups signing key is kept unencrypted in the settings file and a share import can move or overwrite entries anywhere in the vault (SI-09); icon requests keep the user name and password written in the entry URL (SN-02).
