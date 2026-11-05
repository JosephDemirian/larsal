# FIL-02 Screens and flows

Status: **reviewed, 2026-11-05 (E22-S1 specification and static proposals only)**; second Spec corrections and fresh independent Verify approved; exact source adopted in `c8fa2f1`.
Epics: E22-S4, E22-S5, E22-S6
Parity rows: FILE-P1–FILE-P4 (all todo; runtime proof OPEN). Existing SF/SR/SD rows are not signed by this card.

All rules are security relevant unless explicitly visual. Source references S01–S20 and R1–R6, recorded as LD-366–371, are in [research](../research/file-encryption.md). Second Spec corrections and fresh independent Verify approved the exact specification/static proposals; source adoption is `c8fa2f1`. Original dependencies, required technical/sensitive reviews and E22-S2 AT-J03/download gates govern implementation. All runtime cases below remain OPEN in implementing stories. Historical submission wording in unchanged rules/cases does not change current review status. Proof: the research [Review and proof](../research/file-encryption.md#review-and-proof) footer.

## What it does

A single-file local flow from the File menu or a dedicated drop target. Encrypted output is saved to a chosen new path; decryption saves only to the final path the user requests. No automatic upload, launch, clipboard or plaintext preview.

## Inputs and outputs

Inputs are explicit file selections, destination selections, credential entry/opaque vault selection and cancel/lock signals. Public progress is phase and byte count, not file content. Public filenames are untrusted plain text; they are never embedded output paths from ciphertext. Proposal illustrations use demo data only.

## Rules

FIL-02.1 File ▸ Encrypt File… and File ▸ Decrypt File… are available with a vault locked, but default generated-and-saved encryption first requires an unlocked writable vault. Unlock/New Vault is explicit; cancel returns without output. Decryption can use a manual phrase/key file without a vault. Do not bypass ordinary unlock. (Basis: APP-06/08, LD-337, R4.)

FIL-02.2 A dedicated Encrypt a File drop target accepts exactly one local regular file; dropping on it opens the encrypt sheet, never runs the file. A dedicated decrypt target/menu chooser opens decryption. Existing vault-open/attachment drop routing stays unchanged. Multiple files, folders/packages, links, remote URLs and devices are refused in place, no inferred archive/download. (Basis: AT-E06, R4.)

FIL-02.3 Encrypt sheet shows source basename/size, Passphrase or Recipients choice, destination name/folder and original-preservation note. Generated passphrase is the default, Rust-owned and masked; no whole password in Swift view state. A Show control deliberately requests the one selected value and follows existing Show/Hide/lock rules. No new Copy button. (Basis: FIL-01.6, APP-10, R4.)

FIL-02.4 Choose Destination uses the ordinary save panel but commits only a new name. Encrypt suggests basename.age; changing to a neutral name is available because the original name leaks. Decrypt strips one final .age/.asc only for a suggestion; otherwise suggests Decrypted file. Suggestions are not trusted paths or format detection. (Basis: S01/S19, R4.)

FIL-02.5 Default encryption requires choosing writable vault/group and entry title, default File passphrase · cleaned basename. Password is protected; notes identify purpose, not a secret duplicate; full filesystem path is not saved by default. Save passphrase as entry is on and required for this mode. Confirm actual vault persistence before writing ciphertext; do not treat a queued save as durable. (Basis: LD-337, MOD-01/APP-05, R4.)

FIL-02.6 If default credential entry saves and file encryption later fails/cancels, keep that saved entry and show Passphrase saved; no encrypted file was completed. Do not silently delete an entry, auto-generate a different phrase or overwrite an older entry on retry. Reuse requires an explicit existing-entry selection; a new generation makes a new entry. (Basis: APP-05, R4.)

FIL-02.7 Choose My Own Passphrase offers secure input/repeat, optional Save as Entry on by default when a writable vault exists, and weak-phrase confirmation. If save is selected it must finish before encryption. Turning save off is explicit and warns Losing this passphrase means losing this file. Do not put the phrase in argv, settings, logs or path. (Basis: FIL-01.5/.7, SR-06/13, R4.)

FIL-02.8 Recipients sheet supports Add Recipient, full public-key review, removal and an explicit Add My File Key recovery choice. Invalid/unsupported/too-many keys disable Encrypt with own-word inline help. No automatic key substitution/directory lookup. For recipient-only output require I understand I may not be able to decrypt this file when no selected key is held locally. (Basis: FIL-01.8–.10/.20, R4.)

FIL-02.9 Create File Key is an explicit secondary action requiring an unlocked writable vault. Show its public recipient only after protected private-key entry is durably saved; allow the public key to be selected as plain text. No private export or network share action in this flow. (Basis: FIL-01.17, R4.)

FIL-02.10 Decrypt sheet accepts any selected file; magic/armor parsing in Rust decides format, never extension. Password and File Key credential modes are explicit; Choose from Vault selects a protected value/identity by opaque id; Choose Key File uses only that path. Encrypted identity prompts are separate and never substitute the data passphrase. (Basis: FIL-01.14–.16, APP-06, R1/R4.)

FIL-02.11 The decrypt sheet always says Save a readable file and The saved file is not encrypted. Keep it somewhere private. Save panel confirmation authorizes that one final output; no automatic app-open, Quick Look, shell/URL launch, thumbnail or image decoding. Success exposes Done and the chosen path as text only. (Basis: S09, SD-07, R4.)

FIL-02.12 Progress has separate Preparing encrypted copy, Checking the whole file and Saving readable file phases for candidate decryption; encryption shows Saving passphrase then Encrypting file. Phase-local completed/total counts, unknown total indeterminate. Do not show100%/success before EOF checks, write/sync/close and cleanup finish. (Basis: S10, research5/6, R2.)

FIL-02.13 Cancel is present throughout; Escape before commit requests cancel. Operation/session revocation is immediate, blocks future output and ignores late callbacks. Check cancellation before/after KDF and each chunk/write; synchronous KDF may finish before worker cleanup. On handled cancellation remove only an owned incomplete final file; cleanup failure stays visible and fails the original S4 cancel-leaves-no-partial-output check. A committed complete output is retained. An I/O call already handed to the OS may finish; revocation cannot recall those bytes. New write starts require synchronized operation authorization, not a flag check followed by an unsynchronized write. (Basis: APP-02, research5/7, R2.)

FIL-02.14 A lock request, enabled sleep/screen-lock/user-switch trigger, vault close/switch, quit or credential/draft replacement revokes the active Mac file operation before any save/unlock question, including an operation using a manually entered passphrase or explicitly selected identity file without an unlocked vault. Close secret fields immediately; wait only for safe worker cleanup, never keep UI unlocked. No operation auto-resumes after unlock. Standalone CLI operations obey signal rules separately. (Basis: APP-02, SR-16, R2.)

FIL-02.15 All controls have persistent labels, keyboard order source→mode→credentials→destination→Cancel→action, named secure fields and visible focus. Return runs primary only when valid, never confirms weak/save-off/recipient-only danger; Escape cancels. VoiceOver announces phase changes and coarse progress without secrets, at most once per second, errors immediately, and restores focus to invoker. (Basis: APP-08, AT-K06, R4.)

FIL-02.16 Use existing Option A dialog/field/button/progress tokens in light and dark. No layout jump on errors/progress. No animation is required for file work; any sheet appearance uses platform/default restrained chrome only. Reduce Motion removes decorative movement/spinner rotation and leaves static status text/progress. Live preference change never resets work. (Basis: Option A BUILD-AND-VERIFY, R4.)

FIL-02.17 One operation at a time; a second open/drop/menu request reports A file operation is already running, without replacing selection or credential. Closing its sheet requests cancel and waits for cleanup result before re-enabling actions. A second process must not collide with scratch/destination ownership. (Basis: research6, R3/R4.)

FIL-02.18 CLI grammar proposed: larsal encrypt INPUT --output OUTPUT (--generate --vault VAULT --group GROUP --title TITLE | --passphrase | --passphrase-file FILE | --passphrase-entry ENTRY --vault VAULT | --recipient KEY [--recipient KEY…]); larsal decrypt INPUT --output OUTPUT (--passphrase | --passphrase-file FILE | --passphrase-entry ENTRY --vault VAULT | --identity-file FILE | --identity-entry ENTRY --vault VAULT). Require exactly one credential mode and explicit output; --generate saves first. No overwrite/force/stdout shortcut or implicit credential source. (Basis: INT-10, E22-S5, R1/R4.)

FIL-02.19 CLI --passphrase prompts on the controlling terminal with echo off, encryption asks twice; noninteractive mode needs an explicitly named passphrase file or vault entry. Read file bytes as UTF-8, strip exactly one final LF and its preceding CR, preserve all other bytes including spaces/NUL; reject invalid UTF-8/empty/over-limit before work. Never accept literal passphrases in arguments or environment variables. Prompt/key-file prompt ignores --quiet, no echoed secret. (Basis: SR-13, INT-10, FIL-01.5, R4.)

FIL-02.20 CLI INPUT may be - for data stdin, which is distinct from credential transport: decryption captures ciphertext first; encryption streams stdin without plaintext staging. Reject data/password simultaneous stdin; no automatic regular-file seek assumption or terminal input guessing. Ciphertext/clear output must use a named new file in this proposal. Required app↔CLI interoperability is unchanged. (Basis: S10, R2/R4.)

FIL-02.21 CLI success exits0 only after committed completed output; errors1, usage2, handled cancel130; ordinary quiet suppresses progress only. stderr uses FIL-03 own words, no upstream text/paths/secrets. Signal guard records SIGINT/TERM/HUP/QUIT, revokes, cleans, restores echo, then terminates consistently with platform conventions; signal termination is reported as such rather than faking an ordinary exit130. (Basis: INT-10, platform signals, R2/R4.)

FIL-02.22 The sheet states: No server is contacted. Anyone with this encrypted file can test passphrase guesses. The original file stays where it is. Names, sizes and dates may still be visible. Recipient mode adds This does not prove who sent the file and classical quantum warning. A lost credential cannot be reset. No absolute never-lost/never-decryptable/secure-delete wording. (Basis: FIL-01.20–.22, S09/S17, R6.)

FIL-02.23 Bind chosen source descriptor, destination parent/name, credential entry id/revision, vault generation and operation generation at confirmation; changing any cancels or requires a fresh confirmation. Do not apply foreign ciphertext metadata as instructions, save paths, vault edits or external commands. (Basis: AT-E03/06, S19, R2/R4.)

FIL-02.24 Opening a file from another conforming tool is a required path, not replaced by a format-not-supported screen. Foreign binary/armor, empty/large data and encrypted native identities get the same success/error/lifecycle flow. Unsupported profiles remain a documented compatibility limit and OPEN wider scope, never counted as foreign-file success. (Basis: E22-S1/S3/S5, S04/S11, R1/R5.)

## Test cases

| Case | Rules | Given | When | Then |
|---|---|---|---|---|
| FIL-02-T01 | FIL-02.1 | locked app | choose Encrypt, then cancel unlock; choose Decrypt | encrypt writes nothing; independent manual decryption remains available |
| FIL-02-T02 | FIL-02.2 | image, vault, two files, directory, URL dropped on each explicit target | drop | one ordinary file confirms its selected operation; other kinds clear input error and no execution |
| FIL-02-T03 | FIL-02.3 | demo image and default choice | open sheet/Show/Hide | metadata visible, secret masked by default, only authorized Show temporarily crosses, no copy/preview |
| FIL-02-T04 | FIL-02.4 | photo.jpg, photo.jpg.age, hostile name with controls/separators | choose destination | cleaned basename suggestion in chosen folder; full source retained; no traversal |
| FIL-02-T05 | FIL-02.5 | generated secret and vault save fails/full disk | press Encrypt File | no output before protected entry save succeeds; failure explains retry, no unsaved-key success |
| FIL-02-T06 | FIL-02.6 | saved entry, later destination I/O failure | retry/cancel | saved entry remains; incomplete output handled by FIL-03; exact credential selection is visible |
| FIL-02-T07 | FIL-02.7 | manual demo phrase with repeat mismatch/weak strength/save-off | continue | mismatch blocks, weak confirmation has Cancel default, save-off warning required; no accidental credential loss claim |
| FIL-02-T08 | FIL-02.8 | two valid recipients including local recovery, then recipient-only list | encrypt | keys reviewed, local recovery explicit; recipient-only acknowledgement checked before work |
| FIL-02-T09 | FIL-02.9 | new key and simulated vault save failure | Create File Key | private key never enters UI; success offers public recipient, failure neither loses nor uses an unsaved identity |
| FIL-02-T10 | FIL-02.10 | foreign file with arbitrary extension and valid native credentials | Decrypt File | bounded support works under same profile; no import of all vault values or key discovery |
| FIL-02-T11 | FIL-02.11 | demo encrypted image/executable/text | decrypt successfully | only exact readable bytes saved; no handler launch or preview, no safety/provenance claim |
| FIL-02-T12 | FIL-02.12 | 4GB demo, unknown-length input, later final-tag error | operate | responsive phase/status, no time estimate invented and no early success; all runtime proof OPEN |
| FIL-02-T13 | FIL-02.13 | cancel during preparation/KDF/validation/final write/after commit | cancel | no new write authorized after revocation; an in-flight OS write may finish; before commit no owned incomplete output may survive for S4 PASS, a cleanup warning records failed cancellation; after commit file remains |
| FIL-02-T14 | FIL-02.14 | vault-derived operation, manual-passphrase operation with every vault locked, and selected-identity-file operation with no vault; lock/sleep during final write or queued completion | deliver each enabled lock/sleep/screen-lock/user-switch trigger and explicit lock/close/switch/quit/replacement | UI closes/masks at once for all three, generation invalidated, no new write authorized, late success suppressed, no automatic resume; synchronous KDF wipes at its safe boundary; surviving owned incomplete output fails handled cancellation even when warned |
| FIL-02-T15 | FIL-02.15 | keyboard-only/VoiceOver, hidden password, invalid recipient | walk flow | every action reachable/named, error association/focus correct; actual native VoiceOver proof OPEN |
| FIL-02-T16 | FIL-02.16 | both themes, Reduce Motion before/during progress | render/use | content legible and static states equivalent; illustrative frame review is not native runtime proof |
| FIL-02-T17 | FIL-02.17 | two overlapping operations/processes selecting same output | start both | one in-process active; cross-process exclusive create permits at most one destination owner |
| FIL-02-T18 | FIL-02.18 | missing/output/mixed credential flags or secret-looking positional extra | parse | usage error before opening/deriving; valid command uses same Rust operation as app |
| FIL-02-T19 | FIL-02.19 | TTY, no TTY, password-file CRLF/multipleLF/space/NUL/huge | provide credential | exact documented bytes; no TTY returns input error; secret never appears in argv/env/stdout/log |
| FIL-02-T20 | FIL-02.20 | pipe input with explicit credential file, then missing credential TTY | run | bounded flow or clear usage error, no competing stdin consumers; no plaintext emitted to terminal |
| FIL-02-T21 | FIL-02.21 | broken stderr/destination writer/interrupt while echo disabled | run | failure propagated and echo restored; never success after failed checked write/close/cleanup |
| FIL-02-T22 | FIL-02.22 | every creation/decrypt/success view | read/help | accurate mode-relevant limits visible and accessible, no guaranteed anonymity/provenance |
| FIL-02-T23 | FIL-02.23 | entry edited, source/parent swapped, old callback delivers | continue | old generation cannot write/show completion or select a different key |
| FIL-02-T24 | FIL-02.24 | separately approved age1.3.2 classical-profile fixtures: generated/manual passwords, multiple X25519 recipients, binary/armor reads, native/encrypted identity files, empty/binary/large/4GB demo data | open in app and CLI; reverse direction with age1.3.2 and app↔CLI | byte-identical successful foreign-file round trips required in S3/S4/S5; Rust age0.12.1 is a studied library alternative, no runnable Rust peer requested; any addition needs a separate itemized reviewed request; no runtime result in this DRAFT |

## Messages and proposal frames

FIL-03 owns errors. Frame IDs under `e22-s1` in proposals.html: `e22-s1-entry`, `e22-s1-encrypt`, `e22-s1-manual`, `e22-s1-recipients`, `e22-s1-key`, `e22-s1-decrypt`, `e22-s1-progress`, `e22-s1-complete`, `e22-s1-error`, `e22-s1-collision`, `e22-s1-cleanup`, `e22-s1-locked`. Both themes are required. Frames are layout illustrations, not encryption, native dialog, keyboard, accessibility, lifecycle or interop proof. Owner frame review is pending and nonblocking under LD-268/363; locked design sources stay byte-identical.

## Lead decisions and security notes

R1–R6 are recorded as LD-366–371 (reviewed specification only). R2 retains the original corruption and cancellation acceptance with a separate later I/O/crash boundary; candidate custody and cleanup need implementation proof. R6 records already-authorized local export to owner-chosen USB/cloud/email, no E22 service path and every unchanged LD-340 Larsal-service obligation. A future Larsal storage/service route needs a reviewed LD-340-compliant design. Secret input uses existing secure entry paths and clears transient input promptly; new FFI exports/crossings need named sensitive review and API documentation in their implementation story. This card grants no durable Swift secret copy or new broad Show eligibility. Native vault-independent lock-event wiring also needs implementation proof.

## How this was learned

Public standards and official library/implementation documentation only, linked in the research evidence register. Existing Larsal cards and source were read to preserve boundaries and reuse approved behavior. No reference access, translated implementation, package installation or runtime encryption evidence.
