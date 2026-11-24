# FIL-05 Encrypted-folder screens and flows

Status: **DRAFT, 2026-11-05; second Spec and independent Verify pending**.
Epics: E23-S4, E23-S5, E23-S6
Parity: proposed FOLD-P3/P4/P5, all runtime todo.

## What it does

Larsal's own window creates/unlocks/browses an encrypted folder and adds, opens, saves out, renames and deletes files and folders. It can use its own password without an open password vault, or an explicitly chosen password kept in one. Finder is a separate S5 integration. [Research](../research/encrypted-folders.md) supplies public F01–42 and unadopted R1–7; behavior below does not grant new API crossings or weaken original acceptance.

## Inputs and outputs

Explicit root/source/destination selection, secure password input or opaque protected-entry selection, node/session generations and lifecycle signals. Swift holds cleaned plain-text names, sizes/status and opaque handles. Rust owns all retained credentials/content. Password-entry UI uses existing secure fields and the named transient input review, never an all-vault password list or persistent Swift secret. Demo names in static frames are illustrative.

## Rules

FIL-05.1 File menu has New Encrypted Folder… and Open Encrypted Folder…; welcome view offers both. A folder opens only after explicit selection, no automatic root detection, recursive home scan or downloaded-key fetch. Existing vault/attachment/E22 drops retain their routing; the folder's dedicated Add Files drop target is separate. F15, APP-08/R1.

FIL-05.2 Create chooses a parent and new folder name, shows storage location and classic profile help, then Own Password or Generate and Save in Vault. Never convert/delete/encrypt an existing source folder in place. Exclusive new root creation, initialize with journal; on failure preserve originals, remove only proven owned incomplete objects or surface cleanup failure. FIL-06.6/.7, F37/F38/R1/R4.

FIL-05.3 Own Password uses secure password/repeat, length/strength and mismatch help; weak confirmation has Cancel default. Optional Save in Vault is explicit and on only when a writable unlocked vault exists. Generated-and-saved mode requires writable vault/group/title and durable protected-entry save before root publication; cancellation after save keeps that entry and says so. Never infer/use the master password. FIL-01.6, APP-05/R5/R6.

FIL-05.4 Unlock has two explicit choices, Folder Password and Choose from Vault…. Selection is bound to protected entry id/revision and vault/session generation; if that vault is locked ask its normal unlock first, Cancel changes nothing. Manual password works with all password vaults closed. No Touch ID/Keychain shortcut or remembered password is invented; the folder stays locked on failed/cancelled/late unlock. APP-02/06/11, LD-220/R5.

FIL-05.5 Unlocked list has breadcrumb, Up, Refresh, Add Files…, New Folder…, Open, Save Out…, Rename…, Delete… and Lock Folder. Show per-item type/size/storage-time labels accurately; storage dates are untrusted observations, not authenticated author times. Selection uses opaque IDs plus revisions, never a path made from displayed text. Empty state is a working Add/drop target; selection-dependent controls disable with named help. F15/F04/R4.

FIL-05.6 Add accepts explicitly selected regular local files and a bounded explicit folder-tree import, preserving originals. Preflight each name/type/collision and show count/size; links/packages/devices/unknown remote URLs fail visibly, no archive or mount inference. Same-name item offers Keep Both or Cancel, never silent overwrite. Partial batch completion lists completed/pending items; cancellation removes only the active uncommitted owned item and retains completed encrypted items. FIL-06.2/.3/.6/R4.

FIL-05.7 Open is a required functional action, not replaced with unsupported. Before each external handoff show “Another app will receive a readable copy. It may keep its own copies after you close the file or lock Larsal.” Cancel default; Open Copy explicitly authorizes the selected revision and app. Authenticate fully before materialization/launch. No automatic launch on selection, extension, unlock, drop or success; no shell/URL command interpretation, Quick Look/thumbnail/background preview or clipboard. F36, APP-10/R2/R3.

FIL-05.8 Opened Files panel tracks every managed copy, selected encrypted revision, changed/unchanged state and Finish with Copy. On a stable external edit, ask Save Back as New Version, Save Out…, or Cancel; saving back uses current-base recheck/conflict preservation, never an unnoticed overwrite. Managed Finish offers save/discard only for this copy, then closes our handles and removes its owned path; actual external close cannot be inferred from process exit or presenter notification. No force quit/keystroke injection into another app. FIL-06.10/.15, F36/R3/R4.

FIL-05.9 “Closed”, “removed” and lock success must describe proven owned custody only. Original E23-S4 no-readable-copy-after-close and lock-closes-files checks remain unchanged and OPEN, with exact R3 amendment proposal external. A cleanup failure displays MSG-FOLDER-CLEANUP and fails that check; third-party saved copies/descriptors/backups are never claimed erased. Cancel after an external handoff cannot recall custody. F31/F36/R3.

FIL-05.10 Save Out… asks for a new filename/destination and states “This saved copy is not encrypted. It stays after Larsal locks.” No overwrite or decrypted filename-to-path instruction. Whole-input validation and exclusive output ownership precede release under FIL-06; success offers Done and selected path as plain text, no automatic reveal/launch. F37/F38, FIL-03/R2.

FIL-05.11 Rename… works on file or folder, with named secure-content-free name field, live invalid/collision help and Cancel default on collision. New Folder… uses the same name validation. Delete… names selected item/count, warns cloud history may retain it and offers Cancel default/Delete. Empty-folder deletion and nonempty recursive deletion require explicit scope/count review and FIL-06 journal/recovery; deleting an unknown/unreadable/link node is not automatic repair. No secure-delete text. F02/F28, FIL-06.2/.12/R4.

FIL-05.12 Show separate progress phases: Preparing encrypted copy, Checking file, Adding encrypted file, Saving readable copy, Saving changes and Removing managed copy. Known phase bytes/counts use bounded progress; unknown hydration is indeterminate with “Waiting for this file to download.” Cancel remains available; no 100%/success before sync/close/journal/cleanup. UI stays responsive; no guessed ETA or background retry forever. FIL-06.8/.16/.17, APP-05/R7.

FIL-05.13 Conflict view states “Both versions are kept. Choose how to keep them.” Show names/revisions and storage dates as untrusted; Keep Both default, Save Selected Copy… and Cancel. Deletion/edit conflicts say deletion is pending and retain the edited file. Do not choose a winner by clock or offer one-click destructive Replace in this draft. Recovery view names retained ciphertext revisions and separate explicit discard review; no plaintext or password shown. FIL-06.10–.14/R4.

FIL-05.14 Explicit lock/all-lock, enabled idle/screen-lock/sleep/user-switch/minimize triggers, quit, folder close/switch, password-vault close/switch/lock, credential/draft/root replacement all revoke outstanding work before any save/unlock question. This includes own-password folders with no password vault and pending KDFs. Hide names/content/secret input immediately, invalidate generations, prohibit new writes/launches/completions, wipe workers at safe boundaries, clean owned copies without waiting for another app. An already issued OS call may finish; no auto-resume after wake/unlock. Sleep handler must establish revocation before returning; pending synchronous KDF wipe timing remains explicit. APP-02/11, FIL-06.8/R3/R5.

FIL-05.15 Every input has persistent label/error association; every action has an accessible name, keyboard path and visible focus. List rows convey selection/type/status without color alone, multi-select and Delete require deliberate review. Return never confirms weak/external/delete/discard danger; Escape cancels. VoiceOver announces phase/error/coarse progress at≤1Hz, no names/password/content in notifications or logs. Restore focus to invoker after cancel; actual native accessibility proof remains S4. APP-08/10, Option A/R5.

FIL-05.16 Reuse locked Option A components/tokens in both themes; new frames are isolated additions to proposals.html only. Stable error/progress space, readable wrapping, no decorative animation needed. Reduce Motion gives equivalent static progress, live changes do not restart work. Every created Larsal window applies APP-10's legacy capture-property/readback/secure-input behavior with the stated OS capture limit; no guaranteed screenshot exclusion. APP-10/R5.

FIL-05.17 Finder cases stay E23-S5, after S4,D7,W-02: signed same-team File Provider extension, reviewed app-group/IPC/entitlements and opaque session-bound Rust authorization. macOS11+ API fits macOS14; materialized content/cache/indexes need actual custody/lock tests. Remove/hide location content on lock and reject stale fetch/edit callbacks, test existing open descriptors/offline copies and deletion conflicts; a removed icon alone is not PASS. FSKit is a later user-space alternative available15.4+, no deployment-baseline change or kernel extension. Exact entitlement/signing/distribution proof remains OPEN; no account/extension install here. F30–35/R6.

FIL-05.18 Foreign folder created by a conforming approved peer uses the same unlock/list/Open/Save Out/add/rename/delete success flows; reverse direction is independently required. Display compatibility help and limits at creation/unlock: “Names and file contents are encrypted. File counts, sizes and dates are visible to storage. Anyone with the encrypted folder can test password guesses. Keep a backup.” Include replay/object-swap and external-copy limits in accessible Details. All original runtime capabilities remain OPEN, no success-by-refusal or unsupported format migration. FIL-04.14/.15, F04/F05/F15/R1/R6.

## Test cases

All cases are future obligations, **OPEN**. Static frames prove layout/text only.

| Case | Rule | Given / action | Expected proof |
|---|---|---|---|
| FIL-05-T01 | FIL-05.1 | All password vaults closed; menu/welcome and ordinary drops | Both folder actions reachable; dedicated drop routing preserved; no ambient scans/download. |
| FIL-05-T02 | FIL-05.2 | New parent/name versus existing root/symlink/racing root/full disk | New demo initializes/reopens; existing bytes untouched; incomplete owned cleanup or explicit failed cleanup. |
| FIL-05-T03 | FIL-05.3 | Own/generated mode, mismatch/weak choice, password-vault save failure | Valid modes create; mismatch blocks, weak needs nondefault consent; generated root not published before durable credential save; saved entry retained after later cancel. |
| FIL-05-T04 | FIL-05.4 | Manual standalone and explicit protected-entry selection; locked vault/revision change | Both valid modes unlock; normal unlock respected; stale/failed/cancelled generation cannot open folder. |
| FIL-05-T05 | FIL-05.5 | Empty and nested demo folder, no selection, changed item | All controls/breadcrumb and empty target work; stale ID cannot operate on replacement; timestamps labelled storage observations. |
| FIL-05-T06 | FIL-05.6 | Regular file/tree batch with collision/link/device, cancel midbatch | Positive imported bytes exact, originals unchanged; preflight errors visible; keep both deterministic, completed items retained and incomplete owned item removed. |
| FIL-05-T07 | FIL-05.7 | Selected valid demo document, bad last tag, user Cancel/Open Copy | Cancel never materializes/launches; invalid ciphertext0 plaintext; valid deliberate handoff receives exact bytes after warning. |
| FIL-05-T08 | FIL-05.8 | External copy changed while remote base changes; Finish | Stable edited data saved as new/conflict revision or explicitly saved out; no clock overwrite, no inference of external close or app force quit. |
| FIL-05-T09 | FIL-05.9 | External retained descriptor/autosave; cleanup denied | Original closure limitation demonstrated; owned residual produces warning/failure, never “no copies”; no false S4 PASS. |
| FIL-05-T10 | FIL-05.10 | Save Out to new path versus sentinel/link/path swap/corruption | Good exact output persists after lock; sentinel untouched; corrupt initial input0 plaintext writes; no automatic app launch. |
| FIL-05-T11 | FIL-05.11 | File/folder rename/create/delete, invalid/collision/nonempty/unknown node | Valid actions work; Cancel default on destructive review; names and scope exact; durable recovery before removal, no secure erase claim. |
| FIL-05-T12 | FIL-05.12 | Large work, unknown hydration, stalled OS call, final sync error | Correct phase/progress/Cancel and no premature100%; UI acknowledgment measured, no invented ETA or hidden infinite retry. |
| FIL-05-T13 | FIL-05.13 | Two versions and delete/edit; recovery nearing quota | Both accessible, Keep Both default; deletion pending; review/discard explicit, no silent winner/prune. |
| FIL-05-T14 | FIL-05.14 | Manual standalone folder and vault-backed folder, every trigger during KDF/capture/write/launch/completion | Same immediate revocation/masking and no new effect in both; stale callbacks rejected, own copies cleaned or failure shown; no auto-resume; in-flight-call limits recorded. |
| FIL-05-T15 | FIL-05.15 | Native keyboard/VoiceOver/multi-select/error/secure field | Reachability,names,focus,announcements and danger defaults verified without leaked content; S1 HTML does not pass this. |
| FIL-05-T16 | FIL-05.16 | Every proposed state, both themes, Reduce Motion before/during work | Static layout parity; future native lifecycle/property/input proof separately recorded; actual capture results remain OPEN. |
| FIL-05-T17 | FIL-05.17 | Signed Finder location; materialized/dataless/open file,lock/restart/stale callback | Read/write functional before lock; content hidden and new fetch/edit denied after; cache/descriptor limits accurately recorded; D7/W-02 and native proof not waived. |
| FIL-05-T18 | FIL-05.18 | Approved foreign folder/profile and Larsal-created folder | Each successful frontend action and both peer directions proven; leakage/limits/details accessible; no runtime PASS from refusal. |

## Messages and frames

FIL-06 owns exact errors. New light/dark frame IDs under `e23-s1`: `entry`, `create`, `own`, `weak`, `unlock`, `vault`, `list`, `empty`, `add`, `open`, `opened`, `finish`, `discard`, `details`, `saveout`, `rename`, `delete`, `progress`, `conflict`, `recovery`, `error`, `cleanup`, `locked`, `finder`, `complete`, `names`, `limits`, each prefixed `e23-s1-`. Static illustrations execute no crypto, filesystem, clipboard, launch, mount or network operation. The Finder frame is a later-state proposal, no S5 sign-off. Owner frame review is nonblocking under LD-268/363. R2/R3 are exact unresolved acceptance conflicts, not hidden amendments.

## How this was learned

Public primary platform/design documentation and existing APP-02/05/10/11/FIL-01–03 were read to preserve local patterns and boundaries. No reference access, product build, visible window, actual external-app handoff or native proof.
