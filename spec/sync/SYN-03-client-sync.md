# SYN-03 Client sync and the rollback guard

Status: reviewed
Epics: E16-S7a (the loop, its timing, the rollback guard, the status), E16-S7b (the key-file part, the key-change cases), E15-S2 (the merge it calls), E16-S9 (the screens and words), E17-S1 (upload signatures, the wrapped key-file part)
Parity rows: SD-03 (App goes further: the newer key and the deletion pass in server sync). App's own rows: SV-01 to SV-03 (plan/security.md); AT-L01, AT-L04, AT-L08 (plan/attacks-and-checks.md)

## What it does

App keeps a vault in step with its copy on App's server. A run downloads the server copy, merges this Mac's open vault into it with MOD-11 (a same-vault merge, so deletions stay deleted and the newer key wins), saves the result on this Mac and uploads it with `If-Match`. If another Mac uploaded first, the server answers 412 and App tries again, at most 3 times in all. Local state that never leaves this Mac refuses a server copy that went back to an older version.

A vault put on the server gets a second secret: a random key-file part, so nothing on the server can be guessed from the master password. When the server copy opens with other credentials (a password changed on another Mac), App asks for the credentials that copy opens with and uploads nothing until it opens.

Other cards: SYN-01 owns the routes, SYN-04 sign-in, MOD-11 the merge (its Notation holds the one meaning of "same vault"), MOD-11.31 copies under a retired key, APP-05 the local save and APP-05.26 the rollback guard for the local file, SYN-06 the wrap of the key-file part from E17-S1.

Design and sources: spec/research/sync-server.md P2, P3, P4, P7 (decided: spec/decisions.md LD-263 (2), (3), (6), LD-264, LD-265, LD-267 (2), LD-269 (2) to (4), LD-273 (1), (3), (5), (9)).

## Inputs and outputs

- In: an unlocked vault linked to a server vault; the pinned server (SYN-01.2); a session (SYN-04); the triggers of SYN-03.4.
- Out: the merged vault, saved on this Mac and uploaded; the state of SYN-03.3; the status of SYN-03.13 and the messages below.
- Limits: the vault limit of SYN-01.10; at most 3 tries per run (SYN-03.6).

### Messages

| ID | Words (App's own) | Buttons |
|---|---|---|
| `MSG-SYNC-FINGERPRINT` | Check that this code matches the code the server printed: <fingerprint> | They match (default), Cancel |
| `MSG-SYNC-CERT-CHANGED` | The server "<address>" shows a different certificate. App stopped syncing with it. | OK |
| `MSG-SYNC-NOT-SERVER` | "<address>" is not an App sync server. | OK |
| `MSG-SYNC-OTHER-KEY` | The server's copy of "<vault name>" opens with another password or key. Enter the password or key this copy opens with. | the unlock sheet (APP-06): Open, Cancel |
| `MSG-SYNC-OLD-KEY` | The server's copy of "<vault name>" uses a password or key that was replaced on this Mac. | Skip (default), Merge anyway |
| `MSG-SYNC-OTHER-VAULT` | The server's copy is a different vault. Nothing was merged or uploaded. | OK |
| `MSG-SYNC-ROLLBACK` | The server sent an older copy of "<vault name>" than this Mac has seen. Nothing was merged or uploaded. | OK |
| `MSG-SYNC-WENT-BACK` | The server's copy of "<vault name>" went back in time. App merged it, so nothing newer was lost, and uploaded the result. | OK |
| `MSG-SYNC-WEAKER` | The server's copy of "<vault name>" used <setting> weaker than this Mac has seen. | OK |
| `MSG-SYNC-BUSY` | The server's copy kept changing. App will try again at the next sync. | none (status line) |
| `MSG-SYNC-SIGNED-OUT` | This Mac is signed out of "<address>". | Sign In, Cancel |
| `MSG-SYNC-NO-WRITE` | You can't change this vault on the server. Your changes are kept on this Mac. | OK |
| `MSG-SYNC-GONE` | The server no longer has "<vault name>". Your copy on this Mac is unchanged. | OK |
| `MSG-SYNC-TOO-LARGE` | "<vault name>" is too large for the server. | OK |
| `MSG-SYNC-ERROR` | Sync with "<address>" failed. Your copy on this Mac is unchanged. | none (status line) |

## Rules

SYN-03.1 **Putting a vault on the server** (P7). For an unlocked vault the user puts on a server:
1. A vault without a key file gets a random 32-byte key-file part `F` from app-crypto's random source, added through the credential change (MOD-12.10, FMT-04.3, FMT-04.5): the master password and any hardware key stay; `MasterKeyChanged` becomes now; App saves the vault on this Mac (APP-05). A vault that already has a key file gets no second part (FMT-04.5 has one key-file slot): the `F` of that key file (the output of FMT-18) is the part that goes with the vault.
2. `F` goes into the device store for this server vault (SYN-04.1's store; this device only once W-02 is answered), as `SecretBytes`. It is never written into the vault, the local state file, a log or the pasteboard.
3. App draws a `vault_id` (SYN-01.6) and uploads the saved file with `If-None-Match: *`; on 201 it writes SYN-03.3's state.
From E17-S1, `F` is also wrapped to the account's own key (SYN-06.9), so the other Macs of the account get it from the server. Before that, the E16-S7a test helper puts it into the second test client's device store (tests only, LD-266 (2)).

SYN-03.2 **The server vault on another Mac.** The user picks a vault from `GET /v1/vaults`; App downloads it, asks where to save it (the save panel; never over a file without the panel's own question), and opens it with the unlock sheet (APP-06), which takes `F` from the device store and asks only for the rest of the key, normally the master password. Then App writes SYN-03.3's state. Every later unlock of a linked vault takes `F` from the device store the same way, shown as "Key part kept for sync".

SYN-03.3 **Local state** (P4; app-sync `state.rs`; never synced, never in or next to a vault). Per server: its address and its pinned certificate fingerprint (SYN-01.2), written when the user adds the server, before any vault is linked (SYN-01.2, SYN-06.11 step 2, SYN-06.12). Per linked vault: the server it is linked to (it points to that server's entry); the `vault_id`; the local file (a security-scoped bookmark) and the vault's root group id; the highest version seen; the SHA-256 of the server bytes of that version; the newest change time (as APP-05.26 measures it), the file version and the KDF settings of the last server version this Mac accepted or uploaded (SYN-03.7); the SHA-256 of the local file right after the last run; from E17-S1 the upload signature last checked; for shared vaults (E18) the key epoch and the member list's sequence number and hash (SHR-01, SHR-02). This card also reads and updates two records other cards own: the retired-key records of MOD-11.31 and APP-05.26's rollback guard record for the vault, which guards the local file only (SYN-03.7). The state is written atomically (temp file and rename) with mode 0600 in App's settings folder. The highest version and the newest change time only move up; the file version and the KDF settings are those of the last server version accepted or uploaded. A link's values go only when the user removes the link (SYN-03.15).

SYN-03.4 **When a run starts** (P3; a hosted password manager's rhythm, spec/research/business-model.md 3.4). After the vault is unlocked; 2 s after a save (a burst of saves gives one run); every 60 s while the vault is unlocked; and on Sync now. Never while the vault is locked, saving, reloading or unlocking, has unsaved changes or an open editor, or a "changed on disk" event is pending (as APP-05.25): such a trigger waits, and the next save starts a run anyway. One run at a time per vault; a trigger during a run asks for one more run after it.

SYN-03.5 **A run.** One try is:
1. `GET /v1/vaults/{vault_id}` with `If-None-Match` set to the ETag of the highest version seen.
2. 304 (the server holds that version): when the local file's SHA-256 equals the one recorded after the last run, the run ends (Synced). Otherwise App uploads the local file's bytes with `If-Match` (step 4).
3. 200 with version `v`: the guard of SYN-03.7 first. Then App opens the bytes with this Mac's key (when they do not open: SYN-03.8). It merges the open vault (the source) into the server copy (the target), the way APP-05.27 Merge does: a same-vault merge by MOD-11's Notation, so the deletion pass runs (MOD-11.15) and the result holds the newer of the two keys (MOD-11.19 limit 2, LD-264). The merge, the replacement of the open vault by the result and the local safe save (APP-05) are one step under the vault's lock, as a save is. When the merge's change list is empty (this Mac had nothing the server copy lacks), App uploads nothing and records `v`, the server bytes' SHA-256 and the new local file's SHA-256. Otherwise it uploads the bytes it just saved with `If-Match: "v"`.
4. The upload answers 200 or 201: App records the new version and, for both the server and the local hash, the SHA-256 of the bytes it sent. 412: the next try (SYN-03.6). Any other reply: SYN-03.10.

For a shared vault, SHR-01.13 and SHR-03.12 replace SYN-03.8, SYN-03.9 and SYN-03.11, and SHR-01.14 keys every upload.

SYN-03.6 **Tries** (LD-263 (2); E16-S7a). A run makes at most 3 tries in all (P3's "retry at most 3 times" is read as 3 tries, as LD-263 (2) and E16-S7a's check word it). Before the 2nd and the 3rd try App waits a random time from 1 to 3 s (jitter, from app-crypto's random source), so two Macs that collided do not collide again. When the 3rd try ends with 412, the run stops with `MSG-SYNC-BUSY` in the status line; the next trigger starts a new run.

SYN-03.7 **Rollback guard** (P4, P18 (6); LD-267 (3), LD-269 (4)). Only local state stops a full rollback (ETH paper section 6, sync-server.md section 6).
- Before opening: a version lower than the highest seen, or the highest seen with other bytes (another SHA-256), is refused: nothing is merged or uploaded, App shows `MSG-SYNC-ROLLBACK` and the status is Error. The same holds when `GET /v1/vaults` lists a lower version: App downloads nothing.
- From E17-S1, a version whose upload signature does not verify by SYN-03.11 is refused the same way.
- After opening: App compares the copy, by APP-05.26's measures (the newest change time; the file version; KDF settings compared as in MOD-11.19 limit 1), with the values SYN-03.3 keeps for the last server version this Mac accepted or uploaded. It never compares a server copy with APP-05.26's record: that record also holds this Mac's own saves that were not yet uploaded, which no server copy can have. A copy whose newest change time is earlier than the stored one (an old file the server renumbered) is not refused, because the merge keeps everything newer: App merges it as step 3 says, uploads the result and shows `MSG-SYNC-WENT-BACK`. A copy with a lower file version or weaker KDF settings than stored is merged as step 3 says and only warns, as APP-05.26 does with `MSG-DISK-WEAKER` (LD-269 (4)): `MSG-SYNC-WEAKER` names the setting, never a value. The result's KDF settings follow MOD-11.19: the server copy is the target, so its settings stay when its settings time is newer (limit 1 guards only settings taken from the source), and this Mac's stronger ones are taken when this Mac's settings time is newer.
- After each version App accepts or uploads, SYN-03.3's values for the link are set from that version.

SYN-03.8 **The server copy opens with other credentials** (LD-264; MOD-11.29, APP-05.29). When the bytes give `WrongKey` with this Mac's key:
- App uploads nothing for this vault until the copy opens, and the status is Needs password.
- App shows the unlock sheet for the server copy with `MSG-SYNC-OTHER-KEY`. It asks for the password or key this copy opens with, never for "the new" one: the copy may be older or newer. The key-file part comes from the device store (SYN-03.2). On a 60-second tick App does not show the sheet again; the status line and Sync now do.
- The credentials open the copy: App first tests them against this Mac's retired-key records (MOD-11.31). A match goes to SYN-03.9. Otherwise, with the same root group id, the copy is the same vault (MOD-11's Notation: opened with credentials the user gave for that copy), and the try goes on at step 3's merge. When the result takes the copy's newer key, this Mac's old key becomes a key it retired (MOD-11.31). With another root group id, App shows `MSG-SYNC-OTHER-VAULT` and merges and uploads nothing.
- Cancel: nothing is merged or uploaded; the status stays Needs password.

SYN-03.9 **A server copy under a key this Mac retired** (LD-267 (2), LD-269 (3); MOD-11.31). App merges nothing on its own. It shows `MSG-SYNC-OLD-KEY` with Skip (the default) and Merge anyway; the 60-second timer never answers it, and the status is Uses a replaced password until the user does.
- Skip: nothing of the copy is taken. App uploads this Mac's vault with `If-Match` of the copy's version, so the server copy again has this Mac's key (the server keeps the replaced one as an old version, SYN-02.5).
- Merge anyway: MOD-11.31's content merge: this Mac's open vault is the target and the server copy the source (the other way round from step 3), never the copy's key, deletions or metadata. App saves and uploads the result.
Either way the result keeps this Mac's key, whatever the copy's `MasterKeyChanged` says, also one in the future. Why: a password change often follows a leak, so whoever knows the old password must not bring it back or change or delete entries without the user's click (LD-269 (3)).

SYN-03.10 **Other replies.**
- 401: App signs in again once (SYN-04.6) and repeats the try; a second 401 sets the status Signed out with `MSG-SYNC-SIGNED-OUT`.
- 403: `MSG-SYNC-NO-WRITE`; the changes stay on this Mac.
- 404 for a linked vault: `MSG-SYNC-GONE`; the link stays until the user removes it, and App never makes the vault again on its own with `If-None-Match: *`.
- 413: `MSG-SYNC-TOO-LARGE`.
- 400, 411 or 428: a protocol error (a bug on one side): `MSG-SYNC-ERROR`.
- 429: App waits `Retry-After`, at most 300 s, in place of SYN-03.6's random wait, before the next try; the try that got the 429 counts as one of the run's 3 (SYN-03.6). A 429 on the 3rd try ends the run with the status Offline, as a 5xx does; the next trigger tries again. A `Retry-After` that is missing or not a whole number of seconds (for example an HTTP date) counts as 300 s, and so does a whole number over 300, however many digits it has.
- A network error, a timeout, a TLS error other than a changed certificate, or 5xx: the status is Offline, with no message box; the next trigger tries again.
- A changed certificate: `MSG-SYNC-CERT-CHANGED` (SYN-01.2); no run for that server until the user acts.
In every case the vault on this Mac is never left half merged: either the merged result was saved (step 3) or nothing changed.

SYN-03.11 **Upload signatures** (from E17-S1; P4, P11). Every downloaded version must carry `Upload-Signer` and `Upload-Signature` that verify (CRY-04.3) over the SYN-01.7 field list built from the `vault_id`, the version the server sent and the SHA-256 of the bytes received, with a key allowed to write: for a personal vault, the account's own identity key, pinned at sign-up or at the approval of this Mac (SYN-06.6). Otherwise App refuses it as in SYN-03.7. Every upload sends its signature (SYN-01.7). Before E17-S1 the version and hash guard applies alone (P4).

SYN-03.12 **The key-file part stays in the key** (P3, P7). A credential change of a linked vault (MOD-12.10) keeps its key-file part; App offers no way to drop it while the vault is linked (Vault Settings shows "Kept for sync"). So when another Mac asks for the credentials the server copy opens with, the part is already in its device store. App can save the part as a key file through the save panel, so the vault opens in another app with the master password and that file (P7). This is the one exception to FMT-18.21's fresh bytes: the file holds the part already in the key, its own 32 bytes, in the XML 2.0 layout of FMT-18.20; FMT-18.20, FMT-18.22 (no overwrite, mode 0400) and FMT-18.23 (read back; `F` equals the part) apply.

SYN-03.13 **Status** (E16-S9). Per linked vault, one of: Synced (with the time of the last run that ended well), Syncing, Offline, Needs password, Uses a replaced password, Signed out, Error (with the message of the last failure). The status line shows it; Sync now starts a run.

SYN-03.14 **What leaves the Mac.** Only SYN-01's requests: the vault's encrypted bytes, ids, versions, sizes and signatures; from E17-S1 the wrap records of SYN-06. Never the master password, the key-file part, any private or secret key or anything from inside the vault in plain form, in any request, header or log.

SYN-03.15 **Stop syncing.** It removes this Mac's link for the vault from the state and nothing else: the vault keeps its key, its key-file part stays in the device store (the vault still needs it to open), and the server copy stays. Once the vault is no longer linked, a normal credential change may drop the part. A shared vault (SHR-01) offers no Stop syncing: its only key is the group's, so its way out is Leave (SHR-01.7, SHR-04.11).

## Edge cases and errors

- The vault is edited during a run's download: the run stops before its merge (SYN-03.4 forbids a run with unsaved changes), and the save that follows starts a new run.
- The server copy holds a deletion this Mac's vault does not: the deletion pass erases the entry here, unless this Mac changed or moved it after the deletion (MOD-11.15, LD-271 (2)).
- Both Macs deleted the same entry: one item for it stays in the result (FMT-15.11 step 2).
- A server copy with the vault's root group id under another password, given by the user, with an older `MasterKeyChanged`: the result keeps this Mac's key, and the other Mac asks for this Mac's key at its next run (MOD-11.19 limit 2).
- The local vault file is also in a cloud folder: APP-05's change-on-disk and conflict-copy rules apply to the local file as well; both paths are same-vault merges.
- 304 while the local file's SHA-256 changed only because App saved it again with a fresh seed (FMT-04.17): App uploads it once, as any local change; the next run sees 304 and equal hashes.
- The same `vault_id` linked on this Mac to two local files: refused at link time; one link per server vault per Mac.

## Security notes

- **Rollback (SV-02, AT-L01).** A hostile server can hold back, replay or renumber old versions. The version and hash guard refuses a lower or changed version; the newest-change-time compare catches an old file under a new number, and the merge keeps everything newer; from E17-S1 the upload signature binds the bytes to their version. Fork across Macs of one account: each Mac's guard only moves up, so a server that keeps two Macs on two histories is found when one sees the other's newer upload; a fork across members is a known limit (LD-266 (4)).
- **Nothing guessable on the server (SV-03).** The server copy needs the master password plus the 256-bit key-file part (P7), so a stolen server copy cannot be attacked with password guesses.
- **The newer key gives the server nothing (LD-264).** A copy that opens only with a key the server does not have cannot be made by the server; taking the newer key closes the case where an upload from a stale Mac undoes a password change.
- **A replaced password is never taken back (LD-267 (2), LD-269 (3)).** A copy under a key this Mac retired gives no key, no deletions and no metadata, and is merged only after the user's click (AT-L04).
- **No plain text off the Mac (AT-L08).** A test reads every request a client sends and finds no password, key-file part or vault content.

## Test cases

Two in-process clients A and B (two devices of one account) and an in-process server on 127.0.0.1:0 (P25), demo vault D (root id(01), password `demo`), test clock.

| Case | Given | When | Then |
|---|---|---|---|
| T01 SYN-03.1 first upload | D unlocked on A, no key file | Put D on the server | D now opens only with `demo` plus the part (not with `demo` alone); `MasterKeyChanged` = the test clock; the part is in A's device store; the server holds version 1; no request holds the part |
| T02 SYN-03.1 a vault with a key file | D2 keyed by `demo` plus key file K | Put D2 on the server | D2's key is unchanged (one slot); the device store holds K's `F` for D2 |
| T03 SYN-03.2 another Mac | T01 done; the part copied to B by the test helper | On B pick D, save it, unlock with `demo` | Opens; B's state links D; B's later unlocks ask only for `demo` |
| T04 SYN-03.5 both changes survive | T03 done | A edits entry E1, B edits entry E2, both save at once | After both runs, A and B hold both edits; the server's version is 3 |
| T05 SYN-03.5 deletion stays deleted (E15-S2) | T03 done | A deletes E3 for good (bin off) and syncs; B syncs | E3 is gone on B; B's next upload does not bring it back |
| T06 SYN-03.5 304 | A synced, nothing changed | Sync now | One GET answered 304; no PUT |
| T07 SYN-03.5 empty merge | B uploaded a change; A has no local change | A syncs | A's vault holds B's change; no PUT from A; A's state has B's version |
| T08 SYN-03.6 endless 412 | A test server that answers every PUT with 412 | Sync now on A | Exactly 3 PUTs, with waits of 1 to 3 s before the 2nd and 3rd; then `MSG-SYNC-BUSY` |
| T09 SYN-03.4 timing | Test clock | Unlock; save twice 1 s apart; wait 60 s; lock; wait 60 s; Sync now while locked | Runs: at unlock, once 2 s after the second save, once at 60 s; none while locked; Sync now does nothing while locked |
| T10 SYN-03.7 rolled-back version | A has seen version 5 | A test server lists version 4, then serves version 5 with other bytes | No merge, no upload; `MSG-SYNC-ROLLBACK` both times; A's vault unchanged |
| T11 SYN-03.7 old file under a new number | A has seen version 5 with newest change time T3 | A test server serves version 6 holding the bytes of version 2 | Merged, nothing newer lost, result uploaded; `MSG-SYNC-WENT-BACK` |
| T12 SYN-03.7 weaker KDF warns only (LD-269 (4)) | A's sync state for D holds Argon2id 64 MiB (the last server version A accepted) | The server copy (same vault) has Argon2id 16 MiB and a newer settings time than A's open vault. Second run: the same copy with an older settings time | Both runs: merged, and `MSG-SYNC-WEAKER` names the KDF, with no value. First run: the result has 16 MiB (the copy's settings group wins, MOD-11.19). Second run: A's settings group wins and its 64 MiB passes limit 1's compare: the result has 64 MiB |
| T13 SYN-03.8 and LD-264, the key-change case (E16-S7b) | T03 done | A changes the password to `demo2` and uploads (A retires `demo`); at the same time B edits E2 and uploads under `demo` first | A: `MSG-SYNC-OTHER-KEY`; user gives `demo`; it matches A's retired record: `MSG-SYNC-OLD-KEY`; Merge anyway: E2 is in A's result, A's key `demo2` kept, uploaded. B then: `MSG-SYNC-OTHER-KEY` (never "new"); B uploads nothing until the user gives `demo2`; then B's merge keeps both edits, the result opens with `demo2`; after A's next upload, `demo` no longer opens the server copy |
| T14 SYN-03.8 B's deletion converges (LD-267 (2)) | As T13, but B also deleted E4 for good under `demo`. Test clock (after T03): A changes the password at 10:00:00; B edits E2 at 10:00:05 and deletes E4 at 10:00:10, its last change | Run T13 to the end, then A syncs again | When B opens A's result with `demo2`, it merges it, uploads and shows `MSG-SYNC-WENT-BACK` (SYN-03.7, LD-273 (3)): A's Merge anyway took no deletions (MOD-11.31), so the copy's newest change time, 10:00:05, is earlier than the 10:00:10 B uploaded. After B's merge and upload, E4 is gone on the server and, after A's next run, on A |
| T15 SYN-03.9 Skip | As T13 up to `MSG-SYNC-OLD-KEY` on A. Test clock (after T03): A changes the password at 10:00:00; B edits E2 at 10:00:05 | Skip | Nothing of B's copy taken; A uploads its own vault; the server copy opens with `demo2`. B then: `MSG-SYNC-OTHER-KEY`; given `demo2`, B merges, uploads and shows `MSG-SYNC-WENT-BACK` (SYN-03.7, LD-273 (3)): the copy lacks E2, so its newest change time, 10:00:00, is earlier than the 10:00:05 B uploaded. B's edit E2 comes back in B's merged result, which opens with `demo2` |
| T16 SYN-03.9 planted copy | A retired `demo`. A test server serves a copy with root id(01) under `demo`, `MasterKeyChanged` 2099-01-01, deleted objects [E1's id at 2099-01-01], name `Evil` | A syncs, gives `demo`, answers Merge anyway | `MSG-SYNC-OLD-KEY` first; A's result keeps key `demo2`, name and E1; nothing deleted on A |
| T17 SYN-03.8 another vault | The server copy opens with credentials the user gives but has root id(65) | Sync | `MSG-SYNC-OTHER-VAULT`; nothing merged or uploaded |
| T18 SYN-03.8 Cancel | As T13 on B | Cancel the sheet; wait two ticks | No PUT from B; status Needs password; no sheet on the ticks |
| T19 SYN-03.10 401 then sign-in | A's session expired | Sync now | One sign-in, the run goes on; with sign-in refused too: `MSG-SYNC-SIGNED-OUT` |
| T20 SYN-03.10 404 | The server lost vault D | Sync on A | `MSG-SYNC-GONE`; no PUT with `If-None-Match: *` |
| T21 SYN-03.10 offline | The server stopped | Sync now | Status Offline; no message box; the vault unchanged |
| T22 SYN-03.11 signatures (E17-S1) | A test server that serves a version whose signature was made over another version, and one signed by an unknown key | Sync | Both refused as T10 |
| T23 SYN-03.12 part kept | D linked | Change the master password; then open Vault Settings | The part stays (the vault opens with the new password plus the part); "Kept for sync"; Save as key file writes an FMT-18 XML 2.0 file that, with the password, opens D in the reference command line tool (Verify, rule 2) |
| T24 SYN-03.14 nothing in plain | A full T13 run | A test proxy records every request body and header | No `demo`, `demo2`, part bytes, entry titles or passwords |
| T25 SYN-03.15 stop syncing | D linked on A | Stop syncing; lock; unlock | A's state has no link for D; D opens with `demo2` plus the part from the device store; the server copy unchanged |
| T26 SYN-03.3 state | After T04 on A; a client C that added the server and linked no vault | Read A's and C's state files; then kill App while it writes the state (test hook) and restart | The files have mode 0600 and hold the fields of SYN-03.3 and no password, key, part or token; C's holds the server's address and pin and no link; after the kill it holds the old state or the new one, never a mix |
| T27 SYN-03.13 status | Each case of T06, T08, T13, T18, T19, T21 and a run that ended well | Read the status line | Synced with the time; Error with `MSG-SYNC-BUSY`; Uses a replaced password; Needs password; Signed out; Offline; Synced; and Syncing while a run is open |
| T28 SYN-03.7 this Mac's own edit is no rollback | T04 done; A's sync state holds version 3 with newest change time 09:59:00; B edits E2 at 10:00:00 and uploads version 4; then A edits E1 at 10:00:05 and saves, before its next run | A syncs | A merges version 4: its newest change time 10:00:00 is earlier than the 10:00:05 of A's APP-05.26 record but later than A's sync state; A uploads version 5 with both edits; no `MSG-SYNC-WENT-BACK` and no `MSG-SYNC-ROLLBACK` |
| T29 SYN-03.10 a long `Retry-After` (and SYN-03.6) | Test clock; D linked on A; a test server that answers A's first GET with 429 and `Retry-After: 3600`, then each GET with 304 and each PUT with 412 | A edits an entry and saves; the run starts 2 s later. Separately, a second test server answers every GET with 429 and `Retry-After: 3600` | After the 429, A sends nothing for 300 s, then starts its 2nd try at 300 s, not at 3600 s. The 429 counts as the 1st of the run's 3 tries (SYN-03.6): in that run A sends exactly 3 GETs and 2 PUTs, with a wait of 1 to 3 s before the 3rd try; then `MSG-SYNC-BUSY`. With the second server, in that run: 3 GETs at 0, 300 and 600 s; the run ends with the status Offline and no message box (the run that the 60 s ticks asked for starts after it, SYN-03.4) |
| T30 SYN-03.10 a `Retry-After` that is not a number | Test clock; D linked on A, the local file unchanged since the last run; four test servers, each answering A's first GET with 429, then each GET with 304: with no `Retry-After`; with `Retry-After: Fri, 31 Dec 2099 23:59:59 GMT`; with `Retry-After: 1.5`; with `Retry-After: 99999999999999999999999` | Sync now with each | Each time A's 2nd GET comes 300 s after the 429 and the run ends Synced; no crash and no message box |

## How this was learned

- Public sources only; the reference app has no server, so its merge facts come from the existing cards (MOD-11, FMT-15, APP-05).
- spec/research/sync-server.md P2, P3, P4, P7, P18 (6), sections 1 (Enpass's client-side merge; Bitwarden's sync rhythm and its "out of date" refusal), 2 (RFC 9110 conditional writes, SUNDR) and 6 (rollback needs local state: Scarlata, Torrisi, Backendal, Paterson, USENIX Security 2026, section 6, <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>).
- spec/research/business-model.md section 3 ("Guard against rollback"; Bitwarden's sync rhythm, 3.4).
- RFC 9110: <https://www.rfc-editor.org/rfc/rfc9110.html>.
- App's own values, decided: spec/decisions.md LD-273 (1) (P3 says only "debounced" and "with jitter"; no proven client's numbers found): a run 2 s after a save (SYN-03.4, pinned by T09); a wait of 1 to 3 s before the 2nd and the 3rd try (SYN-03.6, pinned by T08); a `Retry-After` of at most 300 s (SYN-03.10, pinned by T29).
- App's own rules, decided: spec/decisions.md LD-273 (9): a 429 on the 3rd try ends the run as Offline, as a 5xx does (SYN-03.10, pinned by T29); a `Retry-After` that is missing or not a whole number of seconds counts as 300 s (SYN-03.10, pinned by T30). RFC 9110 section 10.2.3 lets `Retry-After` be an HTTP date or a number of seconds; App takes the number only, so a wrong clock on either side cannot change the wait: <https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3>.
- Written by E16-S1 (2026-10-31).
