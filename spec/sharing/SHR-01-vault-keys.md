# SHR-01 Shared vault keys, wraps and epochs

Status: reviewed
Epics: E18-S3 (the key, the KDF floor, the key check, wraps, epochs, the routes), E18-S5 (a new epoch at removal), E18-S6 (many vaults in a team group), E18-S7 (the unlock and status words), E18-S8 (the hostile-server run)
Parity rows: none in the reference app (it has no server or sharing). App's own rows: SV-04 (plan/security.md); AT-L14, AT-L15, AT-L16, AT-L21 (plan/attacks-and-checks.md)

## What it does

A vault shared through App's server is an ordinary App vault whose only key part is one random 32-byte key-file part. App wraps that key to each member who may read the vault, with HPKE to the member's X25519 key, and signs each wrap. The key belongs to one **epoch**. When somebody loses the right to read the vault (removal, leaving), the vault gets a new random key in a new epoch, so a removed member gets no key to anything saved after it.

The signed member list (SHR-02) names each vault, each epoch and a hash of each epoch's key (the key check). So a client knows, from signatures alone, which key is right for which epoch, and a wrap from the server that holds any other key does not open. The server holds the keys only inside wraps it cannot open.

Other cards: SHR-02 owns the member list and the state it gives (members, rights, vaults, epochs); SHR-03 owns roles, invites and the check of every upload; SHR-04 owns removal and leaving; CRY-04 owns the crypto (HPKE, the signed wrap record, field lists); SYN-01 to SYN-03 own the routes, the store and the sync loop this card extends. These cards are about "a vault shared through your server"; INT-08's "a group of your vault, shared as a file" is a separate feature (P24).

Design and sources: spec/research/sync-server.md P8, P12, P23, P24 and sections 5 to 7 (decided: spec/decisions.md LD-263 (7), (11), (20), (21), LD-267 (7), LD-269 (5), LD-290 (1), (2); D-SHR01-1 and D-SHR01-2 below, the second of which changes LD-264, LD-267 (2) and LD-269 (3), (4) for shared vaults only).

## Inputs and outputs

- In: the member list state of SHR-02.5 (members, their X25519 keys, rights, vaults, epochs, key checks); this Mac's account keys (SYN-06.8); app-crypto's random source.
- Out: the vault file keyed by the key of the current epoch; one signed wrap record per reader per epoch, on the server; the epoch keys in this Mac's device store.
- Sizes: a vault key 32 bytes; a key check 32 bytes; a wrap record at most 4 KiB (SYN-01.10); an epoch is a u64 that starts at 1.

### Words

| ID | Words (App's own) | Buttons |
|---|---|---|
| `MSG-GROUP-UNLOCK` | Enter your account password to open "<vault name>". | the unlock sheet (APP-06): Open, Cancel |
| `MSG-GROUP-WAITING-KEY` | Waiting for the new key of "<vault name>". Your changes are kept on this Mac. | none (status line) |
| `MSG-GROUP-BAD-KEY` | The key for "<vault name>" that the server sent does not fit. App did not use it. | OK |
| `MSG-GROUP-BAD-VERSION` | The server sent a copy of "<vault name>" that App cannot check. Nothing was merged or uploaded. | OK |

"<vault name>" is the name inside the vault (never on the server). When App has no name for it on this Mac (a Mac that has never opened the vault, such as a newcomer's or a team member's after a new `grant`), it is "Vault <the first 8 lowercase hex digits of vault_id>", and `MSG-GROUP-WAITING-KEY` reads instead: Waiting for the key of "<vault name>". It opens on this Mac when the key arrives.

## Rules

SHR-01.1 **The key** (P8; FMT-04.3, FMT-04.5). The key of a shared vault in epoch `e` is `F_e`: 32 bytes from app-crypto's random source (CRY-04.12), used as the key-file part `F` of FMT-04.3. It is the vault's only key part: no password, no key file of the user's, no hardware key. So the composite key is `C = SHA256(F_e)` (FMT-04.5), and FMT-04.16 (at least one part) holds. A new `F_e` is drawn for each new epoch; App never derives one from another, from a password or from a time.

SHR-01.2 **The KDF floor** (P23; LD-263 (20), LD-269 (5)). A shared vault always uses Argon2id at APP-07's lowest settings: memory 1 MiB (the settings map's `M` = 1,048,576 bytes, FMT-03), 1 iteration, 1 lane, version 0x13. App writes these settings at every save of a shared vault, also when a merge result holds others. No wizard runs, so APP-07's M07-33 warning never shows. Why: the key is 256 random bits, so a costly KDF adds nothing, and MOD-11 never lowers KDF settings in a merge, so a high cost could never come down (P23).

SHR-01.3 **A version with other KDF settings** (P23; FMT-03). Before any KDF runs, App reads the KDF settings of a downloaded version of a shared vault from its outer header (FMT-03) and refuses the version, with `MSG-GROUP-BAD-VERSION`, when they are not exactly the settings of SHR-01.2. So no member and no server can make every member's Mac run a costly KDF.

SHR-01.4 **Making a shared vault** (P8). For the group's first vault (the create entry, SHR-02.2) and for each further team vault (a `vault` entry), the Mac that signs the entry:
1. draws a `vault_id` (SYN-01.6) and `F_1`, and keeps `F_1` in the device store (SHR-01.7) before it signs anything;
2. makes a new vault with the values of MOD-12.22 (APP-07.19), the name the user typed, the key of SHR-01.1 and the KDF of SHR-01.2, and saves it on this Mac (APP-05);
3. signs the entry, which names `vault_id` and the key check of `F_1` (SHR-01.5), and sends it (SHR-02.8);
4. uploads the vault with `If-None-Match: *` (SYN-01.6) and the upload headers of SHR-03.10, as version 1;
5. wraps `F_1` to every member who may read the vault (SHR-01.9, SHR-01.11), its own account included, so the account's other Macs get it.
A crash after step 3 leaves `F_1` in the device store; the next sync run goes on at the first step not done.

SHR-01.5 **The key check** (App's own arrangement, as SYN-05.1's commitment; RFC 9420 section 14: one canonical change per epoch). `check(V, e, F) = SHA-256(field list ("sync-vault-key-check-v1", group_id, vault_id, e as u64, F))` (CRY-04.2). The entry that starts epoch `e` of vault `V` carries this check (SHR-02.2, field `keys`). A key is the key of `(V, e)` only when its check equals the one in the verified list, compared in constant time (CRY-04.11). The check reveals nothing of `F`: `F` is 256 random bits, and the check is a domain-separated hash, never the composite key `SHA256(F)`.

SHR-01.6 **Epochs** (P12; RFC 9420 sections 2 and 3.2). Both client and server compute each vault's epoch from the verified member list alone (SHR-02.5); no request carries an epoch the receiver takes on trust:
- a vault starts at epoch 1 with the entry that adds it (`create` for the first vault, `vault` for a further team vault);
- each later entry whose `keys` field names the vault raises its epoch by 1 and sets the epoch's key check. SHR-02.6 step 8 makes an entry name every vault on which it ends somebody's right to read (a `remove`, a `role` or a `grant` that takes reading away), and a `rotate` entry names its one vault;
- a `leave` entry names no vault (the person leaving must not know the next key): it marks each vault the leaver could read as rotation due, and the next manager's Mac signs a `rotate` entry for it (SHR-04.11).

SHR-01.7 **Where the key lives** (AGENTS.md rule 4; P7). Each `F_e` this Mac holds is kept in the device store (SYN-04.1's store; this device only once W-02 is answered), keyed by group id, vault id and epoch, as `SecretBytes`. It is never written into a vault, the local state file, a log, a crash report, a request in plain form or the pasteboard. App keeps the keys of every epoch it received for a vault while this Mac's account may read it, so it can open any version a member made under an earlier epoch (SHR-01.13); they are all wiped when the account loses the right to read the vault (SHR-04.10). A shared vault offers no Stop syncing (SYN-03.15 is for personal vaults): its only key is the group's, which changes at each epoch, so the way out is Leave (SHR-04.11).

SHR-01.8 **Unlocking a shared vault** (D-SHR01-1 (a), decided: spec/decisions.md LD-290 (1). App's own reason: APP-02's lock must protect a shared vault too, and its only key part sits in the device store; sync-server.md section 5: in the hosted designs studied the vault key is wrapped to each member's public key, so a member reaches it through their own account keys). The unlock sheet (APP-06) asks for the account password with `MSG-GROUP-UNLOCK`. App checks it on this Mac by deriving `K_wrap` (SYN-06.3) and opening the copy of the account blob (SYN-06.4) it keeps in its local state; a wrong password gives APP-06's wrong-key words. Only then does App take `F_e` from the device store. Quick unlock (APP-04) then works for the shared vault as for any vault. Locking follows APP-02. The account password never leaves the Mac (SYN-06.2).

SHR-01.9 **The wrap** (P8; RFC 9180 sections 5.1.3, 9.1.1 and 9.8; CRY-04.5, CRY-04.6). A wrap of `F_e` for member `m` is a signed wrap record (CRY-04.6) with:
- info = the field list (`sync-wrap-info-v1`, `vault-key`, group_id, vault_id, `e` as u64, the account id of `m`);
- plaintext `F_e`;
- HPKE to `m`'s X25519 key as the verified list holds it (SHR-02.5), never to a key from any other source;
- signed by the sender's Ed25519 identity key; the signer id is the sender's account id. The sender is a member who may manage the vault (P8: "The admin signs (suite, enc, ct, info)").

SHR-01.10 **Opening a wrap.** CRY-04.6's order, then one more step; any failure is `WrapInvalid` with no detail, and App shows `MSG-GROUP-BAD-KEY`:
1. the suite is CRY-04.5's one suite;
2. the record's info equals the info this Mac builds itself from the vault, the epoch it expects and its own account id;
3. the signature verifies with the identity key the verified list holds for the signer, and the signer may manage the vault in the state at this Mac's head (SHR-02.5, SHR-03.1, SHR-03.2);
4. HPKE open with this Mac's X25519 private key (SYN-06.8);
5. `check(V, e, F)` equals the key check of `(V, e)` in the verified list (SHR-01.5).
Only then does App keep the key (SHR-01.7). When a wrap for this Mac's own account fails, App also deletes it (`DELETE`, SHR-01.12), so the next manager's run finds the reader missing and wraps again (SHR-01.11). Why both checks: the signature shows a manager of the vault sent the wrap (the ETH paper's ciphertext authentication, against BW02 and BW08), and the key check shows it holds the one key the list names for that epoch.

SHR-01.11 **Who wraps, and when** (P8, P12). Only a Mac whose account may manage the vault (SHR-03.1, SHR-03.2) wraps, only keys it opened or drew itself, and only to readers in the state at its own head:
- the signer of an entry that starts or raises an epoch wraps the new key to every member who may read the vault after it, its own account included;
- the signer of an `add` or `grant` that gives somebody the right to read wraps the current key to them, for each such vault unlocked on its Mac (SHR-03.8 step 3); a vault locked there is left to the next bullet, and that reader shows `MSG-GROUP-WAITING-KEY` for it until then;
- in each sync run of a vault, a Mac whose account may manage it reads the missing wraps (`GET /v1/groups/{group_id}/wraps/missing`, SHR-01.12) and wraps the current key of that vault to each reader listed whom its own verified state also shows as a reader. A Mac that does not hold the current key wraps nothing.
Every wrap needs the vault unlocked on this Mac: App never takes a key from the device store for a locked vault (SHR-01.8). The first bullet's signer has the vault open (SHR-01.4, SHR-04.2, SHR-04.11), the second wraps only vaults unlocked on its Mac, and wrap healing runs for a vault only in that vault's own run (SYN-03.4 never runs a locked vault). So a wrap that a crash, a lost Mac, a locked vault or a failed check (SHR-01.10) left undone is made by the next run of a manager who holds that key and has that vault unlocked. When no Mac but a lost one held the key, nothing heals (SHR-04's lost-Mac edge case).

SHR-01.12 **Wrap routes** (SYN-01 conventions: records, errors, limits, session). The server keeps, per vault and reader, the wraps of the current and the previous epoch only (a Mac that was offline at a rotation still opens the last version of the old epoch). It deletes a reader's wraps when that account may no longer read the vault (SHR-04.5).

| Method and path | Body in | Body out | Statuses |
|---|---|---|---|
| `PUT /v1/groups/{group_id}/vaults/{vault_id}/wraps/{epoch}/{member_id}` | WrapRecord | none | 204, 400, 401, 403, 404 |
| `DELETE /v1/groups/{group_id}/vaults/{vault_id}/wraps/{epoch}/{member_id}` | none | none | 204, 401, 403, 404 |
| `GET /v1/groups/{group_id}/wraps` | none | `{"wraps":[{"vault_id","epoch","wrap"}]}`: this account's wraps | 200, 401, 403, 404 |
| `GET /v1/groups/{group_id}/wraps/missing` | none | `{"missing":[{"vault_id","epoch","member_id"}]}`: readers with no wrap of the current epoch | 200, 401, 403, 404 |

The server answers the PUT with 403 when, in the state at its head, the caller may not manage the vault, the recipient may not read it, or `epoch` is not the vault's current epoch; a later PUT for the same path replaces the record (every honest wrap of one epoch holds the same key, SHR-01.5). The DELETE is for the recipient only: `member_id` must be the caller's own account id (403 otherwise); it removes that wrap, or does nothing when there is none (204). The missing list is for managers only (403 for others). An account that was never a member gets 404 for every path, as an unknown group does (SYN-01.6's rule); a former member gets 403 (SHR-04.5). The server never opens a wrap and checks no signature on it: clients do (SHR-01.10).

SHR-01.13 **Opening a downloaded version** (P8; SYN-03.5 step 3; D-SHR01-2 (a), decided: spec/decisions.md LD-290 (2)). A version of a shared vault names its epoch in its upload headers (SHR-03.10). After SHR-03.12's check and SHR-01.3's KDF check, App opens it with `F_e` of that epoch from the device store:
- this Mac holds no `F_e` for that epoch: it reads its wraps (SHR-01.12) and opens them (SHR-01.10); when none fits yet, nothing is merged or uploaded, the status line shows `MSG-GROUP-WAITING-KEY`, and the next run tries again;
- the bytes do not open with `F_e`: the version is refused with `MSG-GROUP-BAD-VERSION`. App never asks for credentials for a shared vault: SYN-03.8 and `MSG-SYNC-OTHER-KEY` do not apply, because a member never types a key for it.
A version that opens this way and passed SHR-03.12 is a copy of the same vault for MOD-11 (the signed upload and the key check are the proof; D-SHR01-2). The merge then runs as SYN-03.5 step 3 says.

SHR-01.14 **The key of every upload** (P8, P12; D-SHR01-2 (a), decided: spec/decisions.md LD-290 (2)). Before App uploads a shared vault, the vault is keyed by `F_e` of the vault's current epoch at this Mac's head. When the open vault or a merge result is keyed by another key (an older epoch's, or the other side's by MOD-11.19 limit 2), App replaces the key by `F_e` with the effect of MOD-12.10 step 8 only (no question, no warning), sets the KDF of SHR-01.2 and saves (APP-05) before the PUT. When this Mac does not yet hold the current key, it uploads nothing (`MSG-GROUP-WAITING-KEY`). A key change to a new epoch's key makes no retired-key record of MOD-11.31, and `MSG-SYNC-OLD-KEY` never shows for a shared vault: SHR-03.12 decides which versions count (D-SHR01-2).

SHR-01.15 **No user key change.** Vault Settings offers no credential change for a shared vault (MOD-12.10 is not reached); it shows "Key kept for sharing". The Encryption page (MOD-12.11 to MOD-12.14) shows SHR-01.2's settings read only for a shared vault: no slider, no field and no Apply, so no choice of the user's is dropped in silence at the next save. App also offers no "save the key as a key file" for it (SYN-03.12 is for personal vaults): a key file would outlive the member's right to read.

SHR-01.16 **Local state** (P4; SYN-03.3: "for shared vaults (E18) the key epoch and the member list's sequence number and hash"). Per shared vault, SYN-03.3's state keeps the group id, and the epoch and the named head (`seq` and hash) of the last version this Mac accepted or uploaded; both only move up (SHR-03.12 step 6). Per server account, it keeps the copy of the account blob that SHR-01.8 checks against. No key, no key check result and no plaintext.

## Edge cases and errors

- A wrap for epoch 3 arrives while the server's newest version is still under epoch 2: App keeps both keys and opens the version with the key of epoch 2.
- Two Organizers each wrap the current key to a new member at once: both records hold the same key; the second replaces the first; nothing changes for the member.
- A wrap whose key passes the signature but not the key check (a manager's bug, or a manager who wraps another key): `MSG-GROUP-BAD-KEY`; the key is not kept; the recipient deletes its wrap (SHR-01.10), so `wraps/missing` lists it and the next manager's run wraps again.
- A wrap made by an Organizer who has since become a Member: refused at step 3 by a Mac whose head holds the `role` entry; deleted and made again as the line above.
- A downloaded version with Argon2id 4 GiB: refused before any KDF work (SHR-01.3).
- A version saved by an App that wrote AES-KDF: refused (SHR-01.3).
- The Mac's account password is typed wrong at unlock: APP-06's wrong-key words; no vault key taken from the device store.
- `GET /v1/groups/{group_id}/wraps` lists a wrap for a vault this Mac's verified state says it may not read: ignored.

## Lead decisions

D-SHR01-1 **What unlocks a shared vault.** A shared vault's only key part sits in the device store, so without a rule it opens with no question on an unlocked Mac, and locking it (APP-02) protects nothing. (a) The unlock sheet asks for the account password, checked on this Mac against the kept account blob (SHR-01.8); quick unlock (APP-04) then works as for any vault. (b) Touch ID or the Mac's login password through LocalAuthentication only. (c) No question. Recommended: (a). Why (App's own reason): APP-02's lock must mean the same for a shared vault as for any vault, and the one secret a member types for the group is the account password, whose keys open the wraps (in the hosted designs of sync-server.md section 5 the vault key is wrapped to each member's public key); APP-04 already gives the biometric path after it. (b) adds a second unlock path to keep in step with APP-04; (c) makes APP-02 meaningless for shared vaults. Taken: (a); decided: spec/decisions.md LD-290 (1).

D-SHR01-2 **Which copies of a shared vault count, and which key an upload takes** (touches LD-264, LD-267 (2) and LD-269 (3), (4), for shared vaults only). LD-267 (2) gives one meaning of "same vault": a copy that opens with this vault's key, or with credentials the user gave for that copy. LD-269 (3), (4) keep retired-key records for every vault App opens, and a copy under a retired key shows the replaced-password message with Skip as the default. LD-264 (MOD-11.19 limit 2) keeps the newer of the two keys by the key-change time. A shared vault gets a new key at each epoch, and its members never type a key. (a) For a shared vault only: a version that passed SHR-03.12 and opens with the key of the epoch it names, whose check the signed list holds (SHR-01.5), is the same vault (SHR-01.13); a re-key to a new epoch makes no retired-key record and `MSG-SYNC-OLD-KEY` never shows; every upload takes the current epoch's key, never the newer key time (SHR-01.14). (b) Keep the three rows as they are: each earlier epoch's key becomes a retired key, so a version a member saved under the previous epoch during a rotation shows `MSG-SYNC-OLD-KEY` with Skip, and a merge may keep an older epoch's key when its key-change time is newer. Recommended: (a). Why: in a shared vault the proof is the member's signed upload (SHR-03.10) plus the key check that the signed list names, which says more than "it opens with a key this Mac has"; a removed member, or one who left, is refused by SHR-03.12 step 4 whatever key they hold, which is the job a retired-key record does for a personal vault after a leak; under (b) an honest member's edit made just before a rotation is skipped by default, with words about a replaced password nobody typed, and an older epoch's key could come back with a key-change time set in the future, a key a removed member still holds (RFC 9420 section 3.2: the new epoch's entropy is for every member "except the removed member"). SHR-01.13 and SHR-01.14 follow (a). The notes for MOD-11's Notation, MOD-11.31 and SYN-03 are proposed to the lead, who writes them. Taken: (a); decided: spec/decisions.md LD-290 (2).

## Security notes

- **A real boundary per vault (SV-04).** Each vault has its own key, so a team member with no right on a vault holds no key to it (P8; the opposite of the accepted Issue 10 in sync-server.md section 5).
- **The server cannot choose the key (AT-L14, AT-L15, AT-L16).** A wrap must be signed by a member whom the verified list lets manage the vault and must hold the key whose check the list names; a key the server made, encrypted to a member's public key, is refused ("anyone can encrypt a chosen symmetric key under the public key of any user", ETH paper on BW08, sync-server.md section 6). Recipients' X25519 keys come only from the verified list, so the server cannot add a recipient at a rotation (BW02, LP07).
- **New epoch, new key (AT-L21).** A removed member holds no key of a later epoch: the new key is drawn at random and wrapped only to the remaining readers (RFC 9420 section 3.2: the Commit gives "new entropy to all members of the group except the removed member"). What they already saw stays with them (SHR-04.9).
- **No cost bomb.** SHR-01.3 refuses other KDF settings before any work.
- **Not now: post-quantum.** The suite id in each wrap record lets a later suite (X-Wing) come with a new version (P8).

## Test cases

Clients A (an Organizer) and B (a Member) of one family group G with shared vault V, an in-process server on 127.0.0.1:0 (P25), demo data, test clock.

| Case | Given | When | Then |
|---|---|---|---|
| T01 SHR-01.1 key only (E18-S3) | A makes G and V | Open V's local file in app-core with `F_1` alone as the key-file part, no password | Opens (FMT-04.5); with `F_1` plus any password: `WrongKey` |
| T02 SHR-01.2 KDF floor (E18-S3, LD-267 (7)) | V just made; then V after a merge with a copy whose header says Argon2id 64 MiB (test seam that skips SHR-01.3) | Read V's KDF settings after each save | Argon2id, M = 1,048,576, 1 iteration, 1 lane, version 0x13 both times; no M07-33 shown |
| T03 SHR-01.3 other settings | A test server serves a version signed by B whose header says Argon2id 4 GiB; and one with AES-KDF | A syncs | Both refused with `MSG-GROUP-BAD-VERSION`; a counter in the KDF test seam shows 0 KDF runs |
| T04 SHR-01.5 known value | group_id 16 bytes of 0x01, vault_id 16 bytes of 0x02, e = 3, F 32 bytes of 0x04 | Compute the check with App and with an independent SHA-256 over the CRY-04.2 bytes (`shasum -a 256`) | Equal |
| T05 SHR-01.6 epochs | A list: create (V at 1), add B, add C, remove C (names V), add D, rotate V | Compute V's epoch after each entry, on the client and on the server | 1, 1, 1, 2, 2, 3 on both |
| T06 SHR-01.9, SHR-01.10 bound info (E18-S3) | A valid wrap of `F_2` for B | B opens it while expecting: another vault; epoch 1; epoch 3; the account id of C | `WrapInvalid` each time; with the right values the key opens |
| T07 SHR-01.10 signer (AT-L15) | A test server holds a wrap for B that it sealed itself and signed with a key not in the list; one signed by C after C's removal | B reads its wraps | Both refused with `MSG-GROUP-BAD-KEY`; nothing kept |
| T08 SHR-01.10 key check | A wrap signed by A, a member, that holds 32 random bytes in place of `F_2` | B opens it | Refused at step 5; `MSG-GROUP-BAD-KEY` |
| T09 SHR-01.11 healing | A adds B and crashes before the wrap (test hook); A's second Mac A2 (another Organizer's Mac would do the same) runs | A2 syncs G | A2 reads `wraps/missing` (B, V, epoch 1), wraps `F_1` to B; B opens V |
| T10 SHR-01.12 server checks | The server; C was removed in an earlier entry | PUT a wrap: as an account that was never a member; as C (a former member); for a recipient who may not read V; for epoch 1 while V is at epoch 2; as B (a Member) for A; as A for B. DELETE B's wrap: as B; as A | 404; 403; 403; 403; 403; 204. 204; 403. `GET …/wraps` as C: 403 |
| T11 SHR-01.12 kept epochs | V moves from epoch 1 to 2 to 3 | List the server's wrap rows | Only epochs 2 and 3 are kept |
| T12 SHR-01.13 waiting | B is offline while A rotates V to epoch 2 and uploads; the wraps of epoch 2 are not yet stored (test hook) | B syncs; then the hook stores them; B syncs | First run: no merge, no upload, `MSG-GROUP-WAITING-KEY`; second run: B opens and merges |
| T13 SHR-01.13 does not open | A version signed by A at epoch 2 whose bytes are a vault under another key | B syncs | `MSG-GROUP-BAD-VERSION`; no unlock sheet shown; nothing merged |
| T14 SHR-01.14 re-key | B's local V is under `F_1`; V is now at epoch 2 and B holds `F_2` | B edits and syncs | B's upload opens with `F_2` alone; no `MSG-SYNC-OLD-KEY`; B's state holds no retired-key record for `F_1` |
| T15 SHR-01.14 newer key from the other side | A merge where the copy under `F_1` has the newer `MasterKeyChanged` | B merges and uploads | The upload is keyed by `F_2` (the current epoch's), not `F_1` |
| T16 SHR-01.7 secrets | A full run of T05's list with uploads | Search the state files, logs, request bodies and headers (test proxy) for every `F_e` and its SHA-256 | None found; each key is in the device store only |
| T17 SHR-01.8 unlock (D-SHR01-1) | V linked on B, locked | Unlock with a wrong account password; with the right one | APP-06's wrong-key words and no `F_e` taken from the device store (the vault-key counter is 0); then V opens |
| T18 SHR-01.15, SHR-01.7 no key change | V open on B | Open Vault Settings, its Encryption page, and the sync menu | No credential change and no "save as key file"; "Key kept for sharing" shown; the Encryption page shows Argon2id, 1 MiB, 1 iteration, 1 lane with no slider, no field and no Apply; no Stop syncing for V; after B's next save the KDF settings are still those of SHR-01.2 |
| T19 SHR-01.4 making a shared vault, and a crash (E18-S3) | A makes G and V; separately, a test hook stops A after step 3 | Read the server and A's device store; for the hook case start A again and sync | The server holds the `create` entry and V at version 1 with SHR-03.10's headers, and a wrap of `F_1` for A's own account; `F_1` was in the device store before the entry was sent (test log order). After the hook: A uploads V as version 1 and wraps `F_1`; no second key is drawn |
| T20 SHR-01.16 local state | After T05's list on B | Read B's state file | It holds the group id, the highest epoch accepted (3) and the account blob copy; no key, no plaintext; the epoch never goes down after a restart |
| T21 SHR-01.10, SHR-01.11 a bad wrap heals | A test server stores, as C's wrap of `F_1`, one signed by B (a Member); a second case stores T08's wrap for C | C syncs; then A syncs with V unlocked; then C syncs | Both refused at step 3 or step 5 with `MSG-GROUP-BAD-KEY`; C sends `DELETE …/wraps/1/<C's id>` (204); A's `wraps/missing` lists C; A wraps `F_1` to C; C opens V |
| T22 SHR-01.11, SHR-03.8 locked vault | V is locked on A and C has no wrap; separately, V is locked on A while A invites D and both pick Codes match | A's other vaults sync; then A unlocks V | No wrap for C while V is locked and no key of V taken from the device store (the vault-key counter is 0); in V's first run after the unlock A wraps `F_1` to C. For D: A signs the `add` and sends no wrap; D shows `MSG-GROUP-WAITING-KEY` for V in its wording for a vault never opened ("It opens on this Mac when the key arrives", never "Your changes are kept"), with "Vault <the first 8 lowercase hex digits of V's id>" as the name, and a bad list a test server then sends D gives `MSG-GROUP-BAD-LIST` with "Group <the first 8 lowercase hex digits of G's id>"; V holds no name item for D; at the unlock A wraps `F_1` to D and writes D's name, and D opens V |

## How this was learned

- Public sources only; the reference app has no server or sharing.
- spec/research/sync-server.md P8, P12, P23, P24 and sections 5 (how hosted products share a vault key; a well-behaved client forgets keys on removal), 6 (the ETH paper's attacks and fixes) and 7 (HPKE, MLS).
- RFC 9180 (HPKE), read 2026-11-01: sections 5.1.3 (an identifier "should be included in the `info` parameter to avoid identity misbinding issues"), 9.1.1 (sign `(enc, ct)` with the sender's private key) and 9.8 ("in the Base mode, there is no authentication of the remote party at all"): <https://www.rfc-editor.org/rfc/rfc9180.html>.
- RFC 9420 (MLS), read 2026-11-01: section 2 ("epoch: A state of a group in which a specific set of authenticated clients hold shared cryptographic state"), section 3.2 (the Commit "provides new entropy to all members of the group except the removed member"), section 14 (each Commit is premised on one starting state; an application needs a rule for which Commit becomes canonical), section 16.9 (a compromised Delivery Service cannot forge messages but can delay or drop them): <https://www.rfc-editor.org/rfc/rfc9420.html>.
- Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers", USENIX Security 2026, sections 5.1 and 6: <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>.
- App's own cards: FMT-03, FMT-04.3, FMT-04.5, FMT-04.16, APP-07 (its lowest settings), MOD-12.10, MOD-12.22, MOD-11.19, MOD-11.31, SYN-03, SYN-06, CRY-04.
- Written by E18-S1 (2026-11-01).
