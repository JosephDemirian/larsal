# FIL-06 Folder limits, output custody and conflicts

Status: **DRAFT, 2026-11-05; second Spec and independent Verify pending**.
Epics: E23-S3, E23-S4, E23-S5, E23-S6
Parity: proposed FOLD-P2/P3/P4/P5, all runtime todo.

## What it does

Bound hostile folder work, retain every observed/locally created revision, keep writes and cleanup within proven ownership, and disclose what classic authentication and external applications cannot promise. Original acceptance and Order remain unchanged; all runtime checks **OPEN**. [Research](../research/encrypted-folders.md) contains F sources, unadopted R1–7, exact proposed amendments and attack/parity deltas. Rules below are security relevant.

## Inputs and outputs

Untrusted filesystem objects/metadata/cloud events, explicit user operation, stable root/node/destination capabilities and revision/generation handles. Outputs are bounded typed status/errors and owned effects. Names, costs and storage timestamps are not trusted authority. Counter arithmetic and every I/O result are checked; no source data is logged.

## Rules

FIL-06.1 Before allocation/KDF: configuration≤64KiB,key file≤64KiB,JSON depth≤16,members≤64,encoded scalar≤16KiB,password≤1MiB before/after normalization; exact masterkey/wrap lengths; FIL-04's scrypt salt/cost/memory/work limits. Read weak N<2^18 warns only after authentication, never silently rewrites metadata. Bound decoded values too; duplicate/unknown-required fields and integer overflow fail generically. One KDF/operation at a time. Proposed non-KDF owned-buffer budget16MiB,≤4 workers and≤8 queued chunks; KDF dominant128Nr≤1GiB plus overhead measured later. F01/F20,R5.

FIL-06.2 Names are single UTF-8 components, NFC,1–255 bytes after normalization and within actual destination limit. Reject empty,dot/dotdot,NUL,slash,backslash,colon,control/bidi-format characters; never strip characters to produce a different saved name. Check filesystem case/normalization equivalence and portable reserved device/trailing-dot/space names on creation/export; refuse collisions, never collapse two items. Display hostile names only as escaped plain text, no Markdown/links; raw selected capabilities stay in Rust. If a foreign name is valid in its source but unsafe here, show an unsupported-name row and require explicit new safe Save Out name, never silently rename or omit it. F12/F28/R4.

FIL-06.3 Operate descriptor-relative below a selected root; reject symlinks at every traversed component, hardlinked mutable files,devices,FIFOs,sockets,mount escapes and changed root identity. No recursive scan follows aliases or package links; explicit regular-directory import is depth≤128,≤1,000,000 nodes,≤10,000 immediate children,≤4096 plaintext path bytes. Enumerate/page≤256 items; bound work counts before recursion, detect repeated directory IDs/cycles and duplicate references. A limit is a visible refusal, not successful whole-folder import. F37/R4.

FIL-06.4 For any read/Open/Save Out/edit base, capture the selected ciphertext through one verified nonblocking regular-file descriptor into a fresh local0700 directory, exclusive0600 ciphertext-only scratch. Check actual bytes and identity/size/times before/after capture; mismatch/I/O aborts. Seal by closing every writable handle and removing its writable name, retain one read capability. No original-path reopen, writable snapshot alias or plaintext staging for validation. Same-UID arbitrary process/fd/memory compromise is outside this candidate; mere mode bits do not prove exclusive custody. E22 FIL-03,F37/R2.

FIL-06.5 Validate all captured available header/name/object authentication and complete legal chunk structure into bounded wiping discard buffers, then use the **same** sealed descriptor/credential/profile to return/write bytes. Validation hash-at-end cannot retract released plaintext. On first-seen authentic classic truncation/replay/substitution there is no missing cryptographic signal: do not claim validation detects it. Exact custody/replay/cleanup mechanism and original S3 clause stay OPEN under R2. No fallback to whole-file RAM. F02/F05/R2.

FIL-06.6 Mutations create ciphertext in an owned exclusive sibling staging location, check writes/flush/sync/close, preserve durable base and new ciphertext in local private recovery, recheck target identity/digest under available local coordination, then publish using reviewed ownership-safe platform primitives. Create/Save Out never replaces an existing file. A normal rename without target/parent protection is insufficient; advisory lock/NSFileCoordinator is not distributed CAS. No truncate/direct-write fallback. Update pins only after confirmed commit; uncertain commit reports MSG-FOLDER-UNCERTAIN and retains recovery. APP-05,F37/F38/R4.

FIL-06.7 Journal folder create/rename/delete and shortened-name multi-object transitions; keep source/old subtree reachable until new state is durable. Cancellation/error removes only proved owned incomplete scratch/staging/output, never another user's replacement at the same path. Bind cleanup to descriptor/inode and custody, not check-then-unlink or recursive sweep; when safe ownership cannot be established, preserve and report cleanup failure. Crash/power/sync errors may leave ciphertext recovery/staging; startup never overwrites or removes foreign/unrecognized nodes. Original no-plaintext-on-initial-corruption and closed-copy checks are not passed by a warning. F37/F38,R2/R3/R4.

FIL-06.8 Bind root,selected node/revision,target parent/name,credential revision,vault/folder/operation generations at confirmation. Serialize new write/launch/content-release/completion authorization with revocation; a flag check followed by unsynchronized effect fails. Revoke on every FIL-05.14 event, including standalone passwords; clear UI at once, bounded worker cleanup at safe points, no waiting for a remote peer/external app. Check before/after synchronous KDF and each chunk/I/O. An already authorized OS call may finish; no late success or automatic resume. APP-02,R3/R5.

FIL-06.9 Keep bounded local known-history ciphertext/config digests and durable recovery state outside synced storage, bound to validated vault identity/root and credential generation. A mismatch is Changed, not proof of which version is newer. A known older digest stops automatic use, prompts review and preserves both; first-use/unseen replay, lost local pins, storage forks and malicious password holders remain undetectable in general. No trusted wall-clock comparison or automatic “repair” of metadata. Password rewrap never deletes historical keys/backups. F05/F13/F42,R2/R4.

FIL-06.10 Conflict key is validated folder identity,parent directory ID,NFC filename; versions identified by full SHA256 of captured ciphertext. For two different observed versions from the same base, default Keep Both, no last-writer/time winner: retain the lexicographically smallest full digest under the original name and every other version as `conflict-<full64hex>.bin` in the same clear directory, recording the original name in local recovery. Encrypt the generated name normally, retaining the content ciphertext byte-for-byte; no plaintext conflict name is stored in the cloud. If that reserved name is occupied by different data, stop publishing and report collision, retaining all recovery; never overwrite or truncate digest suffixes. Deduplicate only byte-identical ciphertext after bounded streaming comparison, never guessed plaintext identity. Both arrival orders with the same version set must converge. APP-05,R4.

FIL-06.11 Before saving an edit, compare the exact base snapshot digest with current storage. If different/missing, keep the edit as a conflict rather than replace/delete the remote version; preserve every observed variant first. Two offline Macs retain local base+new ciphertext independently; upon later seeing both branches, use .10. Provider conflict files/NSFileVersion are candidates only: bound/authenticate their names and objects before association, never trust a suffix alone or trash them automatically. If a provider permanently withholds/destroys another Mac's sole version, no complete convergence/no-loss claim is possible. Proposed R4 qualification is unadopted. F13/F37/F38,R4.

FIL-06.12 Delete-versus-edit keeps edited content and marks deletion Pending conflict; rename-versus-edit and two different renames retain both source identities/variants until explicit resolution. Recursive delete preflights bounded affected nodes, durably preserves observed ciphertext and stops if any target changes; never recursively follow a foreign directory ID. Invalid/unreadable nodes do not become deletion authority. No nonempty folder is declared removed before all intended transitions are confirmed; partial outcome is visible/recoverable. APP-05,R4.

FIL-06.13 Local recovery uses app-owned0700 directory and0600 objects, ciphertext only plus minimal bounded operation metadata; never a synced cloud location or original plaintext name in recovery filenames. Retain per-operation base/new snapshots until explicit reviewed discard; no age/quota auto-prune. Preflight a proposed10GiB recovery ceiling and actual required space before mutation; if one operation needs more, stop with MSG-FOLDER-RECOVERY, no half-discard/automatic higher limit. A file larger than quota may still read/Save Out with adequate scratch/output space; original large-file speed/CRUD requirements stay OPEN where this policy would block. S3 must settle the quota versus required large-file matrix without silently shrinking acceptance. R4/R5.

FIL-06.14 Recovery/delete/discard UI binds exact owned records and expected digests. External substitution,forged journal/symlink/reused operation directories and bad owner/mode prevent cleanup. Stop rather than deleting unknown files; show cleanup/uncertain error with location separately as cleaned text. Restart scans only proven app-owned namespaces, never broad temporary/user/cloud folders. Local recovery is not a backup against whole-Mac loss and is not uploaded by Larsal. APP-05,F37/R4.

FIL-06.15 Temporary readable Open copies exist only after explicit FIL-05.7 consent and whole-input validation, in a fresh random0700 **local** managed directory, exclusive0600 regular file with safe chosen basename, no xattrs,tags,ACL/executable restoration. Record ownership before launch; never shared general temp/cloud or filename chosen by ciphertext as a path. On managed Finish,close,lock/sleep/userswitch/quit/replacement remove proven owned copies and wipe owned buffers; on crash cleanup is attempted at next start before new secrets. Observe edits with coordinated access plus watcher/checks; no API proves arbitrary external-document closure. Another app's descriptors/autosaves/indexes/backups may survive even after our path is removed. This cannot satisfy unchanged original S4 closed-file/no-leftover acceptance; R3 is unadopted. F31/F36/F37,R3.

FIL-06.16 Byte counts/offsets use checked signed64-bit bounds; classic GCM lifetime per fresh file key additionally≤2^32 invocations including retries, so no enormous single-file key lifetime or nonce budget wrap. No file-size-derived allocation or executable/data parsing. Scratch/output/recovery free-space estimates include all copies, overhead and multi-object staging; estimates are advisory, later I/O failures checked. Worker count≤4/chunk queue≤8,total non-KDF buffers≤16MiB; exact RSS and stack/backend copies remain S3 proof. F20/F21/R5/R7.

FIL-06.17 Remote hydration/coordinated reads stay off main thread; known dataless placeholders show wait state, no automatic recursive download. A user-triggered operation may request only selected files. After30s without byte/phase progress show MSG-FOLDER-WAIT and keep Cancel; no unbounded retry (≤3 explicit attempt cycles, then user action). Raw filesystem-derived research targets are future release requirements, not measured encryption performance. Capture/validate/save/KDF/hydration timings and cancellation latency are separate. Original S3 speed proof stays OPEN. APP-05,F30/R7.

FIL-06.18 Cryptographic/credential/hostile-structure/limit failures share MSG-FOLDER-OPEN; no upstream reason,cost,node text,secret or offset in logs/errors. Explicit input,I/O,collision,conflict,cleanup and uncertain outcomes use the fixed inventory below. Uniform wording is not whole-operation constant-time behavior. No no-metadata,no-replay,no-third-party-copy/secure-erasure promise. Proposed attacks need valid success controls and private-copy mutants; static/guard/PNG evidence signs no runtime security or original acceptance row. LD-340/371,F04/F05/R2–7.

## Test cases

| Case | Rule | Given / action | Expected future evidence (all OPEN) |
|---|---|---|---|
| FIL-06-T01 | FIL-06.1 | Exact limits,+1,huge decimal,duplicate members,KDF below/at/above budget | Valid controls unlock; hostile bounds refused before work/allocation; measured peak RAM/queue; weak authentic file warns without rewrite. |
| FIL-06-T02 | FIL-06.2 | NFC equivalents,case pairs,device names,control/bidi/markup,255/+1 bytes | Safe names round-trip; collision/unsafe creation refused, foreign unsupported row preserved and explicit safe export possible, no collapse or traversal. |
| FIL-06-T03 | FIL-06.3 | Valid nested tree and limits+1,links,FIFO,root/mount swap,ID cycle | No hang/escape/follow; bounded page/traversal, explicit failed import instead of silently skipped data. |
| FIL-06-T04 | FIL-06.4 | Valid snapshot plus mutable/truncated source,retained writer,planted name | Only ciphertext staged; valid stable capture works; bad custody refuses before plaintext, no original-path replay. |
| FIL-06-T05 | FIL-06.5 | Corrupt late tag versus authentic classic whole-chunk cut | Failed authentication0 released plaintext; valid sealed replay exact; undetectable cut documented, original acceptance OPEN. |
| FIL-06-T06 | FIL-06.6 | Valid new/edit update plus stale base,short write,ENOSPC,sync/close faults | Old/new recovery survives before publish; no truncation fallback or false success; existing sentinel untouched. |
| FIL-06-T07 | FIL-06.7 | Every multi-object transition; crash/cancel then plant replacement | Complete recovery path for valid update; no deletion of replacement/foreign bytes; residual cleanup warning is failed cleanup, not PASS. |
| FIL-06-T08 | FIL-06.8 | Every generation/trigger,standalone password,concurrent callback/new write | Serialized authorization proof; no new effects after revoke, immediate UI hide and bounded safe cleanup; in-flight OS outcome honest. |
| FIL-06-T09 | FIL-06.9 | Seen old digest,new valid digest,first-use replay,lost pins | Known-old stops automatic use; Changed never implies latest; unobservable replay/fork limit demonstrated/disclosed, no unapproved password verifier. |
| FIL-06-T10 | FIL-06.10 | Same two/three versions delivered in all orders; reserved-name collision | Identical observed conflict set/names,all bytes reopen,full-digest ordering independent of timestamps; occupied different data untouched,publication stops. |
| FIL-06-T11 | FIL-06.11 | Two offline Macs edit same base; both cloud conflict versions then withheld branch | Both observed/created variants durable,successfully accessible after reconciliation; missing unseen branch not falsely claimed recovered. |
| FIL-06-T12 | FIL-06.12 | Delete/edit,rename/edit,two renames,changed node during recursive delete | Edited content kept,deletion pending; all variants retained,partial outcome explicit,no cycle-based deletion outside scope. |
| FIL-06-T13 | FIL-06.13 | Recovery below/at/over10GiB with small injected logical quota,full disk | Valid operation durable; cap/full disk stops before mutation,no auto-prune; large read remains possible,actual large-write acceptance OPEN. |
| FIL-06-T14 | FIL-06.14 | Valid owned recovery versus forged/replaced/link journal on restart/discard | Only exact owned records removed; unknown bytes untouched,explicit warning and no broad sweep. |
| FIL-06-T15 | FIL-06.15 | Managed Open/edit/Finish,lock,crash,external held fd/autosave | Valid functional handoff and saveback,owned-copy removal proved or failed; external retention shown; original S4 contract not silently amended. |
| FIL-06-T16 | FIL-06.16 |0,1,32767,32768,32769,large file and synthetic2^32/2^63 counters | Exact valid bytes/bounded buffers,overflow/invocation budget fails before wrap; no new header reuse to evade bound. |
| FIL-06-T17 | FIL-06.17 | Dataless/stalled read,three failed attempts,Cancel,local control | No main-thread block/recursive materialization; wait/Cancel responsive,finite retries; actual release speed/stages recorded later. |
| FIL-06-T18 | FIL-06.18 | Each failure family,all user actions,positive flow and private mutants | Exact secret-free words and preserved sentinels; defenses turn red when removed; no format-limit demonstration mislabeled security PASS. |

## Exact error and notice inventory

Paths/names may appear only in separately cleaned selected-location/list labels; never interpolate hostile text or OS/library errors into these messages. Focus goes to the relevant control; dangerous confirmations default Cancel. All messages need native accessibility proof in S4.

| ID | Exact text | Action/state |
|---|---|---|
| MSG-FOLDER-OPEN | This encrypted folder or file could not be opened. Check the password and try again. | Credential,authentication,hostile structure/profile/limit; Cancel/Try Again. |
| MSG-FOLDER-PROFILE | This folder uses a format Larsal does not support yet. | Explicit format help; Close, no migration or success claim. |
| MSG-FOLDER-INPUT | Choose local files or a folder. Links and special files cannot be added. | Selection/preflight; choose again. |
| MSG-FOLDER-NAME | Choose a name that can be used safely on this disk. | Invalid component; focus name. |
| MSG-FOLDER-EXISTS | An item already has this name. Keep both or choose a different name. | Keep Both/Choose Another Name…/Cancel; no replace. |
| MSG-FOLDER-REPEAT | The passwords do not match. | Repeat field; no work. |
| MSG-FOLDER-WEAK | This password may be easy to guess. Anyone with the encrypted folder can test guesses. | Cancel/Use Anyway; never Return default consent. |
| MSG-FOLDER-SAVED | The password is saved in your vault. No encrypted folder was completed. | Credential save followed by cancel/failure. |
| MSG-FOLDER-BUSY | A folder operation is already running. | Existing operation unchanged. |
| MSG-FOLDER-CHANGED | This item changed in storage. Larsal kept your version for review. | Review Versions…/Close; no automatic replacement. |
| MSG-FOLDER-CONFLICT | Both versions are kept. Choose how to keep them. | Keep Both default/Save Selected Copy…/Cancel. |
| MSG-FOLDER-DELETE-CONFLICT | Another version changed this item. Deletion is pending; the edited version is kept. | Review Versions…/Cancel. |
| MSG-FOLDER-RECOVERY | There is not enough room to keep recovery copies safely. Review recovery copies before changing this folder. | Review Recovery…/Cancel; no pruning. |
| MSG-FOLDER-SPACE | There is not enough free space. Free some space or choose another disk. | No completed output; incomplete owned effects reported separately. |
| MSG-FOLDER-IO | The files could not be read or saved. Check access and try again. | Actual I/O; Retry/Cancel, finite attempts. |
| MSG-FOLDER-WAIT | This file is taking longer to download. You can wait or cancel. | Waiting with Cancel, no ETA. |
| MSG-FOLDER-CLEANUP | Larsal could not remove a managed readable copy. It may still be on this Mac. Check the copy before you leave. | Exact known location separately; Close/Check Copy… is explanatory text, never automatic Finder launch. |
| MSG-FOLDER-UNCERTAIN | Larsal could not confirm that this change was saved safely. Keep the source and review the recovery copies. | No success; Review Recovery…/Close. |
| MSG-FOLDER-LOCKED | This encrypted folder is locked. Unlock it to see its files. | No names/content; Unlock/Close. |

## How this was learned

Public standards, current official format/security/platform documentation and existing Larsal output/lock patterns. Concurrency and custody policies are our stated inferences, not a copied implementation or a claimed distributed-lock guarantee. No runtime/crypto/interop/native/memory/attack fleet ran in S1; second Spec and separate Verify still required.
