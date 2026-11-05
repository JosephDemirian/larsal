# FIL-03 Limits, output safety and errors

Status: **reviewed, 2026-11-05 (E22-S1 specification and static proposals only)**; second Spec corrections and fresh independent Verify approved; exact source adopted in `c8fa2f1`.
Epics: E22-S3, E22-S4, E22-S5, E22-S6
Parity rows: FILE-P1–FILE-P4 (all todo; runtime proof OPEN). Existing SF/SR/SD rows are not signed by this card.

All rules are security relevant unless explicitly visual. Source references S01–S20 and R1–R6, recorded as LD-366–371, are in [research](../research/file-encryption.md). Second Spec corrections and fresh independent Verify approved the exact specification/static proposals; source adoption is `c8fa2f1`. Original dependencies, required technical/sensitive reviews and E22-S2 AT-J03/download gates govern implementation. All runtime cases below remain OPEN in implementing stories. Historical submission wording in unchanged rules/cases does not change current review status. Proof: the research [Review and proof](../research/file-encryption.md#review-and-proof) footer.

## What it does

Bound hostile file work, preserve originals and existing outputs, disclose remaining guarantees honestly and use one plain decryption error. The ciphertext-only snapshot/full-discard-validation strategy is a candidate requiring stable custody/cleanup proof. Original corruption/no-plaintext/no-plaintext-temp/bounded-memory and cancel-leaves-no-partial-output checks are unchanged and remain OPEN in their implementing stories; later I/O/crash faults are a separate class.

## Inputs and outputs

Input: hostile regular file or explicitly streamed ciphertext/plaintext input, chosen credentials and output capability. Output: typed own-word error/progress/completion and effects limited to owned scratch and explicitly chosen new final output. All byte lengths use checked arithmetic, all filesystem operations check results.

## Rules

FIL-03.1 Apply limits before allocation/work: binary header ≤2,097,152 bytes, ≤1024 stanzas, decoded native identity list ≤65,536 bytes and ≤64 identities, passphrase ≤1,048,576 UTF-8 bytes, leading/trailing armor whitespace ≤16,384 bytes each. Header limit includes all framing/MAC/newlines; stanzas count includes ignored types. Do not allocate from an untrusted advertised length. (Basis: S02/S14/S16, R3.)

FIL-03.2 Write scrypt logN18; read accepts legal decimal logN1–20 after bounded checked decimal parse, exact r8/p1. LogN1–17 requires weak-file consent after full validation and before output; this is a policy warning, never a second decryption error. >20, zero, sign, leading zero, overflow or nondecimal is refused before KDF. No override/auto lowering. (Basis: S01/S13/S17, R3.)

FIL-03.3 Working RAM does not grow with file length. Proposed non-KDF owned-buffer budget8 MiB; scrypt dominant memory at ceiling1 GiB plus documented B/T/stack/process overhead. One file operation/KDF at a time, no input read_to_end, whole-file Vec, memory mapping plaintext, decompression or hidden plaintext buffering. A memory allocation failure is not reported as successful cancellation; allocator-abort behavior requires explicit review. (Basis: research6, S14, R3.)

FIL-03.4 No user-visible plaintext before complete initial snapshot validation. Candidate state order: Confirm→CaptureCiphertext→SealSnapshot→Unwrap→ValidateAllToDiscard→CreateFinal→DecryptToFinal→SyncClose→Complete. EOF and final-tag checks precede CreateFinal. No per-chunk success, hash-at-end or original-path two-pass replay is substituted. This remains subject to R2. (Basis: S04/S10, research5, R2.)

FIL-03.5 Capture snapshot in a fresh random0700 directory within the app private local scratch root, name unrelated to source, file0600/exclusive/no-follow. Open chosen input once without following a final symlink; verify regular type and record device/inode/size/times before and after capture, count actual bytes and treat mismatch/read failure as input change/I/O failure. Never stage plaintext, derive during unbounded header intake or read .ssh/key stores. (Basis: S19, APP-05/SD-09, R2.)

FIL-03.6 Before validation, close all snapshot write handles, revoke access to its name and retain only the owned read descriptor; do not duplicate it into a process/callback. Initial and output passes use this same sealed snapshot, credentials and parsed profile. File mode/0700 is not immutability against same-UID arbitrary fd/memory access. Exclusive custody and read-only reopen/unlink ordering require actual platform proof; no open writer may survive sealing. (Basis: S19, research5, R2.)

FIL-03.7 Complete syntax/credential/header/payload/final-marker/EOF validation must precede final output or plaintext. Post-validation read/write/sync or process/power faults are a separate output-I/O class and can leave bytes at the explicitly authorized final path; report actual cleanup/uncertain results without success or a universal crash-transaction claim. A handled cancellation with surviving incomplete output fails the unchanged S4 check, even with a correct cleanup warning; crash is not handled cancellation. Neither boundary nor candidate is runtime proof. (Basis: research5, S19, R2.)

FIL-03.8 Outputs always use a new explicitly chosen name. Use exclusive0600 no-follow descriptor-relative creation in a bound parent and verify regular type/uid/linkcount1/dev/inode; source aliases, existing file/link/directory and every collision fail before write. Do not truncate, replace, preserve an unexpected ACL or follow destination/source symlinks. No unsafe-save fallback or chmod of another file. (Basis: S19, APP-05, R4.)

FIL-03.9 Bind output cleanup to the exact created inode and operation; never unlink a substituted pathname or recursively sweep a user folder. A non-atomic check-then-unlink is insufficient under a writable-parent race. Platform review must supply a safe ownership/custody mechanism or decline cleanup and report MSG-FILE-CLEANUP; do not make a safety promise from a stat check alone. (Basis: S19, AGENTS rule11, R2/R4.)

FIL-03.10 Check every read/write/flush/sync/close and phase transition. Completion means all requested bytes, authenticated EOF, sync/close and required scratch cleanup succeeded. Use existing platform durability policy and document filesystem limitations. If sync outcome is uncertain, preserve any complete final file and report MSG-FILE-UNCERTAIN rather than delete a possibly good output or claim success. (Basis: APP-05, S19, R2.)

FIL-03.11 On handled cancellation/lock/error wipe owned buffers/keys and remove owned ciphertext scratch. On crash an unlinked snapshot closes with the process; named ciphertext left before sealing is swept only inside an authenticated app-owned operation directory at next start. No plaintext-temp recovery or broad age-based deletion; malformed/foreign/symlink ownership records are not trusted. Failure to remove owned artifacts is surfaced. (Basis: APP-02, SD-09, R2.)

FIL-03.12 Use checked signed64-bit offsets and unsigned byte counters with no overflow. No artificial small total-file cap: source/output/scratch must fit filesystem/platform and offsets; exceed signed max or chunk-counter domain fails before wrap/output. Free-space estimates include ciphertext snapshot plus final output and overhead; estimates do not replace error checks. (Basis: research6, S19, R3.)

FIL-03.13 Header, credential match, unwrap, tag/MAC, truncation, ordering, unsupported-recipient, parse and hostile-limit failures all return MSG-FILE-DECRYPT. No key/stanza names, costs, offsets, plaintext, parsed text, upstream error or differentiating wrong-password message. This uniform wording is not a constant-time whole-file oracle guarantee; public resource limits necessarily affect work. (Basis: S09/S12, SF-18, R3.)

FIL-03.14 User selection errors, output collision, input changes, filesystem capacity/access and cleanup faults get the fixed distinct messages below. Never echo filename/path or OS reason in an error. The source/destination label shown elsewhere is cleaned plain text: remove bidi/direction controls, visibly escape control/newline, no Markdown/link interpretation; raw path stays only inside selected file capability. (Basis: SF-18, AT-E01/E03, R4.)

FIL-03.15 Detect edits to credential entry/draft/vault generation and cancel; reject handles from another session, reused after completion, stale/revoked or concurrently mutated. Serialize authorization of each new write/completion with revocation; a check-then-write race is not sufficient. An already authorized in-flight OS write may complete after a cancel request, and its cleanup has the limits of .7/.9. Lock/revocation closes secret UI immediately even while worker KDF cleanup is pending. (Basis: AT-E03, APP-02, R2.)

FIL-03.16 Support boundary cases0,1,65535,65536,65537,131072 bytes; final chunk may be full, and empty input is valid. Validate chunk swaps/repeat/cross-file splice, final flag changes, nonce/header corruption and appended data; tolerate only documented armor transport variance. A full new valid replacement remains possible. (Basis: S01/S04/S09, R1/R2.)

FIL-03.17 Published-vector plan enumerates every corpus case and its expected parser/unwrap/header/payload/armor behavior before normalization into the user error. Hash internal discard plaintext where vectors require a valid prefix; final destination remains unwritten on failure. Supported success cases must match expected bytes; policy/unsupported rows remain separate OPEN adoption issues, never silent skips or success-by-refusal. (Basis: S04, E22-S3, R5.)

FIL-03.18 Interop matrix includes password and multiple X25519 recipients, binary/armor input, plain and encrypted native identities, arbitrary extension, empty/binary/Unicode-named/4GB data, app↔CLI and the separately approved age1.3.2 classical-profile tool both directions, with generated and manual passwords. Rust age0.12.1 documentation is a studied library alternative; no Rust peer binary/harness/package closure is requested or approved. Any added Rust peer needs a separate itemized reviewed request. No tool/plugin install or corpus download in S1; each tool/version/fixture hash is recorded when authorized. (Basis: S02/S04/S11, E22-S3/4/5, R1.)

FIL-03.19 For every defense propose a named attack case and a private-copy mutation removing that defense; the attack must turn red. No mutation of shared source, running product/full/crash/heap/reference/device fleets or real-data access in S1. AT-J03, two sensitive Checkers, second Spec and fresh Verify remain distinct roles. (Basis: AGENTS8/11, attacks G6/G7, R1–R5.)

FIL-03.20 Default local generation does not send any request, telemetry, key/hash, file content or filename to a service. No clipboard, Quick Look, thumbnails, metadata copies, xattrs, tags, owner ACL inheritance or executable-bit restoration. Treat file payload as arbitrary bytes, never parse it to decide safety or auto-open it. (Basis: LD-340, S09, R4/R6.)

FIL-03.21 No erasure promise: original plaintext is retained, explicit readable output persists after lock, disk snapshots/backups/cloud versions may retain copies, and a compromised endpoint can read data while used. Outer filename, approximate/exact size, times, number/type of recipients and sharing pattern remain public observations; neutral-name choice reduces only filename leakage. (Basis: S09, research3/5, R4/R6.)

FIL-03.22 Resource and speed figures are analytical/documented proposals, not measurements. S3 measures peak memory and stages, S4 proves original4GB round trip and cancel behavior; E23 independently sets measured folder targets. Do not add an executed-vector/tool/performance gate to S1 or treat a raw-I/O baseline as format performance. (Basis: research6, E22/E23, R3/R5.)

FIL-03.23 Owner-frame approval is separate from Spec/Verify. Static headless illustrations check texts, themes, layout/focus styles and preservation; they never prove encryption, native VoiceOver, secret wiping, filesystem races, successful cancellation or key lifecycle. Original S3 corruption and S4 cancellation acceptance remains unchanged; the snapshot/custody/cleanup candidate still needs actual implementation evidence. R6 preserves already-authorized portable local output and every LD-340 Larsal-service obligation; E22 adds no service path. W-18 wording and owner frame review are nonblocking under LD-220/268/363. (Basis: AGENTS8/10, Option A, R2/R6.)

## Test cases

| Case | Rules | Given | When | Then |
|---|---|---|---|---|
| FIL-03-T01 | FIL-03.1 | each exact limit, limit+1, long line, ignored stanzas | parse | boundary accepted if otherwise valid, +1 refused before extra allocation/KDF; decrypt error generic |
| FIL-03-T02 | FIL-03.2 | cost1/17/18/20/21 and enormous decimal | decrypt | legal within ceiling derives once; weak consent only for authenticated file; >20/malformed zero KDF calls |
| FIL-03-T03 | FIL-03.3 | 1MiB and4GB files, ceiling KDF, allocation fault | measure in S3 | file buffers bounded independently, no memory-sized file cap; actual peak RSS/abort safety OPEN |
| FIL-03-T04 | FIL-03.4 | bad first/middle/last chunk, final marker removed, append | initial validation | one MSG-FILE-DECRYPT and no final-output open/write event; valid nontrivial files still decrypt in future implementation |
| FIL-03-T05 | FIL-03.5 | source edited/replaced/truncated during capture, full scratch disk, symlink input | prepare | failure before final output; no source modified or plaintext scratch; descriptor—not reopened path—defines captured source |
| FIL-03-T06 | FIL-03.6 | attempt write through retained fd/path after seal and replace original file | read two passes | snapshot content remains fixed under stated threat boundary; exact macOS mechanism is OPEN, no inferred proof from chmod |
| FIL-03-T07 | FIL-03.7 | handled cancel, later read/write/sync fault and process/power crash during output after successful whole-file validation | inject each separately in implementing stories | handled cancel must leave no owned incomplete output for S4 PASS; surviving incomplete output is failed cancellation even with a warning. Later I/O/crash tests report actual residual/uncertain results separately, never a false corruption/cancellation PASS |
| FIL-03-T08 | FIL-03.8 | existing sentinel, symlink, hardlink, same source/destination and race at create | save | sentinels/source/link target byte-identical; MSG-FILE-EXISTS or MSG-FILE-DESTINATION, no overwrite |
| FIL-03-T09 | FIL-03.9 | rename owned output away and plant a sentinel before cleanup | cancel/fail | sentinel untouched; cleanup failure explicit, owned inode handling proved or left OPEN |
| FIL-03-T10 | FIL-03.10 | short write, ENOSPC, permission loss, flush/sync/close errors | save | no success; old files untouched; incomplete owned output cleanup attempted; uncertain complete file reported accurately |
| FIL-03-T11 | FIL-03.11 | crash before/after seal, planted scratch link/foreign folder | restart/cancel | only proved owned scratch removed; no other files touched; plaintext final crash limit remains explicit |
| FIL-03-T12 | FIL-03.12 | near2^63 synthetic counts, sparse/small/full storage, unknown input length | prepare/advance | bounded counted reads, no wrap or giant allocation, resource/I/O error with no source damage |
| FIL-03-T13 | FIL-03.13 | wrong password/key and each corruption family | fail | identical message and secret-free typed result/log; no per-cause details sent to UI |
| FIL-03-T14 | FIL-03.14 | hostile basename/control/markup and disk error | show labels/errors | only cleaned label/plain text, exact message; no secret or command interpolation |
| FIL-03-T15 | FIL-03.15 | stale/cross-vault operation and concurrent output callbacks | call FFI | typed generic/cancel response, no secret/output under wrong generation, no resurrection |
| FIL-03-T16 | FIL-03.16 | boundary demo files and bit/cut/swap mutations | future round trip/attack | valid exact bytes; changed cryptographic data fails initial validation without plaintext; replacement limit disclosed |
| FIL-03-T17 | FIL-03.17 | testkit payload-failure vector with valid prefix and native-PQ case | run S3 vector harness after permission | expected internal prefix accounted for safely; external output0; unsupported-PQ mapping recorded and original acceptance still OPEN |
| FIL-03-T18 | FIL-03.18 | separately approved age1.3.2 exact classical profile and both frontends; generated/manual passwords, multi-recipient X25519, binary/armor reads, native/encrypted identity files, empty/binary/large/4GB demo data | future successful foreign-file checks in both directions and app↔CLI | identical bytes required independently; Rust age0.12.1 remains studied documentation, no Rust run/closure requested, any addition separately itemized/reviewed; no runtime PASS in this DRAFT |
| FIL-03-T19 | FIL-03.19 | known-working attack plus private mutant | future E22-S6 | positive control accepts expected demo, missing defense caught; reviewer proof retained |
| FIL-03-T20 | FIL-03.20 | demo file with EXIF, executable payload and filename secret | encrypt/decrypt | payload round trips as bytes; external filesystem metadata not copied; no network/clipboard/handler |
| FIL-03-T21 | FIL-03.21 | encrypt image named after a person then decrypt | read success/help | limits said accurately; no deletion of original or metadata confidentiality claim |
| FIL-03-T22 | FIL-03.22 | S1 report and future benchmark results | assess acceptance | documentation study distinct from runtime evidence, all unexecuted implementation checks OPEN |
| FIL-03-T23 | FIL-03.23 | all proposal PNGs and static assertions | review handoff | DRAFT, owner approval pending and runtime/capability limits explicit |

## Error/message inventory

| ID | Exact own-word text | When / action |
|---|---|---|
| MSG-FILE-DECRYPT | This file could not be decrypted. Check the passphrase or file key and try again. | All cryptographic/hostile file failures; no readable output from initial validation. |
| MSG-FILE-INPUT | Choose one local file. Folders and links are not supported here. | User selection; no file work. |
| MSG-FILE-PASSPHRASE | Enter a passphrase within the allowed size. | Empty/over-limit explicit user credential; no KDF. |
| MSG-FILE-REPEAT | The passphrases do not match. | Repeat field; focus it. |
| MSG-FILE-RECIPIENT | Add a valid native X25519 recipient key. | Invalid or unsupported explicit public key; help explains classical profile. |
| MSG-FILE-EXISTS | A file already exists with this name. Choose a different name. | No overwrite offered; Choose Another Name… / Cancel. |
| MSG-FILE-DESTINATION | This location cannot be used. Choose another folder and a new file name. | Unsafe path/type/access; no target changed. |
| MSG-FILE-CHANGED | The source file changed. Choose it again and try once more. | Capture change; no output. |
| MSG-FILE-SPACE | There is not enough free space. Free some space or choose another disk. | Checked ENOSPC/preflight; not a cryptographic diagnosis. |
| MSG-FILE-IO | The file could not be read or saved. Check access to the files and try again. | Actual I/O failure, generic OS-independent words. |
| MSG-FILE-CLEANUP | Larsal could not remove an incomplete file. It may contain readable data. Check the destination before you leave. | Cleanup not proven/successful; destination shown separately as cleaned selected path, never claim cancelled with no output. |
| MSG-FILE-UNCERTAIN | A file was written, but Larsal could not confirm it was saved safely. Keep the source and check the destination. | Complete bytes, uncertain durability/close/cleanup; no success. |
| MSG-FILE-SAVED-KEY | The passphrase is saved in your vault. No encrypted file was completed. | Default credential saved, later encryption failure/cancel. |
| MSG-FILE-CANCELLED | The file operation was cancelled. | Only after handled cleanup succeeded; original preserved. |
| MSG-FILE-BUSY | A file operation is already running. | No new selection or credential replaces it. |
| MSG-FILE-WEAK | This file uses a low passphrase work factor. Only save its contents if you trust the file. | Authenticated low-cost file; Cancel default / Save Readable File. |
| MSG-FILE-QUANTUM | These public keys do not protect against a future quantum computer. | Classical recipient mode; no implication passwords have unlimited quantum strength. |
| MSG-FILE-LIMITS | No server is contacted. Anyone with this encrypted file can test passphrase guesses. Names, sizes and dates may still be visible. | Persistent passphrase help; recipient help says no sender proof. |

All table entries are exercised by the corresponding rules/cases: T01/T02/T13 for decrypt and weak limits; T08/T09/T10/T12/T14 for filesystem/collision/cleanup/uncertain states; FIL-02-T01/T02/T05/T06/T07/T10/T17/T22 for input/saved-key/manual/busy/limits; FIL-01-T20 for quantum. UI buttons inherit FIL-02 keyboard/default rules. A cleanup warning may accompany the original error, never replace it with a false success.

## Lead decisions and security notes

R2 retains original S3 corruption and S4 cancellation acceptance; T04–T11 specify the unproved ciphertext-only candidate, stable custody and cleanup-race obligations, with later I/O/crash faults reported separately. R6 states authorized local export, accurate offline-guess limits and unchanged LD-340 obligations for every Larsal service; no third-party-storage blocker or service route is added. Second Spec corrections and fresh independent Verify approved this exact specification/static proposal; source adoption is `c8fa2f1` and review/proof is recorded in the research footer. W-18 wording/owner frame review add no blocking gate. No AT-J03/download grant, sensitive runtime sign-off or native parity is supplied.

## How this was learned

Public standards and official library/implementation documentation only, linked in the research evidence register. Existing Larsal cards and source were read to preserve boundaries and reuse approved behavior. No reference access, translated implementation, package installation or runtime encryption evidence.
