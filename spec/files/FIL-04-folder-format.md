# FIL-04 Folder format and keys

Status: **DRAFT, 2026-11-05; second Spec and independent Verify pending**.
Epics: E23-S2, E23-S3, E23-S6
Parity: proposed FOLD-P1/P2/P3; runtime todo, no existing row signed.

## What it does

Create, unlock, list, read, write, rename and delete independently encrypted files/folders in an owner-selected storage directory. The original successful foreign-app interoperability and parallel AES-256-GCM requirements remain OPEN. Rules below are security relevant. Public basis F01–42 and unadopted R1–7 are in [research](../research/encrypted-folders.md); these are proposals, not permissions or new encryption.

## Inputs and outputs

In: a bound root directory capability, bounded public metadata/object bytes, an explicit password source, operation/session generations. Out: opaque Rust session/node/operation handles, cleaned list metadata and typed results; content and keys remain Rust-owned. File effects and user-authorized readable output follow FIL-06. Builders use normative public documents, not external implementation source.

## Rules

FIL-04.1 The proposed exact profile is `classic8-gcm-local-1`: classic format8 `SIV_GCM`, local `masterkey.cryptomator`, `vault.cryptomator`, F02 directory/name/shortening representation. Create shorteningThreshold220 and JWT HS256; read HS256/384/512 only with exact algorithm/key agreement. No Larsal wrapper, extra final marker, whole-vault container or UVF encoding is inserted. F01–03/R1.

FIL-04.2 Parse bounded original configuration/key-file bytes and reject duplicate JSON members, malformed integers/base64, unsupported critical parameters/algorithms and inconsistent required fields. Before authentication, `kid` permits only the exact relative local masterkey identifier of .1; no URL/file-URI, absolute path, traversal, plugin, remote key discovery or ambient secret store. Authenticate the original JWS signing input with the complete raw key; validate format/cipher/threshold only as authenticated claims. Algorithm `none` and algorithm substitution fail. F01/F08/R1.

FIL-04.3 Use scrypt and RFC3394 AES256 KW, with each32-byte encryption/MAC masterkey wrapped separately; validate the documented version MAC as well as wrapping integrity and config authentication before a session exists. Create N=2^18,r8,p1,salt32 bytes, output32 bytes. Read power-of-two N≥2,r1–32,p1 with `128*N*r≤1GiB` and `N*r≤8,388,608`; salt8–64 bytes, fixed wrapped lengths. Reject before KDF/allocation; never fall back to a cheaper cost or GCM wrap. F01/F19/F20/R5; exact ceilings FIL-06.

FIL-04.4 Password input is proposed NFC UTF-8, no trim/case fold/compatibility mapping/terminator, bounded before and after normalization. This is application policy, **check with Verify**: F01 does not establish peer password normalization. Foreign composed/decomposed/non-ASCII credential success is required before claiming that compatibility; no multiple-normalization retries. Default generation reuses FIL-01's ten built-in random words; save choice is FIL-05. F20/F28/R1.

FIL-04.5 Header and content are exactly F02's classic GCM layout:68-byte authenticated header,32768-byte plaintext chunks with12-byte nonce and16-byte tag; AAD binds64-bit big-endian chunk index and header nonce. Use fresh header nonce/content key and all chunk nonces on every Larsal whole-file rewrite, including retry; never resume ciphertext from a failed write. Randomness only through larsal-crypto::random; fixed header reserved bytes follow F02. F02/F21/R1.

FIL-04.6 Authenticate complete selected objects from stable custody before any content is released. Invalid header/chunk tag, illegal fragment, reordering, duplication or cross-file splice returns MSG-FOLDER-OPEN with zero readable output. Parallel work is bounded and ordered: up to4 workers, no unbounded completed-chunk queue, checked indices, no plaintext before full validation. Entire input validation is not just a successful first chunk. F02/F21, FIL-06.4/.5/R2.

FIL-04.7 Classic has **no final marker or authenticated total length**. Do not invent one, require a UVF marker in a classic file, or assert that removing whole trailing chunks is detected. Correctly authenticated shortened files can pass. Original E23-S3's broad corruption/no-plaintext clause remains OPEN with the exact R2 amendment proposal; generic refusal of all legitimate foreign files cannot satisfy it. F02/R2.

FIL-04.8 Name authentication binds names to a parent directory ID, not a regular file's contents to that name. Authentic complete content substitution within/across slots, older valid files, and old chunks under retained legacy headers can pass. New full-file keys reduce splicing of Larsal-created revisions only. Local known-history checks stop automatic acceptance on a mismatch; they are neither universal anti-replay nor trusted clocks. F05, research/R2/R4.

FIL-04.9 Apply F02's directory-ID storage/path calculation and deterministic RFC5297 AES-SIV name encryption exactly, with NFC UTF-8 names and the specified associated-data vector; distinguish absent associated data from an empty parent-ID component. Root ID is empty, new child IDs are fresh UUID strings from existing Rust RNG. SHA1 here is the format's addressing step, not a password hash or a new security construction. Never use the high-level SIV nonce wrapper as a replacement. F02/F18/F22/R1.

FIL-04.10 Implement ordinary and shortened names, files, directory links and optional encrypted directory-ID backups per F02. Check canonical encodings, hash/name mapping, parent context and mutually exclusive node representations; ambiguous duplicate/type-conflicting nodes fail closed and remain on disk. Do not “repair” hostile metadata or auto-merge two different names after normalization. Directory creation/removal spans multiple objects: journal crash boundaries as FIL-06, no atomic-tree claim. F02/F28/R1/R4.

FIL-04.11 Symlink representations may be recognized and listed as Unsupported link, never followed, created or exported as operating-system links. Real ciphertext/source symlinks, hardlinked mutable objects, devices, FIFOs, aliases/bookmark resolutions and package traversal are rejected by platform capability checks. Unsupported legitimate foreign features remain explicit interoperability limits and OPEN wider capability; nothing is deleted or silently skipped. FIL-06.2/.3, F12/F37/R1.

FIL-04.12 Only larsal-crypto imports SIV/KW/GCM/KDF/hash/encoding packages. Existing RNG failure aborts before usable output, no local RNG seed/fallback. Primitive known answers precede format vectors; sensitive crypto review is by two Checkers. AES-GCM, AES-SIV and AES-KW are distinct approved-or-proposed interfaces; no primitive is reimplemented in larsal-folders. F18–27, architecture/R5.

FIL-04.13 Master/password/KEK/content/name keys, normalized password copies, plaintext chunks, library state and error-path buffers use existing secret types, allocator and key-page policy. No Debug/Clone/log/view/error secret copy, no uncapped reallocation. Inspect CMAC/AES/SIV/KW/GCM and scrypt stack/register/backend copies on both Mac targets; zeroize flags and allocator alone are not proof. Lock invalidates handles immediately, joins/wipes workers at safe boundaries and suppresses late results, including vault-independent sessions. APP-02/11, LD-220, FIL-05.14/R5.

FIL-04.14 Future interoperability matrix must succeed both directions with an approved exact peer/profile: empty and binary files;0/1/32767/32768/32769/65536 bytes; nested/empty directories; short/long/NFC/Unicode names; manual and generated credentials; list/read/add/write/rename/delete; one changed file leaves every unrelated encrypted object byte-identical. Include 4GB and reopen after edits. Record tool versions/assets/fixture hashes, real output hashes and which nodes changed. Different cipher/profile/unsupported cases are classified separately, never counted as success. E23-S3/F39–41/R1.

FIL-04.15 List all observer leakage in research and show FIL-05's short notice: sizes/counts/times/fan-out/name equality/history are not hidden. A local folder entails no network call by Larsal; a third-party sync application may transport its ciphertext independently. Offline password guessing remains possible with portable wrapped keys; no new Larsal-service verifier, account or recovery path. LD-340/371, F04/F20/R6.

FIL-04.16 Keep classic and UVF separate. UVF spec1 at F09 is published working material with different headers/EOF/KDF/recipient/name metadata and seed pins; this draft adds no UVF read/write/migration selector. Password rewrap cannot revoke old data or historical wrapped keys; no recipient management/data-key rotation/reset command is invented. Document unsupported profiles honestly, retain all required implementing successes OPEN. F09–14/F42/R1/R6.

## Test cases

Every case is a future implementation obligation, **OPEN**. Positive success controls accompany all hostile cases; remove defenses only in private mutation copies.

| Case | Rule | Given / action | Expected proof |
|---|---|---|---|
| FIL-04-T01 | FIL-04.1 | Create and reopen classic8 GCM; inspect with approved peer | Exact wire profile and both successful opens; pre8/CTR/UVF refusals separate, never interoperability PASS. |
| FIL-04-T02 | FIL-04.2 | Valid signed config versus duplicate key, none, wrong alg, remote/traversal kid, changed signed bytes | Valid unlock succeeds; bad inputs generic error,0 network/child/ambient-secret calls and no session. |
| FIL-04-T03 | FIL-04.3 | Valid N/r bounds and wrapped keys; cost overflow,+1 memory/work,salt/wrap/version-MAC corruption | Exact-bound valid fixture opens; bad cost0 KDF calls, invalid authenticity0 sessions/output, no fallback. |
| FIL-04-T04 | FIL-04.4 | Foreign demo credentials: spaces,NUL,composed/decomposed accents, newer Unicode and generated words | Record exact agreed password conversion, successful peer cross-check; gap remains OPEN until established, no alternate retry or trimming. |
| FIL-04-T05 | FIL-04.5 | Same demo content rewritten/retried; injected random failure | Fresh key/header/nonces, exact AAD and ciphertext shape; failure yields no completed update. |
| FIL-04-T06 | FIL-04.6 | Valid boundary files versus bad first/middle/last tags,swap/repeat/splice/cut fragment/append | Valid bytes exact; invalid full-validation trace has0 plaintext release/output writes; memory/queue bound under slow first worker. |
| FIL-04-T07 | FIL-04.7 | Valid classic multi-chunk file; remove complete trailing chunk(s) | Demonstrate format limit honestly; no fabricated final-marker failure/PASS; original acceptance conflict remains OPEN. |
| FIL-04-T08 | FIL-04.8 | Authentic object swaps/replays and legacy retained-header revision splice | Authentication limits recorded; known-history mismatch blocks automatic use, first-use unseen replay not claimed detected. |
| FIL-04-T09 | FIL-04.9 | Same filename in same/different parents; root/child IDs; absent versus empty AD vector | Normative known answers and peer names match; changing parent context fails; root storage mapping exact. |
| FIL-04-T10 | FIL-04.10 | Valid shortened regular/directory nodes plus wrong mapping,duplicate type,missing directory ID | Long names and empty directories work; malformed nodes preserved/refused without repair; each journal crash boundary recoverable. |
| FIL-04-T11 | FIL-04.11 | Foreign encrypted symlink and actual OS link/FIFO/hardlink/cycle | Visible unsupported node, no follow/materialize/delete; ordinary file control reads successfully. |
| FIL-04-T12 | FIL-04.12 | Primitive vector suite,dependency/import scan,RNG failure | Vectors pass through only crypto crate; failing RNG aborts; two sensitive reviews and AT-J03 remain required. |
| FIL-04-T13 | FIL-04.13 | Success,error,cancel,lock during KDF/chunk on both targets | Immediate handle/UI revocation; eventual owned state wipe; site-specific memory evidence, no secret-bearing FFI/log/debug, no late completion. |
| FIL-04-T14 | FIL-04.14 | Full exact peer matrix above in both directions | Byte-identical successes, unchanged unrelated objects and real hashes; no unapproved download/tool run in S1. |
| FIL-04-T15 | FIL-04.15 | Offline copy plus observer/store/request review | Guesses possible and leakage accurately named;0 Larsal network requests/server-verifier route. |
| FIL-04-T16 | FIL-04.16 | UVF/CTR/pre8 fixture,old wrapped key backup after password rewrap | Explicit profile boundary,no silent migration; historical-key access demonstrated/disclosed, no retroactive revocation claim. |

## Errors, security and learning

MSG-FOLDER-OPEN in FIL-06 covers hostile parsing, integrity, credential and limit failures; no wrong-password oracle from detailed reasons. Visible explicit profile-selection help is separate, not a successful open. Current keys/config authenticate only under the format's stated limits. R2's proposed amendment is unadopted and the original clause unchanged. Learned from public primary format/standards/library documentation and existing Larsal boundaries only; no runtime/foreign/source-translation evidence.
