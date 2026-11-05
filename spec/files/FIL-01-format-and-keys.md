# FIL-01 File format and keys

Status: **DRAFT, 2026-11-05; do not implement from this draft.**
Epics: E22-S2, E22-S3, E22-S4, E22-S5, E22-S6
Parity rows: proposed file-encryption rows; Lead owns central allocation. Existing SF/SR/SD rows are not signed by this card.

All rules are security relevant unless explicitly visual. Source references S01–S20 and unadopted rulings R1–R6 are in [research](../research/file-encryption.md). They supply evidence, not approval. The prior draft received second Spec review; its six accepted corrections are applied here. Fresh independent Verify and selective Lead adoption remain pending. Original acceptance remains OPEN. Runtime cases below are specifications for the implementing stories, not tests run in E22-S1.

## What it does

Encrypt exactly the bytes of one file in a public format; the file is independent of its Larsal vault. Required modes are a generated/stored passphrase, an explicitly chosen manual passphrase and public recipients. No sender-authentication or everlasting-security promise.

## Inputs and outputs

Input: bounded byte streams, one credential selection and FIL-03 limits. Output: binary age-classic-1 ciphertext or a validated operation handle; no decrypted byte stream is handed to Swift. Destination effects are FIL-03. Passphrases/private identities/file keys/plaintext are Rust secret types. Public recipient strings may cross the screen boundary.

## Rules

FIL-01.1 The exact interoperability profile is research P1: binary age v1 writes, binary/strict armor reads, scrypt or native X25519. No proprietary prefix, container, compression, embedded filename or alternate KDF is added. The normative wire algorithms/grammar are S01, not code copied from a tool. (Basis: S01, R1.)

FIL-01.2 Parsing obeys S01 canonical unpadded header base64, LF grammar, argument counts and wrap lengths. Authenticate the original accepted header bytes, not a repaired/re-encoded substitute. Bound before buffering. (Basis: S01, S04, R1/R3.)

FIL-01.3 Use fresh file key and payload nonce for each encryption attempt, including retry after cancel or failure. Each X25519 stanza uses a fresh ephemeral secret. Every random draw comes from larsal-crypto::random and OS failure aborts. Never resume/reuse a partial encrypted file. (Basis: S01, S18, architecture rule7.)

FIL-01.4 Passphrase write uses exactly one scrypt stanza, fresh salt, r8/p1, 32-byte derived wrap key and logN18; no second recipient of any type. Validate stanza/body shape and work limit before KDF or allocation. (Basis: S01, S13/S17, R3.)

FIL-01.5 Passphrase bytes are exact UTF-8 with no normalization, trimming, case conversion or added terminator. Empty manual passwords are refused. Whitespace, non-ASCII and NUL from a vault value remain data. Password-file/TTY transport has the explicit rules of FIL-02. (Basis: S01, existing SecretString, R4.)

FIL-01.6 Default file passphrase is a fresh FEA-03 generation with the built-in list, 10 lower-case words and one space; do not inherit weak or custom saved generator settings. Its nominal entropy is 10×log2(7776), about129.25 bits, without claiming more than the format file-key strength. Save protected before encryption as FIL-02. (Basis: FEA-03.1/.6/.17, S09, R4.)

FIL-01.7 A manual passphrase requires a matching repeat and FEA-05 strength check. Below Excellent warns with Cancel default; an explicit Use Anyway permits it. The warning explains offline guessing. Never substitute the vault master password or claim chosen words are unguessable. (Basis: FEA-05, S09/S17, R4/R6.)

FIL-01.8 Public-key mode accepts 1–1024 distinct native X25519 recipient keys; deduplicate exact decoded keys before wrapping. Each can independently decrypt the same file key. Do not add an implicit self-recipient: require an explicit recovery recipient or acknowledge that the sender may not reopen the file. (Basis: S01/S02, R1/R3/R4.)

FIL-01.9 Native recipient/identity strings use the exact S01 HRPs/32-byte data and original Bech32 checksum, never Bech32m. Accept all-lower or all-upper spellings, reject mixed case, wrong padding/checksum/HRP/length. Parse using S16 checked Bech32/byte iteration; no hand-made checksum or unbounded decoded allocation. (Basis: S01, S16, R1.)

FIL-01.10 Public-key review shows the complete recipient string in a selectable wrapped plain-text control and requires confirmation that it was checked with its owner independently. A label or a checksum catches typing errors, not a swapped valid key. No network lookup, directory trust or automatic replacement. (Basis: S09, S16, R4.)

FIL-01.11 Reject low-order X25519/all-zero shared secrets before wrap/open using approved crypto checks. Reject native stanza body/share shape before primitive work; compare header MAC/keys in constant time. Do not reuse browser-channel derivation labels for file encryption. (Basis: S01, existing bridge Secret, R1.)

FIL-01.12 The complete payload including the required final marker and EOF is validated, with chunk ordering/counters, before user output under FIL-03. A successful early chunk grants no right to return a readable prefix. No counter wrap, appended content, empty extra final chunk or concatenated second file. (Basis: S01/S04/S10, R2.)

FIL-01.13 Strict armor read accepts the public armor label, canonical padded body and S01 permitted outer whitespace/LF/CRLF; reject junk, extra blocks, blank interior lines and noncanonical body. It is transport syntax, not encrypted authentication: tolerated line-ending/whitespace changes are not claimed detected. Write remains binary. (Basis: S01/S03, R1.)

FIL-01.14 Unknown stanza types in a public header are bounded and ignored for matching; malformed syntax fails. Unknown-only, SSH, plugin, tagged or native PQ-only headers do not start a process or use an ambient key. They return generic decrypt failure with separate non-diagnostic help listing supported modes. Never guess a wrong-password diagnosis. (Basis: S01/S11/S12, R1/R3.)

FIL-01.15 Private identities come from explicitly selected protected vault fields or an explicitly chosen bounded key file. Plain native identity lists allow blank/comment lines and up to64 identities; each noncomment line must be a valid native key. No .ssh, agent, Keychain, plugin, pinentry, home-folder search or network request. (Basis: S11/S12, existing secret boundary, R1/R3.)

FIL-01.16 A passphrase-encrypted native identity file is opened through the same authenticated bounded reader into at most64 KiB of wiping memory, then parsed as the native list. Prompt separately for its passphrase. No recursion, no plaintext key temp, no treating its contents as a shell/config format. (Basis: S10/S11, R1/R3.)

FIL-01.17 Generate a native file key only after explicit Create File Key; persist its private string as a protected vault custom field and public recipient as plain metadata, distinct from sync/SSH/passkey keys. Confirm durable save before using it. Export of a private key is not implied; public key selection/review never exposes the private value. (Basis: S01/S16, MOD-01, R4.)

FIL-01.18 Secret types/wiping allocator hold passphrases, private identity text, ephemeral/file/wrap/payload keys and plaintext buffers. Allocate once within bounds; wipe on success/error/cancel/revocation. Library key schedule/ROMix/stack/register copies need the explicit S3 review sites in research7; no generic whole-process erasure promise. (Basis: S13–S18, existing secret.rs, R1.)

FIL-01.19 Only larsal-crypto imports cryptographic/Bech32 packages; larsal-files arranges bounded format/state through typed crypto interfaces and performs no primitive or random algorithm. Use exact standard labels and parameter checks. Swift receives opaque handle/progress/errors, never file content, private keys or retained passphrases. (Basis: architecture, R1.)

FIL-01.20 Published native hybrid MLKEM768-X25519 exists; FIPS203 is the ML-KEM component standard while HPKE-PQ is a draft. This classical profile exposes no PQ selector and gives its quantum limitation plainly. Native PQ support remains OPEN for a separate exact library/review route if required by Lead; never emulate it with tagged recipients or silent classical fallback. (Basis: S01/S03/S07/S08/S11, R1.)

FIL-01.21 Content integrity is not sender identity or freshness. A new valid encryption to the same recipient can replace the entire file, and anyone who knows a passphrase can replace a password file. No signed/safe-to-open badge, replay protection or automatic launch follows from successful decryption. (Basis: S09, R2/R4.)

FIL-01.22 No upload or online recovery is part of E22. Anyone obtaining portable password ciphertext can test guesses; filenames/size/times remain observable. State this with R6's local-export/service boundary, never claim a third-party cloud cannot test a weak password. A lost credential has no reset/decrypt service. (Basis: S09/S17, LD-340, R6.)

## Test cases

| Case | Rules | Given | When | Then |
|---|---|---|---|---|
| FIL-01-T01 | FIL-01.1 | demo binary/image/empty bytes | encrypt then open with an approved external peer | bytes identical, public format accepted; no Larsal envelope |
| FIL-01-T02 | FIL-01.2 | bad padding, CRLF binary header, oversized args, noncanonical base64 | parse | generic failure and zero final-output writes; accepted valid header MAC checked over original bytes |
| FIL-01-T03 | FIL-01.3 | two encryptions of identical demo input/credential and injected RNG failure | encrypt/retry | fresh values differ; RNG failure produces no completed file and owned partial is removed |
| FIL-01-T04 | FIL-01.4 | scrypt plus another stanza, body31/33, cost21 or long decimal | decrypt | failure before KDF; valid single stanza proceeds |
| FIL-01-T05 | FIL-01.5 | leading/trailing spaces, composed/decomposed text, NUL in vault demo value | encrypt/decrypt | only identical UTF-8 opens; no truncation, empty rejected |
| FIL-01-T06 | FIL-01.6 | global generator configured for one custom word | start default encryption | uses ten built-in random words; error/no RNG never yields fallback credential |
| FIL-01-T07 | FIL-01.7 | short demo phrase, mismatching repeat | continue | mismatch blocks; weak value warns, cancel writes nothing, explicit consent binds that exact value |
| FIL-01-T08 | FIL-01.8 | two recipients and no sender identity | encrypt then each recipient decrypts | both succeed independently; no hidden recovery key or master-key relation |
| FIL-01-T09 | FIL-01.9 | uppercase valid key; mixed-case, Bech32m and excess-data keys | import/select | only conforming native key accepted; no partial key or fallback algorithm |
| FIL-01-T10 | FIL-01.10 | different valid key under the same display label | select/send | fresh full-key review; no trust inferred from label or prior encryption |
| FIL-01-T11 | FIL-01.11 | low-order public share and one-bit bad MAC | wrap/open | generic failure; no plaintext/key returned; normal recipients use file-specific standard derivation |
| FIL-01-T12 | FIL-01.12 | valid prefix with missing/bad final chunk, appended bytes, swapped/repeated/cross-file chunks | decrypt | one generic error, zero final-output writes during initial validation |
| FIL-01-T13 | FIL-01.13 | same ciphertext in LF/CRLF armor; changed base64 bits; trailing nonspace | decrypt | legal transport variants identical; invalid body/junk generic failure, no output |
| FIL-01-T14 | FIL-01.14 | unknown stanza plus valid X25519 and unknown-only file | decrypt | first succeeds only after all authentication; second generic failure, zero child processes |
| FIL-01-T15 | FIL-01.15 | hostile identity text containing command/plugin paths | select key | refused without execution or service calls; valid explicit list bounded and Rust-owned |
| FIL-01-T16 | FIL-01.16 | encrypted native identity file and nested encrypted/oversized decoded file | decrypt selected data file | valid native identity works after complete key-file authentication; recursion/size failure generic and no data output |
| FIL-01-T17 | FIL-01.17 | unlocked writable demo vault and save failure | create file key | success saves protected key before use; failure no usable unsaved selection and no private UI return |
| FIL-01-T18 | FIL-01.18 | every failure stage plus success and lock during KDF | end operation | all owned secret buffers released/wiped; independent memory proof remains OPEN for both Mac targets |
| FIL-01-T19 | FIL-01.19 | source/dependency graph and hostile FFI calls | review/operate | imports/RNG boundary holds, no secret-bearing view/error/Debug and no new unsafe outside platform |
| FIL-01-T20 | FIL-01.20 | native PQ public recipient or identity supplied | select/open | explicit unsupported-selection help or generic decrypt error; no fallback or claim that PQ is unpublished |
| FIL-01-T21 | FIL-01.21 | independently re-encrypted replacement/replay with valid recipient | decrypt | valid plaintext may be accepted; UI never claims original sender or latest version |
| FIL-01-T22 | FIL-01.22 | weak passphrase file copied to a demo offline attacker | assess promise | offline guesses are possible and disclosed; E22 makes no service request, and all Larsal service no-verifier obligations remain unchanged |

## Edge cases and errors

All decrypt credential/structure/integrity/unsupported-recipient/limit failures map to MSG-FILE-DECRYPT of FIL-03. Pre-operation user input and filesystem/cleanup errors have the distinct own-word messages there; no contents, keys or upstream error string are interpolated.

## Lead decisions and security notes

Research R1–R6 are unadopted. FIL-01-T12 and FIL-03-T04/T06 remain OPEN: complete syntax/credential/header/payload/final-marker/EOF validation must precede final output or plaintext. A normal stream reader alone fails this original corruption check. Later post-validation I/O/crash faults are separate; a handled cancellation with surviving incomplete output fails the unchanged S4 check, even with a correct warning. S3 must list every published vector and the supported/unsupported/policy mapping; unsupported vectors cannot be counted as successful interoperability. Two sensitive Checkers and independent Verify are required, no self-sign-off.

## How this was learned

Public standards and official library/implementation documentation only, linked in the research evidence register. Existing Larsal cards and source were read to preserve boundaries and reuse approved behavior. No reference access, translated implementation, package installation or runtime encryption evidence.
