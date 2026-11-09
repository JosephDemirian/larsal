# SYN-06 Accounts, the account secret, the Recovery Kit and a new Mac

Status: reviewed
Epics: E17-S1 (sign-up, account keys, the blob, the recovery key, the wrapped key-file part, upload signing), E17-S2 (a new Mac by approval or Recovery Kit), E17-S3 (dropping account data), E17-S4 (the screens), E16-S8 (the frames)
Parity rows: none in the reference app (it has no accounts). Larsal's own rows: SV-01, SV-03 (plan/security.md); AT-L06, AT-L10, AT-L12 (plan/attacks-and-checks.md)

## What it does

An account is a random id plus public keys; it has no email. At sign-up the Mac makes a random 256-bit account secret, an Ed25519 identity key (it signs) and an X25519 key (it receives wrapped keys). The private keys go to the server only wrapped, under a key made from the account password (Argon2id, on the Mac) and the account secret together (HKDF). Without the account secret nobody can test password guesses against that blob. The Recovery Kit is the account secret, printed or saved once.

A new Mac gets the account in one of two ways: an existing Mac approves it after both screens show the same code (SYN-05), then seals the account secret to it; or the Recovery Kit plus the account password. Either way the account password is typed on the new Mac.

Other cards: SYN-01 owns the routes, SYN-04 device keys and sessions, SYN-05 the compare, CRY-04 the crypto, SYN-03 the key-file part this card wraps.

Design and sources: spec/research/sync-server.md P6, P7, P10, P13 (decided: spec/decisions.md LD-263 (5), (6), (9), (12), LD-273 (2), (4)).

## Inputs and outputs

- In: the account password (typed on the Mac, through the unlock-screen path into Rust, APP-06, LD-220); larsal-crypto's random source.
- Out: on the Mac, the account secret and keys in the device store (SYN-06.8); on the server, the public keys, the signature on the X25519 key, the recovery public key and the account blob (SYN-06.6).
- Sizes: account secret 32 bytes; account id 16 bytes; identity seed 32; X25519 private key 32; blob at most 4 KiB.

## Rules

SYN-06.1 **Sign-up secrets** (P6). After SYN-04.2 made the account, the Mac draws from larsal-crypto's random source: the account secret `S_acct` (32 bytes), the identity key (an Ed25519 seed, CRY-04.3) and an X25519 key pair (CRY-04.5). The identity key signs the X25519 public key: the CRY-04.2 field list (`sync-x25519-v1`, `account_id`, the X25519 public key).

SYN-06.2 **The account password.** Typed on the Mac only; never sent anywhere, in any form. At least 8 characters: NIST SP 800-63B-4 section 3.1.1.2 allows 8 for a password used only with a second factor, and here the account secret is the second secret. Larsal shows its strength (FEA-05). It is used exactly as typed, with no normalization and no trimming, as FMT-04.1 does for a master password.

SYN-06.3 **The wrap key** (P6; CRY-04.9). `A` = Argon2id over the password's UTF-8 bytes, with a fresh 32-byte salt, 3 iterations, 64 MiB, 4 lanes, version 0x13, a 32-byte output: RFC 9106 section 4's second recommended option, with Larsal's 32-byte salt (CRY-02.23 uses 32 too). `K_wrap` = HKDF-SHA256 (RFC 5869) with salt `account_id`, input key material `S_acct || A` and info `sync-account-key-v1`, 32 bytes. Both secrets go into one extract step, so neither alone gives `K_wrap`.

SYN-06.4 **The account blob.** Version 1 holds: the version (1), the Argon2id salt, the 12-byte nonce, and the AES-256-GCM ciphertext and tag (CRY-04.7) of the identity seed followed by the X25519 private key, with the associated data the field list (`sync-account-blob-v1`, `account_id`, the version as a u16 big endian, the salt). The Argon2id settings are those of SYN-06.3, fixed by the version: a reader refuses any other version, so a hostile server cannot make Larsal run a costly KDF or a weak one.

SYN-06.5 **The recovery sign-in key** (P6). `seed_R` = HKDF-SHA256 with salt `account_id`, input key material `S_acct` and info `sync-recovery-key-v1`, 32 bytes; it is the seed of an Ed25519 key (CRY-04.3). The server stores only its public key.

SYN-06.6 **Account keys on the server.** `PUT /v1/account/keys` with `If-None-Match: *` sends `{"identity_public_key","x25519_public_key","x25519_signature","recovery_public_key","blob"}`; the server stores them once and refuses a second PUT with 412 (no key change in this build). `GET /v1/account/keys` returns them. After each GET the client checks: the X25519 signature verifies with the identity key, and the identity key equals the one this Mac pinned (made here at sign-up, or learned in the compare of SYN-06.11 or by unwrapping in SYN-06.12). A failure: `MSG-ACCOUNT-KEYS-CHANGED`, and the Mac stops using the account until the user acts.

SYN-06.7 **The Recovery Kit** (P6). A text with: the kit format `1`, the server address and its certificate fingerprint (SYN-01.2), the `account_id` as 32 hex digits, and `S_acct` in base32 (RFC 4648 section 6, upper case, no padding: 52 characters, in groups of 4). Larsal shows it once, right after sign-up, with Print and Save as PDF (E17-S4). Larsal writes it nowhere else: not to a log, a crash report, the state file or the general pasteboard (E17-S4: the kit is printed or saved as a PDF, shown once).

SYN-06.8 **What this Mac keeps.** `S_acct`, the identity seed and the X25519 private key are kept in the device store (SYN-04.1's store; this device only once W-02 is answered), as `SecretBytes`, so this Mac signs uploads and opens wraps without asking for the account password again. The account password is typed at sign-up, on a new Mac, and after this Mac dropped its account data (SYN-04.9). Decided: spec/decisions.md LD-273 (2) (D-SYN06-1 below).

SYN-06.9 **The key-file part through the server** (P7; E17-S1; LD-266 (2)). For each personal vault this Mac links (SYN-03.1), it wraps the part `F` to the account's own X25519 key as a signed wrap record (CRY-04.6) with info = the field list (`sync-wrap-info-v1`, `keypart`, `account_id`, `vault_id`), signed by the identity key, and sends it with `PUT /v1/vaults/{vault_id}/keypart`. Another Mac of the account gets it with GET, checks that the signer is the pinned identity key, opens it with the info it builds itself, and puts `F` into its device store. This replaces the test helper's copy of E16-S7b.

SYN-06.10 **Upload signing** (P4, P11; E17-S1). From E17-S1 every upload of a personal vault carries the identity key's signature of SYN-01.7, and every Mac checks it (SYN-03.11).

SYN-06.11 **A new Mac by approval** (P6 (1), P10; Bitwarden's Log in with device: 15 minutes). The new Mac is N; the Mac that approves is E.
1. On E the user picks Add a Mac. E draws the code, 16 bytes from larsal-crypto's random source, and sends only its SHA-256 with `POST /v1/approvals` (`{"code_hash"}`). The server answers `{"approval_id","expires"}` and stores only the hash, so it first sees the code at the claim (step 2), as it sees a session token (plan/architecture.md, "What the server sees": codes as hashes). The code is shown as base32 in groups of 4, valid 15 minutes, used once. E shows the code, the server address and its fingerprint.
2. On N the user adds the server (comparing the fingerprint as SYN-01.2 says) and types the code. N makes its device key (SYN-04.1) and a one-request X25519 key pair (CRY-04.5), and sends `POST /v1/approvals/claim` with `Authorization: Approval <code>` and `{"device_public_key","device_name","commit"}`. The commitment is SYN-05.1's, with `K_C` = the field list (N's device public key, N's one-request X25519 public key) and `ctx` = the field list (`sync-approval-v1`, `account_id`, `approval_id`). A code already claimed gets 409; an expired or unknown code gets 401.
3. E reads the claim (`GET /v1/approvals/{approval_id}`) and sends `POST …/keys` with `K_R` = the field list (the identity public key, E's device public key) and `n_R`.
4. N reads it and sends `POST …/reveal` with `K_C` and `n_C`. Both screens show the code (SYN-05.4, SYN-05.5).
5. After Codes match on E: E seals `S_acct` to N's one-request X25519 key as a signed wrap record (CRY-04.6) with info = the field list (`sync-wrap-info-v1`, `account-secret`, `account_id`, `approval_id`, N's device public key), and signs N's device: the field list (`sync-device-v1`, `account_id`, N's device public key, `approval_id`). It sends both with `POST …/seal`. The server checks the device signature with the account's identity key and registers N's device (a `devices` row, SYN-02.3), or answers 403.
6. After Codes match on N: N reads the seal, checks that the signer is the identity key from step 3's `K_R`, opens it with the info it builds itself, and signs in with its device key (SYN-04.4). It then reads the account keys (SYN-06.6), asks for the account password, unwraps the blob (SYN-06.3, SYN-06.4) and checks that the unwrapped identity seed gives the identity public key it compared. Only then does N pin it and keep the secrets (SYN-06.8).
Codes differ on either side, a failed check, a second claim or commitment, or 15 minutes: `DELETE /v1/approvals/{approval_id}`; nothing is sealed or registered. No device is registered before E's Codes match.

SYN-06.12 **A new Mac by Recovery Kit** (P6 (2)). On N the user types the kit (or opens the saved PDF's text). N pins the server by the kit's fingerprint (the kit is the user's own record), derives `seed_R` (SYN-06.5), makes its device key, gets a nonce with `POST /v1/recovery/challenge` (`{"account_id"}`; same reply for unknown accounts) and sends `POST /v1/recovery/signin` with `{"account_id","nonce","device_public_key","device_name","signature"}`, the recovery key signing the field list (`sync-recovery-signin-v1`, origin, nonce, `account_id`, the device public key). The server checks it with the stored recovery public key as SYN-04.4 checks a device, registers the device and answers with a session. N then reads the account keys, asks for the account password, unwraps the blob and pins the identity key it unwrapped. A wrong kit or a wrong password gives one plain message, `MSG-ACCOUNT-RESTORE-FAILED`, with no detail on which was wrong.

SYN-06.13 **No email, no reset, no escrow** (P6, P13). No route takes or stores an email address in this build; email comes with billing (E17-S6), never as a sign-in factor (NIST SP 800-63B-4 section 3.1.3.1). Nothing on the server, and no admin, can restore an account without `S_acct` and the account password: a lost kit and lost Macs lose the account. Local vaults still open with their master password and key-file part (save the part as a key file, SYN-03.12); members of a shared vault invite the new account again (P13).

SYN-06.14 **Quantum-safe account keys** (E25-S3, E17-S1; CRY-05.8, LD-510). Where SYN-06.1 to SYN-06.12 name the identity key, the X25519 key and their sizes, CRY-05.8 holds from E25-S3: the identity key is CRY-05.5's composite ML-DSA-65 + Ed25519 key (public 1,984 bytes, private 64) and signs only with the composite signature; the X25519 key is an X-Wing receiving key (public 1,216 bytes, a 32-byte seed); its binding is the composite signature over (`sync-kem-key-v1`, `account_id`, the receiving public key); the account keys record is `{"identity_public_key","kem_public_key","kem_signature","recovery_public_key","blob"}`; the blob's plaintext is the identity private key followed by the receiving seed (96 bytes, version 1, never written before); SYN-06.9's key-file part wrap and SYN-06.11's seal use CRY-05.4's record, and SYN-06.11's one-request key is an X-Wing key pair. The recovery sign-in key of SYN-06.5 and SYN-06.12 stays Ed25519 (CRY-05.13). Security relevant.

## Messages

| ID | Words (Larsal's own) | Buttons |
|---|---|---|
| `MSG-ACCOUNT-KIT` | This is your Recovery Kit. Print it or save it, and keep it safe. Larsal shows it only now. | Print, Save as PDF, Done |
| `MSG-ACCOUNT-ADD-MAC` | On the new Mac, add this server and type this code: <code>. It works for 15 minutes. | Cancel |
| `MSG-ACCOUNT-RESTORE-FAILED` | The Recovery Kit or the account password is not right. | OK |
| `MSG-ACCOUNT-KEYS-CHANGED` | The server sent other account keys than this Mac knows. Larsal stopped using this account. | OK |

## Lead decisions

D-SYN06-1 **Where this Mac keeps the account's private keys.** (a) In the device store, this device only, as SYN-06.8 says: the account password is typed on a new Mac and after a sign-out everywhere; routine sync signs uploads with no question. (b) In memory only: Larsal asks for the account password each time it starts and a linked vault needs the identity key (every upload from E17-S1). Recommended: (a). Why: the device store already holds the account secret and every key-file part (P5, P7), so (b) adds a question at each start without protecting anything the device store does not; Bitwarden's and the commercial manager's Mac apps keep the unlocked key in the system key store for biometric unlock (spec/research/sync-server.md sections 4 and 5). Decided: spec/decisions.md LD-273 (2): (a).

## Edge cases and errors

- The account password has 7 characters: refused at sign-up with the strength meter's message.
- The kit is typed with lower-case letters or without the hyphens: accepted (base32 is read case-blind, separators ignored).
- The kit names another server: N asks to add that server first.
- Two Macs try to claim one approval code: the first gets 201, the second 409.
- E's user picks Codes match after 15 minutes: the seal gets 404; nothing registered.
- The blob on the server has version 2: N refuses it ("Larsal needs an update to use this account").
- N's account password is wrong after an approval: `MSG-ACCOUNT-RESTORE-FAILED`; N stays registered and may try again (rate limits apply only on the server; the blob test runs on N).

## Security notes

- **Nothing to guess on the server (SV-03, AT-L06).** The blob needs `K_wrap`, which needs `S_acct` (256 random bits) as well as the password; a full copy of the server cannot test password guesses (P6; the two-secret design of the large commercial password manager, without its SRP).
- **Signed keys, pinned keys (AT-L12).** The server cannot swap the account's keys for a Mac that already knows them (SYN-06.6), cannot register a device without the identity key's signature (SYN-06.11 step 5), and cannot replace the sealed account secret, because N checks the seal's signer against the key it compared (step 6) and the info binds the seal to this approval and this device.
- **The kit is the account.** Whoever has the kit and the password owns the account; Larsal shows it once and never copies it to the general pasteboard.
- **No reset (P13).** Escrow and admin reset are where the ETH paper's BW01, BW02, BW03 and LP01 attacks come from (sync-server.md section 6); Larsal has neither.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 SYN-06.1 to SYN-06.6 sign-up (E17-S1) | A new account (SYN-04.2) | Sign up with password `demo-account-pw` | The server's keys row holds four public values and a blob; the X25519 signature verifies; nothing on the server equals `S_acct`, the seeds or the password, or their SHA-256 |
| T02 SYN-06.3 two secrets (E17-S1) | Every row and file of the server; the right account password; no `S_acct` | A test tries to open the blob | It opens nothing |
| T03 SYN-06.3 known value | Password `demo`, salt 32 bytes of 0x01, `S_acct` 32 bytes of 0x02, `account_id` 16 bytes of 0x03 | Compute `K_wrap` with Larsal, and with an independent Argon2id (the RFC 9106 reference implementation) and HKDF (Python's `hmac` module, RFC 5869 steps) | Equal |
| T04 SYN-06.4 blob version | A blob of version 2; a version 1 blob with one changed byte of the salt, the nonce, the ciphertext or the tag | Unwrap | Version 2 refused before any Argon2id run; each changed byte fails with `MSG-ACCOUNT-RESTORE-FAILED` |
| T05 SYN-06.6 swapped keys | A test server that returns another identity key after sign-up | GET keys | `MSG-ACCOUNT-KEYS-CHANGED`; no upload signed, no wrap opened |
| T06 SYN-06.7 the kit (E17-S4) | Sign-up, with Larsal's pasteboard record of LD-206 on (tests use a private named pasteboard and never read the general one, AGENTS.md rule 10) | Read the kit; search logs and the state file; read the record of pasteboard writes | The kit holds format `1`, the address, the fingerprint, the account id and 52 base32 characters; shown once; found nowhere else; the record holds no write of the kit |
| T07 SYN-06.9 key-file part (E17-S1) | Clients A and B of one account, vault D linked on A | B opens D | B gets `F` from the server's wrap, not from the test helper (the helper is gone); a wrap signed by another key, or with info naming another vault, is refused |
| T08 SYN-06.10 upload signing (E17-S1) | As T07 | A test server accepts an upload with a missing signature, and one signed by an unknown key | B refuses both versions (SYN-03.11) |
| T09 SYN-06.11 approval (E17-S2) | E signed in; N new | Run steps 1 to 6 with Codes match on both | N registered only after E's match; N's code equals E's; N opens the blob with the password and pins the identity key; the E16-S7a and E16-S7b tests pass with N as the second device; a test proxy finds only the code's SHA-256 in `POST /v1/approvals`, never the code |
| T10 SYN-06.11 swapped key (E17-S2) | A test relay that swaps N's one-request X25519 key in the claim | Run | The codes differ; with Codes differ chosen nothing is sealed and no device is registered |
| T11 SYN-06.11 expired, reused (E17-S2) | An approval code | Claim after 15 min 1 s; claim twice; send a second commitment | 401; 201 then 409; 409 |
| T12 SYN-06.11 forged seal | A test server that replaces the sealed record with one sealed by its own key, and one that registers N without E's device signature | Run | N refuses the seal (wrong signer); the server's own check refuses the registration (403); a test server that skips that check still gets no account secret into N |
| T13 SYN-06.12 Recovery Kit (E17-S2) | An account; an empty demo app state on N | Restore with the kit and the password | N registered with a session; the account keys unwrap; the vault list shows the account's vaults |
| T14 SYN-06.12 wrong kit or password | As T13 | Restore with one changed kit character; with a wrong password | `MSG-ACCOUNT-RESTORE-FAILED` both times, with the same words |
| T15 SYN-06.13 no email | The server's routes and rows | Search for any email field | None |
| T16 SYN-06.2 short password | Sign-up | Password of 7 characters; of 8 | Refused; accepted |
| T17 SYN-06.5 recovery key | SYN-06 T03's `S_acct` and `account_id` | Derive the recovery seed and public key with Larsal and with an independent HKDF and Ed25519 (RFC 8032 section 5.1.5) | Equal; the server's stored recovery public key equals it after sign-up |
| T18 SYN-06.8 kept on this Mac | N after T09 | Quit and start Larsal; sync | No account password asked; the device store holds `S_acct` and both private keys; the state file and logs hold none of them |
| T19 SYN-06.14 hybrid account keys (E25-S3) | A new account | Sign up; then add a second Mac by approval (SYN-06.11) | The keys row and the blob have CRY-05.8's names and sizes (CRY-05 T14); the seal of `S_acct` is a `[25722, 1, 3]` record with a composite signature, and N opens it; a classical record or an Ed25519-only binding offered by a test server is refused |

## How this was learned

- Public sources only; the reference app has no accounts.
- spec/research/sync-server.md P6, P7, P10, P13 and sections 4 (the large commercial password manager's Secret Key and Emergency Kit; SRP and OPAQUE), 5 (Bitwarden's Log in with device, 15 minutes), 7 (Threema ids) and 8 (NIST, OWASP).
- RFC 9106 section 4 (Argon2id, second recommended option: t=3, p=4, 64 MiB), read 2026-10-31: <https://www.rfc-editor.org/rfc/rfc9106.html>. RFC 5869 (HKDF): <https://www.rfc-editor.org/rfc/rfc5869.html>. RFC 4648 (base32): <https://www.rfc-editor.org/rfc/rfc4648.html>.
- NIST SP 800-63B-4 section 3.1.1.2 (at least 8 characters for a password used only with another factor) and section 3.1.3.1 (email is not out-of-band authentication), read 2026-10-31: <https://pages.nist.gov/800-63-4/sp800-63b.html>.
- Written by E16-S1 (2026-10-31).
