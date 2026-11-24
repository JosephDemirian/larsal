# CRY-04 Signatures, HPKE and key wrap

Status: reviewed
Epics: E16-S2 (larsal-crypto `sign.rs`, `hpke.rs`, `wrap.rs`); used by E16-S5, E16-S6, E17-S1, E17-S2, E18-S2 to E18-S5
Parity rows: none in the reference app (it has no server or accounts); AT-B01 (known answers) applies. Larsal's own rows: SV-03 (plan/security.md); AT-L12 (plan/attacks-and-checks.md)

## What it does

This card fixes the crypto that sync, accounts and sharing use, all in larsal-crypto (AGENTS.md rule 3): Ed25519 signatures, ECDSA P-256 signature checks, HPKE base mode for one suite, a signed record for a wrapped key, AES-256-GCM key wrap, HKDF-SHA256 and the two-secret key of the account. It also fixes one way to put several fields into bytes for signing and binding, and the labels each use carries. Our code only arranges the approved crates; nothing here is home-made crypto.

Design and sources: spec/research/sync-server.md P5, P6, P8, sections 7 and 11 (decided: spec/decisions.md LD-263 (4), (5), (7), (19), LD-266 (5)).

## Inputs and outputs

| Function | In | Out |
|---|---|---|
| Ed25519 key from seed | 32-byte seed (secret) | signing key; 32-byte public key |
| Ed25519 sign | signing key, message | 64-byte signature |
| Ed25519 verify | 32-byte public key, message, 64-byte signature | ok, or `SignatureInvalid` |
| P-256 verify | 65-byte SEC1 public key, message, DER signature (at most 72 bytes) | ok, or `SignatureInvalid` |
| X25519 key pair | larsal-crypto's random source | 32-byte private key (secret), 32-byte public key |
| HPKE seal | recipient public key, info (at most 512 bytes), plaintext (at most 1 KiB) | enc (32 bytes), ct (plaintext + 16 bytes) |
| HPKE open | recipient private key, enc, info, ct | plaintext (secret), or `WrapInvalid` |
| Signed wrap: make | recipient public key, info, plaintext, signer id, signer's Ed25519 key | wrap record (CRY-04.6) |
| Signed wrap: open | record, trusted signer public key, expected info, recipient private key | plaintext (secret), or `WrapInvalid` |
| AES-256-GCM wrap | 32-byte key (secret), associated data, plaintext (at most 4 KiB) | nonce (12) ‖ ciphertext ‖ tag (16) |
| AES-256-GCM unwrap | key, associated data, wrapped bytes | plaintext (secret), or `WrapInvalid` |
| HKDF-SHA256 | salt, input key material (secret), info, length 32 | 32 bytes (secret) |
| Two-secret key | account password (secret), Argon2id salt, account secret (secret), account id | `K_wrap` (secret) |

## Rules

CRY-04.1 **Crates** (LD-263 (7), (19); LD-221; plan/architecture.md, "Approved crates to add"). Only larsal-crypto imports them:
- Ed25519: `ed25519-dalek` (=3.0.0, approved, with `curve25519-dalek` 5.0.0);
- P-256: `p256` (=0.14.0, feature `ecdsa`, approved);
- HPKE: `hpke`, no default features, features `x25519`, `aes`, `alloc` (no ML-KEM), with `x25519-dalek` and `zeroize_derive`; new in the tree, each after its AT-J03 review, at the newest release at least 14 days old on the day E16-S2 starts (LD-266 (5); on 2026-10-31 that is hpke 0.14.1 and x25519-dalek 3.0.0), as Larsal's own copy in `vendor/` (LD-221);
- AES-256-GCM: `aes-gcm` (0.11.1, in the tree through ssh-key; it gets its own approved-table line, LD-263 (19), sync-server.md section 11);
- HKDF and SHA-256: `hkdf` and `sha2` (approved); Argon2id: `argon2` (approved, CRY-02.2);
- constant-time compares: `subtle`; wiping: `zeroize`; randoms: `larsal-crypto::random` (CRY-03.9).
No other crate does any of this, and no other Larsal crate imports them.

CRY-04.2 **Field lists** (Larsal's own arrangement). Where a card says "the field list (f1, f2, …)", the bytes are, for each field in order, its length as a u32 big endian, then its bytes. The first field is always an ASCII label from the table below; integers are written as fixed-size big-endian bytes (u16 for suite ids and blob versions, u64 for vault versions); ids are their 16 raw bytes; public keys are their raw encodings. Why: no two different field lists give the same bytes, so a signature or a binding made for one use can never be read as another.

| Label | Use | Card |
|---|---|---|
| `sync-signin-v1` | a device's sign-in message (P-256) | SYN-04.4 |
| `sync-recovery-signin-v1` | the recovery key's sign-in message (Ed25519) | SYN-06.12 |
| `sync-upload-v1` | an upload signature (Ed25519) | SYN-01.7 |
| `sync-wrap-v1` | the signature on a wrap record (Ed25519) | CRY-04.6 |
| `sync-wrap-info-v1` | the HPKE info of a wrap (its second field names the purpose: `keypart`, `account-secret`, `vault-key` (SHR-01.9)) | SYN-06.9, SYN-06.11, SHR-01.9 |
| `sync-x25519-v1` | the identity key's signature on the X25519 key | SYN-06.1 |
| `sync-device-v1` | the identity key's signature on a new device | SYN-06.11 |
| `sync-approval-v1` | the compare's `ctx` for a new Mac | SYN-06.11 |
| `sync-compare-commit-v1`, `sync-compare-code-v1` | the code compare | SYN-05.1, SYN-05.4 |
| `sync-account-key-v1` | HKDF info of `K_wrap` | SYN-06.3 |
| `sync-account-blob-v1` | associated data of the account blob | SYN-06.4 |
| `sync-recovery-key-v1` | HKDF info of the recovery seed | SYN-06.5 |
| `sync-member-entry-v1` | a member-list entry (Ed25519) | SHR-02.2, SHR-02.3 |
| `sync-member-hash-v1` | the hash of a member-list entry | SHR-02.3 |
| `sync-member-consent-v1` | a newcomer's consent to its add entry (Ed25519) | SHR-03.8 |
| `sync-member-list-code-v1` | the list code two members compare | SHR-02.13 |
| `sync-vault-key-check-v1` | the key check of a shared vault's epoch key | SHR-01.5 |
| `sync-share-upload-v1` | an upload signature on a shared vault (Ed25519) | SHR-03.10 |
| `sync-invite-v1` | the compare's `ctx` for an invite | SHR-03.7 |

CRY-04.3 **Ed25519** (RFC 8032 section 5.1). Pure Ed25519: no prehash, no context. The private key is a 32-byte seed (section 5.1.5), the public key 32 bytes, a signature 64 bytes (section 5.1.6). Verification is strict (ed25519-dalek `verify_strict`): it refuses a signature whose S is not below the group order L (section 5.1.7), and refuses small-order public keys and R values. A public key that does not decode is `SignatureInvalid`.

CRY-04.4 **ECDSA P-256, verify only** (FIPS 186-5 section 6.4.2; SEC1 v2 sections 2.3.4, 3.2.2.1 and 4.1.4). The message is hashed with SHA-256 (the Secure Enclave's message algorithm does the same, SYN-04.1). The public key is the 65-byte SEC1 uncompressed form `04 ‖ X ‖ Y`, checked to be a point on the curve and not the point at infinity; the compressed and hybrid forms are refused. The signature is the DER `ECDSA-Sig-Value` (SEC1 v2 appendix C.5): strict DER, no trailing bytes, r and s from 1 to n − 1. A high s is accepted, because the Secure Enclave does not normalize it, and every message Larsal checks this way holds a one-time nonce (SYN-04.3), so a second valid form of one signature gains nothing. In sync, larsal-crypto never signs with P-256 (E9-S2's `ssh.rs` signs with it for Larsal's own SSH agent): the Secure Enclave or the keychain key signs (SYN-04.1).

CRY-04.5 **HPKE** (RFC 9180; P8). Base mode only, single shot (`SealBase`, `OpenBase`, sections 5.1.1 and 6.1), with one suite: KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0002 AES-256-GCM (section 7; Nk 32, Nn 12, Nt 16; Npk, Nsk and Nenc 32). The associated data is empty; every context goes into `info`, which each use builds as a field list (CRY-04.2), with the identities in it (section 5.1.3). Key pairs come from larsal-crypto's random source. Open fails, with one error `WrapInvalid`, on a tag that does not verify, an enc of the wrong length, or an X25519 result of all zero bytes (RFC 9180 section 7.1.4; RFC 7748 section 6.1). No psk, auth or export modes, and no other suite: base mode does not say who sent the wrap (RFC 9180 section 9.8: "in the Base mode, there is no authentication of the remote party at all"), so CRY-04.6 signs it (section 9.1.1: a signature over (enc, ct) with the sender's private key). Private key bytes are whatever the vendored release writes; from hpke 0.15 X25519 keys are clamped when written (sync-server.md section 7), so Larsal never compares private key bytes across releases.

CRY-04.6 **The signed wrap record** (P8; RFC 9180 section 9.1.1; the ETH paper's ciphertext authentication). A record holds: the suite (0x0020, 0x0001, 0x0002), enc, ct, info, the signer's id (16 bytes) and an Ed25519 signature over the field list (`sync-wrap-v1`, the suite as three u16, enc, ct, info, signer id). Opening runs in this order, and any failure is `WrapInvalid` with no detail:
1. the suite is the one suite above;
2. the record's info equals, byte for byte, the info the caller built for what it expects (the caller never takes the info from the record);
3. the signature verifies with the public key the caller trusts for that signer (pinned: SYN-06.6, SHR-02);
4. HPKE open (CRY-04.5).
Records are at most 4 KiB (SYN-01.10). On the wire (SYN-01.8) a record is the JSON object `{"suite":[32,1,2],"enc":…,"ct":…,"info":…,"signer":…,"signature":…}`: the suite as three numbers, `enc`, `ct`, `info` and `signature` as base64url without padding, and `signer` as 32 lowercase hex digits (LD-327 (4)).

CRY-04.7 **AES-256-GCM key wrap** (NIST SP 800-38D). A 32-byte key, a fresh 12-byte nonce from larsal-crypto's random source for every wrap (the random IV construction, section 8.2.2), a 16-byte tag, associated data given by the caller (SYN-06.4). Output: nonce ‖ ciphertext ‖ tag. A key wraps only a few blobs in its life, far below the 2^32 limit for random nonces (section 8.3). Unwrap fails with `WrapInvalid` on any change of the key, the nonce, the ciphertext, the tag or the associated data.

CRY-04.8 **HKDF-SHA256** (RFC 5869): extract with the given salt, then expand with the given info, to 32 bytes. Its uses are SYN-06.3 and SYN-06.5.

CRY-04.9 **The two-secret key** (P6; SYN-06.3). `A` = Argon2id (RFC 9106; CRY-02.2's algorithm) over the account password's UTF-8 bytes with the given 32-byte salt and the fixed version-1 settings: 65,536 KiB, 3 iterations, 4 lanes, version 0x13, a 32-byte output (RFC 9106 section 4, second recommended option). `K_wrap` = HKDF-SHA256 (CRY-04.8) with salt = the account id, input key material = account secret ‖ `A`, info = `sync-account-key-v1`. The function takes no other settings, so no caller can run it weaker or costlier.

CRY-04.10 **Secrets** (AGENTS.md rule 4). Every private key, seed, account secret, HPKE shared secret, plaintext of a wrap, `A` and `K_wrap` lives only in `SecretBytes` (wiped on drop), with no `Debug` or `Display` output, and never goes into a log, an error value or a crash report. Public keys, signatures, enc, ct and nonces are not secret.

CRY-04.11 **Constant-time compares.** Commitments (SYN-05.3), pinned public keys and any hash compared for trust are compared with `subtle`, in constant time.

CRY-04.12 **Random values** (CRY-03.9, CRY-03.15). Every key, seed, nonce, salt and secret comes from `larsal-crypto::random`; a failed draw fails the operation and nothing is written; nothing is derived from time, a counter or a non-cryptographic generator.

CRY-04.13 **Known answers** (gate G3, AT-B01; E16-S2). Kept as test data in the tree, each file with its source link:
- Ed25519: RFC 8032 section 7.1, TEST 1, TEST 2, TEST 3 and TEST SHA(abc); and Wycheproof `ed25519_test.json`: every case marked valid verifies, every case marked invalid fails.
- P-256: RFC 6979 appendix A.2.5, the SHA-256 signatures of "sample" and "test", written as DER, verify with its key; Wycheproof `ecdsa_secp256r1_sha256_test.json` (DER signatures): every valid case verifies, every invalid case fails, and every case marked acceptable fails (Larsal's DER is strict).
- HPKE: every base-mode (mode 0) record with kem_id 32, kdf_id 1, aead_id 2 in the RFC 9180 [TestVectors] JSON file, cfrg/draft-irtf-cfrg-hpke at commit 5f503c564da00b0687b3de75f1dfbdfc4079ad31 (RFC 9180 Appendix A has no vector for this suite): each listed encryption opens to its plaintext with the record's skRm, enc and info; and with the record's ephemeral key put in through a test seam (tests only), seal gives the record's enc and ct.
- AES-256-GCM: the NIST CAVP GCM vectors of `gcmEncryptExtIV256.rsp` with 96-bit IVs and 128-bit tags, and the 256-bit-key, 96-bit-IV cases of Wycheproof `aes_gcm_test.json`.
- HKDF-SHA256: RFC 5869 appendix A, test cases 1 to 3.
- Argon2id: CRY-02's RFC 9106 section 5.3 vector (no new one).
- Waiver (LD-305, until the owner says yes to that download, rule 7): Wycheproof `ed25519_test.json` (T02) and the cases of `ecdsa_secp256r1_sha256_test.json` marked acceptable (T05) are not in the tree. T05 runs the valid and invalid cases of the p256 0.14.0 copy's `wycheproof.blb`, and T11's Wycheproof cases are the aes-gcm 0.11.1 copy's `wycheproof-256_pass.blb` and `wycheproof-256_fail.blb`.

CRY-04.14 **One changed byte fails.** One changed byte of enc, ct, info, the signer id or the signature of a wrap record gives `WrapInvalid`; one changed byte of a P-256 or Ed25519 message, public key or signature gives `SignatureInvalid`; one changed byte of an AES-256-GCM wrap or its associated data gives `WrapInvalid`.

## Edge cases and errors

- An Ed25519 signature with S = L + (the right S): refused (CRY-04.3).
- A P-256 public key with a valid X but Y off the curve: refused.
- A DER signature with a leading zero byte too many in r (not minimal), or with 1 trailing byte: refused.
- An HPKE enc of 31 bytes, or the all-zero X25519 point as enc: `WrapInvalid`.
- A wrap record with suite 0x0020, 0x0001, 0x0003: refused at step 1, before any signature check.
- A wrap record whose info is valid for another vault: refused at step 2.
- A plaintext over 1 KiB for HPKE, or 4 KiB for AES-256-GCM: refused before any work.

## Security notes

- **Why sign the wrap.** In base mode anyone can encrypt a chosen key to anyone's public key ("anyone can encrypt a chosen symmetric key under the public key of any user", ETH paper on BW08); signing (suite, enc, ct, info) with the sender's identity key is the fix both RFC 9180 section 9.1.1 and the paper give (sync-server.md sections 6 and 7).
- **Why info.** `info` binds a wrap to its purpose, account, vault, epoch and recipient, so a wrap moved to another place does not open (RFC 9180 section 5.1.3).
- **One suite.** No suite choice is offered to the other side; a record with another suite is refused, so no downgrade is possible. The suite id stays in the record so a later suite (X-Wing, P8) can be added with a new version.
- **The two-secret key** needs both the 256-bit account secret and the password: a stolen blob alone cannot be attacked with password guesses (P6, SV-03).
- **Two Checkers** review every change to this card's code (team.md: crypto).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 CRY-04.13 Ed25519 vectors | RFC 8032 section 7.1 TEST 1 to 3, TEST SHA(abc) | Sign each message with its seed; verify | Signatures equal the RFC's; all verify |
| T02 CRY-04.13 Ed25519 Wycheproof | `ed25519_test.json` | Verify each case | Valid cases pass, invalid cases fail |
| T03 CRY-04.3 strict | TEST 1's signature with S + L; a small-order public key with any signature | Verify | Both `SignatureInvalid` |
| T04 CRY-04.13 P-256 RFC 6979 | RFC 6979 A.2.5 key, "sample" and "test" with SHA-256, as DER | Verify | Both pass |
| T05 CRY-04.13 P-256 Wycheproof | `ecdsa_secp256r1_sha256_test.json` | Verify each case | Valid pass; invalid and acceptable fail |
| T06 CRY-04.4 encodings | The RFC 6979 key in compressed form; a DER signature with one trailing byte; a high-s form of a valid signature | Verify | Refused; refused; passes |
| T07 CRY-04.13 HPKE vectors | The base-mode 0x0020/0x0001/0x0002 records of the TestVectors file at commit 5f503c5… | Open each encryption; seal with the record's ephemeral key | Plaintexts equal; enc and ct equal |
| T08 CRY-04.5 round trip | A fresh X25519 key pair; info I; 32-byte plaintext | Seal, then open with I; open with I plus one byte | Plaintext back; then `WrapInvalid` |
| T09 CRY-04.6 record order | A valid record | Open with: another suite; another expected info; another trusted key; one changed byte of ct | `WrapInvalid` each time; with another suite no signature check runs (a counter in the test seam) |
| T10 CRY-04.14 one byte | A valid record | Change one byte of enc, ct, info, signer id, signature, one at a time | `WrapInvalid` each time |
| T11 CRY-04.13 AES-256-GCM vectors | CAVP `gcmEncryptExtIV256.rsp` (96-bit IV, 128-bit tag) and Wycheproof `aes_gcm_test.json` (256-bit key, 96-bit IV) | Encrypt and decrypt each | Results equal; invalid cases fail |
| T12 CRY-04.7 nonce | Wrap one plaintext 1,000 times with one key | Read the nonces | 1,000 different nonces |
| T13 CRY-04.8, CRY-04.13 HKDF vectors | RFC 5869 A.1 to A.3 | Derive | OKM equals the RFC's |
| T14 CRY-04.9 two-secret key | SYN-06 T03's inputs | Derive | Equals the independent result of SYN-06 T03 |
| T15 CRY-04.10 no output | Every secret type of this card | Format with `{:?}` (prints `[hidden]`, plan/architecture.md's secret types) and search the logs of a full E17-S1 test run | No secret bytes anywhere |
| T16 CRY-04.2 field lists | Field lists ("a", "bc") and ("ab", "c") | Encode | Different bytes: `00000001 61 00000002 6263` and `00000002 6162 00000001 63` |
| T17 CRY-04.12 random failure | A test seam that makes the random source fail | Make a key pair, seal, wrap | Each fails with the random error; nothing returned |
| T18 CRY-04.1 crates | The tree after E16-S2 | `cargo tree -i hpke`, `-i x25519-dalek`, `-i aes-gcm`, `-i ed25519-dalek`, `-i p256`; search every Larsal crate's `use` lines | Each is reached from Larsal crates only through larsal-crypto; no other Larsal crate imports them; gate G1 passes offline with the vendored copies |
| T19 CRY-04.11 constant time | The code of SYN-05.3 and of every pinned-key compare | Checker reads each compare (gate G6) | Each uses `subtle`'s constant-time equality; none uses `==` on the bytes |

## How this was learned

- Public standards only; the reference app has no server, accounts or sharing.
- RFC 8032 (Ed25519; sections 5.1.5 to 5.1.7 and 7.1): <https://www.rfc-editor.org/rfc/rfc8032.html>.
- FIPS 186-5 (ECDSA; section 6.4): <https://csrc.nist.gov/pubs/fips/186-5/final>. SEC1 v2 (point encoding, key check, verification, `ECDSA-Sig-Value`): <https://www.secg.org/sec1-v2.pdf>. RFC 6979 appendix A.2.5 (P-256 vectors): <https://www.rfc-editor.org/rfc/rfc6979.html>.
- RFC 9180 (HPKE; sections 5.1.1, 5.1.3, 6.1, 7, 7.1.4, 9.1.1): <https://www.rfc-editor.org/rfc/rfc9180.html>; its test vectors at the pinned commit: <https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json>. RFC 7748 (X25519): <https://www.rfc-editor.org/rfc/rfc7748.html>.
- NIST SP 800-38D (GCM): <https://csrc.nist.gov/pubs/sp/800/38/d/final>; NIST CAVP block cipher modes (GCM vectors): <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes>.
- RFC 5869 (HKDF): <https://www.rfc-editor.org/rfc/rfc5869.html>. RFC 9106 (Argon2; section 4, the second recommended option, read 2026-10-31; section 5.3): <https://www.rfc-editor.org/rfc/rfc9106.html>.
- Wycheproof test vectors (C2SP): <https://github.com/C2SP/wycheproof/tree/main/testvectors_v1> (`ed25519_test.json`, `ecdsa_secp256r1_sha256_test.json`, `aes_gcm_test.json`, each read 2026-10-31).
- ed25519-dalek 3.0.0 `verify_strict` (refuses non-reduced S, small-torsion R and weak public keys): <https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html>, read 2026-10-31.
- spec/research/sync-server.md sections 6, 7 and 11; the ETH paper (Scarlata, Torrisi, Backendal, Paterson, USENIX Security 2026), section 5.1.
- Written by E16-S1 (2026-10-31).
