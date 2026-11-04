# SYN-05 The code two screens compare

Status: reviewed
Epics: E17-S2 (its first use: approving a new Mac), E18-S4 (invites; SHR-03 builds on this card), E16-S8 and E17-S4 (the frames and screens)
Parity rows: none in the reference app (it has no server or sharing). Larsal's own row: AT-L10 (plan/attacks-and-checks.md)

## What it does

Before one Mac trusts another party's keys (a new Mac of the same account, or a person invited to a group), both screens show the same 6-digit code, and the people compare it, in person or on a call. The code is made from both sides' public keys, the request and two random nonces. The side that speaks first commits to its keys and nonce with a hash before it sees the other side's, so a party in the middle, the server included, gets one guess only: 1 in 1,000,000.

This card owns the protocol, the code and the rules of the screens. SYN-06.11 says which keys a new Mac presents and what happens after "Codes match"; SHR-03 (E18-S1) does the same for invites.

Design and sources: spec/research/sync-server.md P10 (decided: spec/decisions.md LD-263 (9): 6 digits).

## Inputs and outputs

- Roles: **C**, the side that commits first (the new Mac, or the invitee); **R**, the side that answers (the Mac that approves, or the inviter).
- In: `ctx`, the bytes that name the request (SYN-06.11 or SHR-03 builds it, always with a label and the request's id); `K_C` and `K_R`, each side's public keys as one CRY-04.2 field list; a fresh 32-byte nonce on each side from larsal-crypto's random source.
- Messages, carried by the server (which may be hostile): (1) C → R: `commit`; (2) R → C: `K_R`, `n_R`; (3) C → R: `K_C`, `n_C`.
- Out: the same 6-digit code on both screens when nobody changed a message; each side then holds the other's keys, to pin after "Codes match".

## Rules

SYN-05.1 **Commitment** (P10; the ZRTP pattern, RFC 6189 section 4.4.1.1). C draws `n_C` and sends `commit = SHA-256(field list ("sync-compare-commit-v1", ctx, K_C, n_C))` (CRY-04.2). C sends `K_C` and `n_C` only in message (3), after it has R's message (2).

SYN-05.2 **Order.** R sends message (2) only after it has stored `commit`, and draws `n_R` only then. C sends message (3) only after it has message (2). Each request accepts exactly one `commit` and one message (2) and (3): a second one of any of them ends the request (the server answers 409 and R refuses it too), so an attacker cannot try a second commitment (E17-S2 check: one guess).

SYN-05.3 **Check of the reveal.** R recomputes `commit` from message (3) and compares it with the stored one in constant time (CRY-04.11). A difference ends the request on both sides with `MSG-CODE-FAILED`, and no code is shown.

SYN-05.4 **The code.** `h = SHA-256(field list ("sync-compare-code-v1", ctx, K_R, K_C, n_R, n_C))`; the code is the first 8 bytes of `h` read as a u64 big endian, modulo 1,000,000, written as 6 digits with leading zeros in two groups of 3 (`042 917`). The order of the fields is fixed by role, so both sides compute the same value. The modulo bias (2^64 mod 10^6 over 2^64) is below 10^-13.

SYN-05.5 **The screens.** Each Mac shows the code with `MSG-CODE-COMPARE` (Check that the other screen shows the same code: <code>) and two buttons, Codes match and Codes differ (neither is the default). There is no option to skip the compare and no "never ask" setting (E18-S7). Codes differ ends the request on both sides and nothing is sealed, signed or pinned. A side acts on the other's keys (seals, signs, pins) only after its own user chose Codes match.

SYN-05.6 **Lifetime.** A request lives as long as the card that uses it says (SYN-06.11: 15 minutes) and is used once. The nonces and the stored `commit` are wiped when the request ends, whichever way.

SYN-05.7 **What the server sees.** The commitment, both key lists and both nonces, once revealed. It never sees the code before both reveals, and it cannot choose one that matches on both screens: whatever it does in the middle, the two codes are equal by chance only, 1 in 10^6 per request (P10).

## Messages

| ID | Words (Larsal's own) | Buttons |
|---|---|---|
| `MSG-CODE-COMPARE` | Check that the other screen shows the same code: <code> | Codes match, Codes differ |
| `MSG-CODE-FAILED` | The check did not work. Nothing was shared. Start again on both Macs. | OK |

## Edge cases and errors

- R gets message (3) before it sent message (2): refused, the request ends.
- C gets a second message (2) with other keys: the request ends.
- A reveal 16 minutes after the request started (SYN-06.11): refused, the request ends.
- The code starts with zeros (`000 417`): shown with them.
- One side's user chose Codes match, the other Codes differ: the request ends with nothing done; the first side's match has no effect.

## Security notes

- **One guess (AT-L10).** A party in the middle must give C a message (2) before it learns `n_C`, and must commit to its own `K_C'` and `n_C'` toward R before it learns `n_R`. So each code it causes is random to it when it must decide, and the two match with probability 10^-6 (RFC 6189 section 4.4.1.1 for the same pattern with a 16-bit code).
- **Why short.** Users seldom compare long numbers (sync-server.md section 5, the commercial manager's Appendix C); the commitment makes 6 digits enough. Signal's 60 digits need no protocol state but are long (section 7).
- **What it fixes.** Comparing the code and then pinning the keys is the out-of-band public key check of the ETH paper (section 5.1), which closes the key-swap attacks BW09, LP07 and DL02 (sync-server.md section 6).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 SYN-05.1, SYN-05.4 same code | Two test clients C and R; an honest relay | Run messages (1) to (3) | Both show the same 6 digits; recomputing from the logged messages gives the same value |
| T02 SYN-05.4 known value | `ctx` = field list ("test", 16 bytes of 0x11); `K_C` = field list (32 bytes of 0x22); `K_R` = field list (32 bytes of 0x33); `n_C` = 32 bytes of 0x44; `n_R` = 32 bytes of 0x55 | Compute the code with an independent SHA-256 (for example `shasum -a 256` over the bytes) | Larsal's code equals it |
| T03 SYN-05.3 swapped key | A test relay that replaces `K_C` in message (3) | Run | R: `MSG-CODE-FAILED`; no code shown; nothing sealed |
| T04 SYN-05.7 relay in the middle | A test relay that runs its own C toward R and its own R toward C, with its own keys | Run 10,000 times with fresh nonces | The two screens' codes match by chance only (0.01 matches expected in 10,000 runs; the test fails on more than 2); in no run did either side seal or pin before its user's Codes match |
| T05 SYN-05.2 second commitment | A request with one commitment | Send a second commitment | 409; R refuses it; the request ends |
| T06 SYN-05.2 order | R | Send message (3) before message (2) | Refused, the request ends |
| T07 SYN-05.5 no skip | The compare screen | Look for any way past it but the two buttons (keyboard, menu, settings) | None; Return does nothing (no default) |
| T08 SYN-05.5 codes differ | An honest run | One user picks Codes differ | Both sides end; nothing sealed, signed or pinned |
| T09 SYN-05.6 wiped | A request that ended | Read the client's state and the server's rows | No nonce and no commitment left |
| T10 SYN-05.4 leading zeros | A test seam that fixes the nonces so the value is 417 | Show | `000 417` |

## How this was learned

- Public sources only; the reference app has no server or sharing.
- spec/research/sync-server.md P10 and sections 5 to 7.
- RFC 6189 (ZRTP), section 4.4.1.1 (commit first; one guess) and section 4.5.2 (the short code): <https://www.rfc-editor.org/rfc/rfc6189.html>.
- Signal, safety numbers: <https://signal.org/blog/safety-number-updates/>; Bitwarden, Log in with device (a phrase compared before approval; 15 minutes): <https://bitwarden.com/help/log-in-with-device/>.
- Scarlata, Torrisi, Backendal, Paterson, USENIX Security 2026, section 5.1 (public key authentication): <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>.
- Written by E16-S1 (2026-10-31).
