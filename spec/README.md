# Spec cards

Spec cards keep the clean room working. Spec agents read the reference source and run the reference app, then write what it does in our own words. Builders build only from these cards and public standards. They never open the reference source.

## Rules for cards

- Our words only. No reference code, no code translated from it, no reference names.
- Facts needed to read and write the same files are allowed: byte layouts, constants, algorithm ids, field names inside the file, default values. Facts are not code.
- Every rule has an ID (for example `FMT-06.3`) and at least one test case.
- Mark what is security relevant and link the parity rows in [plan/security.md](../plan/security.md).
- When a behavior is unclear, write what you observed and how, and mark it `check with Verify`.
- One card per file: `spec/<area>/<ID>-<short-name>.md`, for example `spec/format/FMT-06-block-integrity.md`.

## Card template

```
# <ID> <Title>

Status: draft | reviewed
Epics: <story IDs that build from this card>
Parity rows: <SF-01, ...>

## What it does
<Plain description, in our words.>

## Inputs and outputs
<What goes in, what comes out, with types and limits.>

## Rules
<ID>.1 <One testable rule.>
<ID>.2 ...

## Edge cases and errors
<Each case and the exact expected behavior or message.>

(Optional) ## Lead decisions
<Questions for the lead, with options and a recommendation; once ruled, "Decided: spec/decisions.md LD-xx".>

## Security notes
<What could go wrong, what must never happen.>

## Test cases
| Case | Given | When | Then |
|---|---|---|---|

## How this was learned
<Which parts of the reference source or app were studied, described without names: for example "the save routine", "the settings screen".>
```

## Cards to write

### Format (`spec/format/`)

| ID | Card | Built in |
|---|---|---|
| FMT-01 | File layout, versions and the interop matrix | E3, E0-S5 |
| FMT-02 | Outer header fields and their limits | E3-S2 |
| FMT-03 | The KDF settings map | E3-S2 |
| FMT-04 | Key flow: composite key and derived keys | E3-S3 |
| FMT-05 | Header integrity and the wrong-key rule | E3-S4 |
| FMT-06 | Block integrity stream, version 4 | E3-S4 |
| FMT-07 | Hashed block stream, version 3 | E3-S4, E3-S8 |
| FMT-08 | Payload encryption and compression | E3-S5 |
| FMT-09 | Inner header and the protected-field stream | E3-S5 |
| FMT-10 | Document: vault metadata | E3-S6 |
| FMT-11 | Document: groups and entries | E3-S6 |
| FMT-12 | Encodings: times, booleans, ids, binary data | E3-S6 |
| FMT-13 | Attachment pool and references | E3-S5, E3-S6 |
| FMT-14 | Custom icons and custom data | E3-S6 |
| FMT-15 | Deleted objects | E3-S6 |
| FMT-16 | Choosing the file version on save | E3-S7 |
| FMT-17 | Version 3 differences | E3-S8 |
| FMT-18 | Key files: kinds, reading, creating | E3-S3 |

### Crypto (`spec/crypto/`)

| ID | Card | Built in |
|---|---|---|
| CRY-01 | Ciphers, modes, IV and nonce sizes | E2-S4 |
| CRY-02 | Key derivation: algorithms, defaults, limits, benchmark | E2-S5 |
| CRY-03 | Random values made on each save | E3-S7 |
| CRY-04 | Signatures, HPKE and key wrap | E16-S2 |

Status: CRY-04 reviewed 2026-10-31 (E16-S1, Verify signed).

### Model (`spec/model/`)

| ID | Card | Built in |
|---|---|---|
| MOD-01 | Entry fields, standard and custom | E3-S1, E4-S1 |
| MOD-02 | Groups and what entries inherit from them | E4-S1 |
| MOD-03 | History rules | E4-S2 |
| MOD-04 | Recycle bin | E4-S3 |
| MOD-05 | Attachments | E4-S4 |
| MOD-06 | Icons | E4-S5 |
| MOD-07 | Tags | E4-S5 |
| MOD-08 | References and placeholders | E4-S6 |
| MOD-09 | Expiry | E4-S7 |
| MOD-10 | Clone options | E4-S7 |
| MOD-11 | Merge rules | E4-S12 |
| MOD-12 | Vault settings and field protection flags | E4-S14 |
| MOD-13 | Master key change reminders | E4-S14 |

### Features (`spec/features/`)

| ID | Card | Built in |
|---|---|---|
| FEA-01 | Search language and rules | E4-S8 |
| FEA-02 | Password generator | E4-S9 |
| FEA-03 | Passphrases and the word list | E4-S9 |
| FEA-04 | One-time passwords: storage forms and codes | E4-S10 |
| FEA-05 | Strength estimate and Health Check | E4-S11 |
| FEA-06 | Breach check | E4-S11 |
| FEA-07 | Statistics | E4-S11 |
| FEA-08 | Import formats | E4-S13 |
| FEA-09 | Export formats | E4-S13 |
| FEA-10 | [Show as QR Code](features/FEA-10-show-as-qr.md) | E21-S1 (spec and proposals); E21-S2 to E21-S5 after review |

Status: FEA-10 revised DRAFT 2026-11-04 (E21-S1), after fresh second Spec SEND BACK A1–A8. Revised card, nine proposed frames per theme and scoped APP-10 correction await revised Spec review then fresh independent Verify. Proposed LD-359–362 and E21-S1/S2/S4/S5 aftertexts are external and unadopted; original acceptance remains unpassed until joint recording. Functional Share, enterprise/device proof and other unproved runtime checks remain OPEN. No implementation or Done; W-18 and frame approval remain pending.

### Larsal (`spec/app/`)

| ID | Card | Built in |
|---|---|---|
| APP-01 | Settings inventory and defaults | E1-S8, E5-S9 |
| APP-02 | Lock rules | E6-S2 |
| APP-03 | Clipboard rules | E6-S1 |
| APP-04 | Quick unlock | E6-S3 |
| APP-05 | Saving, backups, changes on disk | E4-S15, E5-S10 |
| APP-06 | Unlock screen behavior and messages | E3-S9, E5-S3 |
| APP-07 | New vault wizard | E5-S8 |
| APP-08 | Menus, shortcuts, menu bar icon | E5-S11 |
| APP-09 | Single instance and the app's command line flags | E5-S1 |
| APP-10 | Screen protection and secure input | E6-S5 |
| APP-11 | Process hardening | E6-S4 |

Status: APP-01 to APP-11 previously reviewed; APP-10's scoped capture-claim correction is DRAFT in this E21-S1 revision pending revised Spec review and fresh Verify, with secure-input rules and historical evidence retained. APP-06, APP-07 and APP-08 had their second Spec review in Sprint 3 (E1-S5), with the rulings LD-95 to LD-100 written in.

### Integrations (`spec/integrations/`)

| ID | Card | Built in |
|---|---|---|
| INT-01 | Browser bridge protocol | E7-S1 |
| INT-02 | Association and site access | E7-S2 |
| INT-03 | URL matching | E7-S3 |
| INT-04 | Passkeys | E7-S5 |
| INT-05 | Auto-Type sequences, placeholders and window matching | E8 |
| INT-06 | SSH agent | E9 |
| INT-07 | Hardware keys | E10 |
| INT-08 | Shared groups | E11 |
| INT-09 | Remote sync | E11 |
| INT-10 | Command line tool commands, with a parity table | E12 |
| INT-11 | Browser extension | E7-S7c to E7-S7n |

Status: INT-04 and INT-10 written (draft). INT-08 reviewed 2026-10-31 (E11-S1: Verify against the reference, second Spec review passed; W-15 decided, LD-262 (6)). INT-10 written 2026-10-28: 28 commands, 50 parity rows, 11 lead decisions (D-INT10-1 to D-INT10-11); it waits for its second Spec review. The others are written just in time (plan/epics.md E1-S6). INT-06 and INT-07 written 2026-10-28 (draft): INT-06 SSH agent, 44 rules, 73 test cases, D-INT06-1 to D-INT06-7; INT-07 hardware keys, 33 rules, 53 test cases, D-INT07-1 to D-INT07-7; both wait for their second Spec review. INT-05 written 2026-10-28 (draft): Auto-Type, 47 rules, 107 test cases, D-INT05-1 to D-INT05-16 (`spec/integrations/INT-05-auto-type.md`); it waits for its second Spec review. INT-01, INT-02 and INT-03 written 2026-10-28 (draft): INT-01 browser bridge protocol, 42 rules, 65 test cases, D-INT01-1 to D-INT01-11 (`spec/integrations/INT-01-browser-bridge.md`); INT-02 association and site access, 32 rules, 73 test cases, D-INT02-1 to D-INT02-14 (`spec/integrations/INT-02-association-site-access.md`); INT-03 URL matching, 19 rules, 86 test cases, D-INT03-1 to D-INT03-8 (`spec/integrations/INT-03-url-matching.md`); all three wait for their second Spec review. INT-09 written 2026-10-28 (draft): remote sync, 30 rules, 52 test cases, D-INT09-1 to D-INT09-9 (`spec/integrations/INT-09-remote-sync.md`); E11's scope stays the owner's (D-INT09-1). INT-08 and INT-09 second review 2026-10-28: 27 fixes (INT-08 12, INT-09 15), 5 findings (R08-1 to R08-3, R09-1, R09-2); INT-08's decisions are now D-INT08-1 to D-INT08-10. Review findings fixed 2026-10-28 (INT-09 now 54 test cases, T01 to T54). Both stay draft until the owner rules E11's scope. Checker sample findings fixed 2026-10-28: every rule of INT-01 to INT-10 has a test case naming it (INT-01 now 77 test cases, INT-03 90, INT-05 111); INT-01 records its retired rule numbers; INT-04 had its second Spec review (13 fixes, now 82 test cases; finding R04-1 waits for the lead before E7-S5, LD-215). INT-11 reviewed 2026-11-01 (E7-S7a: six Spec reviews, Verify round 4 signed): 44 rules, 89 tests.

### Sync (`spec/sync/`)

| ID | Card | Built in |
|---|---|---|
| SYN-01 | Wire protocol | E16-S3, E16-S4, E16-S5, E16-S7a |
| SYN-02 | Server store | E16-S3, E16-S4, E16-S5 |
| SYN-03 | Client sync and the rollback guard | E16-S7a, E16-S7b, E16-S9 |
| SYN-04 | Devices, sign-in and sessions | E16-S5, E16-S6, E16-S7a, E17-S3 |
| SYN-05 | The code two screens compare | E17-S2, E18-S4 |
| SYN-06 | Accounts, the account secret, the Recovery Kit and a new Mac | E17-S1, E17-S2, E17-S4 |

Status: SYN-01 to SYN-06 written 2026-10-31 (draft, E16-S1, from spec/research/sync-server.md and public standards; the reference app has no server); reviewed 2026-10-31 (six Spec reviews, Verify signed). D-SYN06-1 decided: (a), spec/decisions.md LD-273 (2).

### Sharing (`spec/sharing/`)

| ID | Card | Built in |
|---|---|---|
| SHR-01 | Shared vault keys, wraps and epochs | E18-S3, E18-S5, E18-S6, E18-S7, E18-S8 |
| SHR-02 | The signed member list | E18-S2, E18-S3, E18-S6, E18-S7, E18-S8 |
| SHR-03 | Invites, roles and write checks | E18-S3, E18-S4, E18-S6, E18-S7, E18-S8 |
| SHR-04 | Removal, leaving and the list of passwords a removed member saw | E18-S5, E18-S7, E18-S8 |

Status: SHR-01 to SHR-04 written 2026-11-01 (draft, E18-S1, from spec/research/sync-server.md and public standards; the reference app has no server or sharing): 59 rules, 102 test cases; reviewed 2026-11-01 (three Spec reviews, Verify signed round 3). D-SHR01-1, D-SHR01-2, D-SHR02-1, D-SHR02-2 and D-SHR04-1 decided by spec/decisions.md LD-290.
