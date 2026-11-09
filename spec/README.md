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
| CRY-05 | [Quantum-safe keys](crypto/CRY-05-quantum-safe-keys.md): every public-key use, the hybrid KEM and HPKE suite, the composite signature, TLS, the words | E25-S2 to E25-S6 |

Status: CRY-04 reviewed 2026-10-31 (E16-S1, Verify signed).

Status: CRY-05 Done 2026-11-09 (E25-S1, LD-521): 20 rules, 34 test cases, 32 uses; new rules in the cards that use public keys: CRY-04.15, SYN-01.16, SYN-06.14, SHR-01.17, SHR-02.16, SHR-03.16, FIL-01.23, each with one test case.

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
| FEA-10 | [Show as QR Code](features/FEA-10-show-as-qr.md) | E21-S1 (reviewed spec and proposals only); E21-S2 to E21-S5 remain todo |

Status: FEA-10 reviewed 2026-11-05 (E21-S1 written contract and static proposals only), after second Spec corrections and fresh independent Verify APPROVE with no required findings. Commit d413e06 jointly adopted the exact card/index/proposals/scoped APP-10 package and E21/LD-359–362 records. Only LD-359/360's exact capacity and external Share persistence amendments supersede their original clauses; refusals and disabled actions pass neither. All other acceptance stays required. Functional Share, enterprise/device proof and other unproved runtime checks remain OPEN. Owner proposal review and W-18 wording remain pending without blocking implementation; existing story dependencies and technical reviews apply (LD-363). Proof: FEA-10's Review and proof footer.

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

Status: APP-01 to APP-11 reviewed; APP-10's scoped capture wording/case correction was reviewed and independently verified as written-contract-only E21-S1 work, jointly adopted in d413e06. Secure-input rules and historical evidence are retained; actual capture QA remains OPEN, with no new SC-05/AT-D04 sign-off. APP-06, APP-07 and APP-08 had their second Spec review in Sprint 3 (E1-S5), with the rulings LD-95 to LD-100 written in.

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


### Files (`spec/files/`)

| ID | Card | Built in |
|---|---|---|
| FIL-01 | [File format and keys](files/FIL-01-format-and-keys.md) | E22-S2, E22-S3 |
| FIL-02 | [Screens and flows](files/FIL-02-screens-and-flows.md) | E22-S4, E22-S5 |
| FIL-03 | [Limits and errors](files/FIL-03-limits-and-errors.md) | E22-S3 to E22-S6 |

Status: FIL-01 to FIL-03 reviewed 2026-11-05 (E22-S1 specification and static proposals only), after second Spec corrections and fresh independent Verify APPROVE with no required findings. Owner commit `c8fa2f1` adopted the exact research/cards/index/proposals and central source package; LD-366–371 record R1–R6, AT-FILE-01–14 and FILE-P1–4 are final catalog identifiers with runtime proof OPEN. All original acceptance and dependencies remain unchanged, including S3 corruption/no-plaintext/no-plaintext-temp/bounded-memory and S4 cancel-leaves-no-partial-output. Original technical/sensitive reviews and E22-S2 AT-J03/package/tool/corpus download gates govern implementation; no runtime PASS or new general permission gate. Owner frame review/W-18 wording are nonblocking under LD-220/268/363. FIL-04–06 remain E23-S1’s separate encrypted-folder scope under its original dependency. Proof: the research [Review and proof](research/file-encryption.md#review-and-proof) footer.

### Encrypted folders (E23-S1 reviewed specification)

| ID | Card | Built in |
|---|---|---|
| FIL-04 | [Folder format and keys](files/FIL-04-folder-format.md) | E23-S2, E23-S3, E23-S6 |
| FIL-05 | [Folder screens and flows](files/FIL-05-folder-screens.md) | E23-S4, E23-S5, E23-S6 |
| FIL-06 | [Folder limits and conflicts](files/FIL-06-folder-limits-and-conflicts.md) | E23-S3 to E23-S6 |

Status: FIL-04–06 reviewed 2026-11-05 (E23-S1 specification and static proposals only), after seven second-Spec corrections and fresh independent Verify APPROVE with no required findings. LD-372–378 record R1–7 exactly; AT-FOLD-01–16 and FOLD-P1–5 are final catalog identifiers with all runtime proof OPEN/todo. LD-364/365 remain reserved. Original acceptance/Order, all other story statuses and required successful capabilities remain unchanged. Every implementing proof remains OPEN: S3 one-changed-byte/generic-error/zero-plaintext; first-party Open with own-view closure/no readable disk copy, semantic text/image/PDF and exact arbitrary supported-file bytes; content/shared-header GCM budgets and unknown peer history; Unicode/secure transport/wiping; encrypted recovery-name/journal custody, quota/races/crash/ownership; named FFI/rendering API no-disk/index/cache/lifetime review; foreign CRUD/both directions/parallel-GCM/speed/required4GB; native accessibility/device/capture and signed Finder S5 after S4/D7/W-02. Authentic truncation/replay/substitution remain separate S6 handling/disclosure; refusal or warning never passes a required success. Original dependencies, technical/sensitive reviews and E23-S2 itemized AT-J03/package/tool/corpus download gates govern implementation. Exact dependency/license/advisory/checksum closure remains unresolved where uncomputed; no API/download grant or runtime PASS. Owner frame review and W-18 wording remain nonblocking under LD-220/268/363; no new permission gate or owner frame approval. Locked Option A and proposal frames/captions remain exact. Conditional adoption/closure proof: the research [Review and proof](research/encrypted-folders.md#review-and-proof) footer.


### E24-S1 passkeys and SSH everywhere — proposed 2026-11-05

DRAFT only: [research and source status](research/passkeys-and-ssh.md), [INT-04 E24 appendix](integrations/INT-04-passkeys.md#e24-s1-proposed-extension--2026-11-05) (26 new rules/cases) and [INT-06 E24 appendix](integrations/INT-06-ssh-agent.md#e24-s1-proposed-extension--2026-11-05) (30 new rules/cases). [Option A proposal frames](../design/option-a/proposals.html#e24-s1) cover native provider, protected exchange, key generation, approval/revocation, git signing and public-only extension/web/CLI surfaces in both themes. Pre-existing card bodies, IDs/cases, implemented behavior and dated proofs are preserved; proposed conflicts require explicit Lead adoption. Signing D7/W-02 and custody/backend/identity/API reviews are later implementation gates, not S1 prerequisites. No runtime pass, second Spec review, independent Verify, central/status change or Done is claimed; original E24 order/checks remain required. Next: fresh second Spec, then independent Verify and selective Lead adoption with actual-current guard.


## E24-S1 review and adoption record

2026-11-05: the exact revised specification and static proposals received fresh second Spec and independent Verify APPROVE, with R1–R4/N1 closed. The sealed pre-adoption complete source manifest is `8e0f22f647e509c5263995837624f57a5b2f6fb136a8b7f8c28c87ae54a1f4a1`; second Spec seal `5d3c7d944de41b109064b0d3cf51ec8b10c68825dc6c89a8962c48e762a91091`; Verify seal `f345bd00ee81226d2219d17909092c3b686d2be29850231feeb380e19c6d0dc2`. Proof covers56 rule/case/source pairs,112 fresh removal controls,80 themed source-bound PNGs plus2 accepted long captures and129 older frames/rectangles preserved per theme. Verify corrected contact-sheet accounting without changing the images or earlier proof. The full canonical frozen-source guard passed11604 scanned files plus19 vault names; actual-current adoption guard remains Root's separate requirement.

The DRAFT/unadopted status labels in the sealed appendices describe their pre-adoption state. This record and LD-380–396 adopt their written contracts only and explicitly supersede the listed legacy clauses for E24 implementation; historical rules/cases/proof keep their old scope. AT-KEY-01–18 and KEY-P1–7 are final catalog IDs with all runtime proof OPEN/todo. All17 acceptance conflicts remain visible in those rulings and their implementing gates; no successful capability is waived. G01–G05, Apple receiver identity, private Data/copy/transport custody, provisioned signing, signer backends, peer identity, descriptor feasibility and every implementing positive/hostile/removal/native/AX/capture obligation remain OPEN. Static evidence proves no running provider, exchange, generation, signing or secure custody. Detector/storage/bootstrap findings remain recorded externally. Original187-story scope, E24 Order and all S2–S7 acceptance/status lines are unchanged. Root closes only S1 after selective current-source equality, actual-current canonical guard and its owner-only commit; no implementation or runtime PASS follows.
