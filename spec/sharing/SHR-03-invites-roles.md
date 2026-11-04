# SHR-03 Invites, roles and write checks

Status: reviewed
Epics: E18-S3 (family roles, the limits, the upload signature, the server's 403, every client's check), E18-S4 (invites and the code compare), E18-S6 (team roles and per-vault rights; the server without `teams`), E18-S7 (the invite sheet, roles and the read-only words), E18-S8 (the hostile-server run)
Parity rows: none in the reference app (it has no server or sharing). App's own rows: SV-06 (plan/security.md); AT-L13, AT-L17, AT-L18, AT-L21, AT-L22 (plan/attacks-and-checks.md)

## What it does

This card says who may do what in a group, how a person joins, and how every Mac checks every upload of a shared vault.

- **Roles.** A family has Organizers (at most 2) and Members, at most 6 people, and everyone can edit. A team (the paid server folder) has Owners, Admins, Members and Read-only members, with a right per vault: Can view, Can edit or Can manage.
- **Invites.** An Organizer, Owner or Admin makes a one-time invite code (128 random bits, 5 days, no key inside) and sends it through any channel. Both Macs then run SYN-05's code compare. Only after "Codes match" on both sides does the newcomer sign its consent and the inviter sign the add entry and wrap the vault key. Both pin each other's identity key.
- **Write checks.** Reading is enforced by crypto (holding the key). Writing is enforced twice: the server refuses an upload from a member without the right (403), and every Mac checks that each version it reads is signed by a member who may edit, over the vault id, version, the SHA-256 of the bytes, the epoch and the uploader's member-list head.

Other cards: SYN-05 owns the compare protocol, its code and its screens; SHR-02 the member list and its accept rules; SHR-01 keys and wraps; SHR-04 removal and leaving; SYN-01 the vault routes this card extends.

Design and sources: spec/research/sync-server.md P10, P11, P19, sections 5 and 6 (decided: spec/decisions.md LD-262 (2), (3), LD-263 (9), (10), (17), LD-273 (4)).

## Inputs and outputs

- In: the verified state of SHR-02.5; this Mac's account keys (SYN-06.8); the invite text; the compare of SYN-05.
- Out: an `add` entry and wraps; upload headers; the decision to accept or refuse each downloaded version.
- Sizes: invite code 16 bytes; invite id 16 bytes; a member name 1 to 64 Unicode scalar values.

### Words

| ID | Words (App's own) | Buttons |
|---|---|---|
| `MSG-GROUP-INVITE` | Send this invite to <name>. It works once, for 5 days. | Copy, Done |
| `MSG-GROUP-INVITE-USED` | This invite was already used or has expired. Ask for a new invite. | OK |
| `MSG-GROUP-INVITE-FAILED` | The invite did not finish. Nothing was shared. Ask for a new invite. | OK |
| `MSG-GROUP-READ-ONLY` | Read-only members can see and copy every password in this vault. | none (members page and vault badge) |
| `MSG-GROUP-NO-TEAMS` | This server has no team sharing. | OK |

The compare itself shows SYN-05's `MSG-CODE-COMPARE` and `MSG-CODE-FAILED`.

## Rules

SHR-03.1 **Family roles** (P11; LD-262 (2); sync-server.md section 5: families of 6 people in the hosted products studied, and one organizer plus five members in a platform's family plan).

| Role | Reads and edits the vault | May manage (sign entries of SHR-03.3, wrap) |
|---|---|---|
| Organizer | yes | yes |
| Member | yes | no |

A family has exactly one shared vault, made with the group (SHR-01.4).

SHR-03.2 **Team roles and rights** (P11; sync-server.md section 5: collection levels View, Edit and Manage; "hidden password" levels "limit but don't prevent access", so App has none).

| Role | On every vault of the group | Signs |
|---|---|---|
| Owner | manage | everything of SHR-03.3 |
| Admin | manage | everything of SHR-03.3 except what touches an Owner |
| Member | its right per vault: none, view, edit or manage | `leave`; `grant` and `rotate` on a vault where it has manage |
| Read-only | its right per vault: none or view | `leave` |

`manage` includes `edit`, and `edit` includes `view`. "May read" a vault means at least `view`, "may edit" at least `edit`, "may manage" `manage`. A new team member has `none` on every vault until a `grant`.

SHR-03.3 **Who may sign which entry** (P9: "only if its signer was an owner or admin in the state before it"; sync-server.md section 5: "Only a current owner can invite new owners"). In the state before the entry (SHR-02.6 step 6):

| Action | Family | Team |
|---|---|---|
| `create` | anyone, as Organizer, at seq 1 | anyone, as Owner, at seq 1 |
| `add` | an Organizer; role Organizer or Member | an Owner or Admin; role Owner only by an Owner |
| `remove` | an Organizer; not the signer itself | an Owner or Admin; an Owner only by an Owner; not the signer itself |
| `leave` | the member itself | the member itself |
| `role` | an Organizer; not the signer itself | an Owner or Admin; to or from Owner only by an Owner; not the signer itself |
| `vault` | never | an Owner or Admin |
| `grant` | never | an Owner, an Admin, or a Member with manage on that vault; only to a Member or Read-only member; at most `view` to Read-only; not the signer itself |
| `rotate` | an Organizer | an Owner, an Admin, or a Member with manage on that vault |

In a `remove`, `role` or `grant`, `member_id` is never the signer. A manager steps down through another manager's entry, or leaves. Why: the signer of an entry that ends a right to read draws the new epoch's key (SHR-04.3), and it must still manage the vault after the entry to wrap that key (SHR-01.11); otherwise no Mac could wrap it.

SHR-03.4 **Limits** (P11; LD-262 (2)). The state after every entry keeps them (SHR-02.6 step 7):
- family: at most 6 people; while anyone is in it, 1 or 2 Organizers ("up to 2, so a lost account cannot freeze the list", P11);
- team: while anyone is in it, at least one Owner; at most 100 vaults (SHR-02's entry size, D-SHR02-2); no limit on people in this build (seats come with billing, LD-262 (2));
- both: an account appears once; one identity key belongs to one account; the last person may leave, and the group then ends (SHR-04.12).
So the last Organizer or Owner leaves only after making somebody else one, or as the last person.

SHR-03.5 **The paid folder** (P19; LD-263 (17), LD-266 (7)). Every client rule of SHR-01 to SHR-04, for families and teams, is GPL code in app-sync. On the server, the family rules are AGPL code in app-server; the team rules (SHR-03.2, the team column of SHR-03.3, `vault` and `grant` entries) are only in `crates/app-server-teams/`, linked through the cargo feature `teams`. A server built without `teams` answers a `create` of kind `team` with 403 and keeps no team group; App then shows `MSG-GROUP-NO-TEAMS`. The Mac app links no paid code.

SHR-03.6 **The invite** (P10; LD-273 (4): "A code the server draws would let the server answer its own challenge"). On the inviter's Mac R, the user picks Invite, types the person's name (SHR-03.14) and picks the role (Member unless the user picks another):
1. R checks in its own verified state that it may sign the `add` with that role and that the group has room (SHR-03.3, SHR-03.4).
2. R draws the code, 16 bytes from app-crypto's random source, and sends only its SHA-256: `POST /v1/groups/{group_id}/invites` with `{"code_hash","role"}`. The server checks the same in its state (403 otherwise) and answers `{"invite_id","expires"}`, 5 days on its clock (sync-server.md section 5: email invitations expire after five days).
3. R shows `MSG-GROUP-INVITE` with the invite text: the server's origin (SYN-04.4's form), its certificate fingerprint (SYN-01.2's form) and the code in base32 (RFC 4648 section 6, upper case, no padding: 26 characters, in groups of 4). The invite holds no key and nothing from the vault. R keeps the invite id, the code's SHA-256 and the role in its local state until the invite ends, and the name until it has written it into the vault (SHR-03.8 step 3), or until the invite ends with no `add` entry (step 4).
4. The invite is used once: by its first claim (SHR-03.7). It ends at the `add` entry that names its `invite_id`, at `DELETE`, 5 days after it was made if nobody claimed it, or 15 minutes after the claim (SYN-05.6; SYN-06.11's lifetime). Then the server deletes its row and both Macs wipe the compare's nonces and commitment (SYN-05.6).

Invite routes (SYN-01 conventions; "C" is the invitee, "R" the inviter, each with its own session):

| Method and path | Who | Body in | Body out | Statuses |
|---|---|---|---|---|
| `POST /v1/groups/{group_id}/invites` | R | `{"code_hash","role"}` | `{"invite_id","expires"}` | 201, 400, 401, 403, 404 |
| `POST /v1/invites/claim` | C | `{"code"}` | `{"invite_id","group_id","kind","role","inviter_id"}` | 201, 400, 401, 404, 409, 429 |
| `POST /v1/invites/{invite_id}/commit` | C | `{"commit"}` | none | 204, 400, 401, 404, 409 |
| `POST /v1/invites/{invite_id}/keys` | R | `{"keys","nonce"}` | none | 204, 400, 401, 404, 409 |
| `POST /v1/invites/{invite_id}/reveal` | C | `{"keys","nonce"}` | none | 204, 400, 401, 404, 409 |
| `POST /v1/invites/{invite_id}/consent` | C | `{"consent"}` | none | 204, 400, 401, 404, 409 |
| `GET /v1/invites/{invite_id}` | R or C | none | `{"commit","inviter_keys","inviter_nonce","invitee_id","invitee_keys","invitee_nonce","consent","expires"}`, each `""` until sent | 200, 401, 404 |
| `DELETE /v1/invites/{invite_id}` | R or C | none | none | 204, 401, 404 |

The claim answers an unknown, expired or ended code with one 404, a code already claimed with 409, and a claimer who is already a member with 409. It counts as a sign-in route for SYN-01.12's rate limit (10 a minute per IP address), as `/v1/approvals/claim` does. A second commit, keys, reveal or consent ends the request with 409 (SYN-05.2). Only the inviter and the claimer may call an invite's routes; anyone else gets 404.

SHR-03.7 **Joining: the compare** (P10; SYN-05). On the invitee's Mac C, the user pastes the invite text:
1. C adds the server from the invite (SHR-03.9), signs in, or signs up first when it has no account there (SYN-04.2, SYN-06.1 to SYN-06.7).
2. C sends `POST /v1/invites/claim` with the code. The server stores C's account id with the invite.
3. C builds `ctx` = the field list (`sync-invite-v1`, `invite_id`, `group_id`, kind, role, the inviter's account id, C's account id) from the claim's answer and its own id, and `K_C` = the field list (C's account id, identity public key, X25519 public key, the X25519 signature of SYN-06.1). It sends SYN-05.1's commitment with `POST …/commit`.
4. R reads the claim (`GET /v1/invites/{invite_id}`), builds `ctx` from its own invite record and the claimer's id, and sends `K_R` = the field list (R's account id, R's identity public key) and `n_R` with `POST …/keys`.
5. C reads them and sends `K_C` and `n_C` with `POST …/reveal`. R checks the reveal against the commitment (SYN-05.3) and that `K_C`'s X25519 signature verifies with `K_C`'s identity key.
6. Both screens show the code (SYN-05.4, SYN-05.5): "Check the code with the person you invited" on R, "Check the code with the person who invited you" on C.
A server that changes the group, the role, either id or either key list makes the two `ctx` or key lists differ, and so the two codes, except by the one chance in 10^6 of SYN-05.7.

SHR-03.8 **After "Codes match"** (P10: "Only after 'Codes match' does the admin sign the add entry and wrap the key"; the ETH paper's ciphertext authentication).
1. On C, after its user's Codes match: C signs its consent, Ed25519 over the field list (`sync-member-consent-v1`, `group_id`, `invite_id`, C's account id, C's identity public key, role, the inviter's account id), and sends it with `POST …/consent`. Joining sends nothing else: no key of C's, wrapped or plain, goes to anybody (no enrolment, SHR-04.13).
2. On R, after its user's Codes match: R reads the consent and checks it with the identity key in `K_C`. Then R updates its list (SHR-02.9), checks SHR-03.3 and SHR-03.4 again, and signs the `add` entry with `member_id`, `identity_key`, `x25519_key` and `x25519_signature` from the compared `K_C`, the role of `ctx`, the `invite_id` and the consent, on its head with `If-Match` (SHR-02.7; on 412 it reads the list and tries again, at most 3 tries). R pins C's keys (SHR-02.11).
3. For each vault C may read that is unlocked on R, R wraps its current key to C's compared X25519 key (SHR-01.9, SHR-01.11). A vault locked on R gets its wrap in the next run of it by a manager (SHR-01.11), and C shows `MSG-GROUP-WAITING-KEY` for it until then. R writes C's name (SHR-03.14) when the group's first vault is unlocked on R, at once or at R's next unlock of it.
4. C reads the list until it holds an `add` entry naming C, with C's own consent, signed by the identity key in the compared `K_R`. C checks the whole list from seq 1 (SHR-02.6, SHR-02.10), pins every key in it (SHR-02.11; R's key in the list must equal the compared one), reads its wraps and opens them (SHR-01.10), then downloads the group's vaults it may read (SYN-03.2's flow, with SHR-01.8's unlock).
Codes differ on either side, a failed check, or no `add` naming C within the request's 15 minutes: `DELETE …`, `MSG-GROUP-INVITE-FAILED` on both Macs, nothing signed, wrapped or pinned. No add entry for C is made before R's Codes match, and none is accepted without C's consent.

SHR-03.9 **The invitee adds the server** (SYN-01.2; SYN-06.12 pins by the kit's fingerprint in the same way). When the invite names a server C has not pinned, C makes one TLS handshake, compares the presented certificate's SHA-256 with the invite's fingerprint, and pins it with no question when they are equal; when they differ, App shows `MSG-SYNC-CERT-CHANGED` and adds nothing. A server C already pinned under another fingerprint is not changed. Why no question: the invite is the inviter's own record, and an invite changed on its way leads only to a compare that fails (SHR-03.7).

SHR-03.10 **The upload of a shared vault** (P11: "signed … over vault id, version and SHA-256 of the bytes"; D-SHR02-1 (a)). Every PUT of a shared vault carries, in place of SYN-01.7's signature:
- `Upload-Epoch: <epoch>` (decimal u64), the vault's current epoch at this Mac's head;
- `Upload-List-Head: <seq>:<hash>` (decimal u64, a colon, 64 lowercase hex digits), this Mac's head;
- `Upload-Signature: <base64url of 64 bytes>`, the identity key signing the field list (`sync-share-upload-v1`, `vault_id`, the new version as u64, the SHA-256 of the body, `group_id`, epoch as u64, head seq as u64, head hash).
The server stores the three values and the signer's id with the version (SYN-02.3) and returns them on `GET /v1/vaults/{vault_id}` with `Upload-Signer`. A signature made with SYN-01.7's label `sync-upload-v1` is never accepted for a shared vault, nor this one for a personal vault. The new headers have fuzz targets (SYN-01.15).

SHR-03.11 **The server's write check** (P11: "the server refuses uploads (403)"; sync-server.md section 5: "The server will reject any attempt from a read-only user of a vault to upload data to that vault"). After SYN-01.6's precondition checks, for a vault of a group, in the state at the server's head:
1. a caller who may not read the vault gets SYN-01.6's answer for a vault it may not read; a former member gets 403 (SHR-04.5);
2. a caller who may read but not edit gets 403;
3. a missing or malformed header of SHR-03.10 gets 400;
4. `Upload-List-Head` not equal to the server's head, or `Upload-Epoch` not the vault's epoch there, gets 412;
5. a signature that does not verify with the caller's identity key from the list gets 403;
6. `If-None-Match: *` is accepted only for a vault the list names and the store does not hold yet.
Then SYN-02.4 stores the version. On 412 the client updates the list (SHR-02.9) and its keys (SHR-01.13) before its next try (SYN-03.6).

SHR-03.12 **Every Mac's check of a version** (P11: "every client checks that each uploaded version is signed … by a member whose role allows editing"; architecture "Rules for this part" 3). Before it opens a downloaded version of a shared vault (it replaces SYN-03.11 for shared vaults), the Mac checks, in this order; a failure refuses the version as SYN-03.7 refuses a rollback (nothing merged or uploaded, and the group stays in use, except after `MSG-GROUP-FORK`, which stops it as SHR-02.9 says), with `MSG-GROUP-BAD-VERSION` (step 3: `MSG-GROUP-FORK`, or `MSG-GROUP-BAD-VERSION` for entries held back, as SHR-02.12 says):
1. `Upload-Signer`, `Upload-Signature`, `Upload-Epoch` and `Upload-List-Head` are present and well formed;
2. the signature verifies (CRY-04.3) with the identity key this Mac's verified list holds for the signer, over SHR-03.10's field list built from the vault id, the version the server sent, the SHA-256 of the bytes received, the vault's group id from this Mac's state (SHR-01.16) and the two header values; when the named head's `seq` is above this Mac's head, the Mac first updates its list (SHR-02.9), so a member added since is known. A header the server changed fails here, so only a head a member signed reaches step 3;
3. the named head passes SHR-02.12;
4. in the state at this Mac's head, the signer may still edit the vault (so a member removed or made read-only since cannot slip in a version made under an older head);
5. in the state at the named head, the signer may edit the vault and `Upload-Epoch` is the vault's epoch;
6. the epoch and the named head's `seq` are not below those of the last version this Mac accepted or uploaded for the vault (SHR-01.16): an honest server takes uploads only on its current head (SHR-03.11 step 4), so along the versions neither goes down;
7. SYN-03.7's version and hash guard.
Then SHR-01.3 and SHR-01.13. This is the check that counts: a server that accepts an upload it should have refused gains nothing.

SHR-03.13 **Read-only, said plainly** (P11). For a member who may read but not edit a vault, App opens that vault with editing turned off, and the members page and the vault's badge show `MSG-GROUP-READ-ONLY` (E18-S7). The screen never suggests that `view` hides anything.

SHR-03.14 **Member names** (App's own; accounts have no name or email, SYN-06.13). The inviter types the person's name with the invite, and the creator types their own name at `create`: 1 to 64 Unicode scalar values, none in the Unicode category Cc (as SYN-04.2). After the entry is accepted, that Mac writes the name into the custom data of the group's first vault, key `app.member-name.<32 lowercase hex of the account id>` (FMT-14). MOD-11.18 merges vault custom data as one container: the container with the newer `_LAST_MODIFIED` wins, and keys missing from it are removed. So when two Macs write a name between the same two syncs (two invites at once), one of the names can be lost. When the members page finds no name item for a member, an Organizer, Owner or Admin can type it again (Name… on that member's row), and so can the member for their own row. A member may change their own name item. Names live only inside the encrypted vault and, until the inviter writes them there, in the inviter's local state (SHR-03.6): never in an entry, a request field or a log. A Mac that cannot read the first vault, or finds no item, shows "Member <the first 8 lowercase hex digits of the account id>".

SHR-03.15 **When a right to edit ends** (P11). An entry that takes away somebody's right to edit a vault but leaves them the right to read it (for example a `role` to Read-only for a Member with `edit`, or a `grant` from `edit` or `manage` down to `view`; an Owner or Admin made a Member keeps only the rights of their grants, SHR-02.5, so where they lose reading SHR-04.1 applies instead) is signed only after the signer's Mac ran a sync of that vault that ended Synced (as SHR-04.2). Right after the entry is in, that Mac saves the vault again and uploads it (SHR-03.10), so the newest version is signed by a member who may still edit. Until then, a Mac that reads the older version refuses it at SHR-03.12 step 4, and its next run reads the new one. `remove` and `leave` need no extra upload: their new epoch brings one (SHR-04.4, SHR-04.11).

## Edge cases and errors

- Two invites claimed at once by two people for the 6th place: both compares may finish; the first `add` gets in, the second fails SHR-03.4 on R's check (step 2 of SHR-03.8) and both Macs show `MSG-GROUP-INVITE-FAILED` for it.
- The claimer is already in the group: 409 at claim; `MSG-GROUP-INVITE-USED`.
- An invite pasted 5 days and 1 second after it was made: 404; `MSG-GROUP-INVITE-USED`.
- The inviter is made a Member (family) after making the invite: R's check of SHR-03.8 step 2 fails; nothing signed.
- R's user picks Codes match before C's: R waits for C's consent until the request ends.
- An upload by a team Member whose right on that vault is `view`: 403 on the server; refused by every Mac at step 4.
- A version signed by an Organizer who left after uploading it: refused at step 4 by a Mac whose head holds the `leave`. The change survives only on Macs that merged it before they read the `leave`; the leaver's own file no longer opens (SHR-04.10), and `MSG-GROUP-LEAVE-CONFIRM` says so (SHR-04.11).
- The invite text with lower-case letters or without the spaces: accepted (base32 read case-blind, separators ignored, as SYN-06's kit).

## Security notes

- **Swapped keys at an invite (AT-L17, AT-L18).** The keys that go into the `add` entry and the wrap are the ones both people compared; a server that swaps the invitee's keys (LP07) or the inviter's (DL02) at any step makes the codes differ, and nothing is signed or wrapped (SYN-05.7; the ETH paper's public key authentication, sync-server.md section 6).
- **No forced enrolment (AT-L13).** BW01 needs a client that sends its own key, encrypted to a key the server chose, when it accepts an invite. Joining App sends only a commitment, public keys, a nonce and a consent signature (SHR-03.8 step 1); there is no recovery or enrolment key at all (SHR-04.13).
- **Consent closes injection (AT-L15).** An account is in a group only with its own consent signature (SHR-02.10), so a server cannot add it to a group of its own making, and a reused consent fails (`invite_id` once per list).
- **Two locks on writing (SV-06).** The server's 403 keeps the honest case clean; every Mac's check makes a hostile server's acceptance worthless. A read-only member can still copy what it can read: App says so (SHR-03.13; sync-server.md section 5: hidden levels "limit but don't prevent access").
- **Removed members cannot write (AT-L21).** Step 4 of SHR-03.12 refuses a removed member's version even when a hostile server serves it with an old head.

## Test cases

Organizer A, Members B and C of family group G1 with vault V; invitee D; an in-process server on 127.0.0.1:0; a test relay or test server where named.

| Case | Given | When | Then |
|---|---|---|---|
| T01 SHR-03.6 the invite (E18-S4) | A invites D | Read the invite text, the server's invite row and every request A sent | The text holds the origin, the fingerprint and 26 base32 characters, no key; the row holds the code's SHA-256, the role, the ids and the expiry, never the code; no request holds the code before D's claim (test proxy) |
| T02 SHR-03.6 used or expired (E18-S4) | An invite | Claim after 5 days and 1 s; claim twice; claim as B (a member) | 404; 201 then 409; 409; `MSG-GROUP-INVITE-USED` each time |
| T03 SHR-03.7, SHR-03.8 honest join (E18-S4) | A invites D | Run the compare; both pick Codes match | Same code on both; D's consent, then A's `add` entry with D's compared keys; D opens V with its wrap; D pins A's key; E17-S2's compare tests pass with the invite as the request |
| T04 SHR-03.7 swapped invitee key (LP07) | A test relay that replaces D's X25519 key in the reveal, keeping a valid commitment of its own | Run | The codes differ; with Codes differ chosen, no entry, wrap or pin |
| T05 SHR-03.7 swapped inviter key (DL02) | A test relay that replaces A's identity key in `POST …/keys` | Run | The codes differ; nothing signed, wrapped or pinned |
| T06 SHR-03.7 swapped context | A test server that tells D role Organizer while A's invite says Member, and one that names another group | Run each | The codes differ |
| T07 SHR-03.8 no consent | A test server that drops D's consent, and one that puts a consent from another invite | A's user picks Codes match | A signs no `add`; after 15 minutes `MSG-GROUP-INVITE-FAILED` on both; then A's local state holds no row of the invite and no name for D |
| T08 SHR-03.8 forced enrolment (BW01) | A test server that answers D's claim and every later GET with an extra field `"enrol_key"` holding its own X25519 key, and swaps A's key | D joins | Unknown fields ignored (SYN-01.8); the codes differ; a test proxy finds no request from D that holds a wrap, anything sealed, or a private key or secret of D's, wrapped or plain |
| T09 SHR-03.4 7th person (E18-S3) | G1 with 6 people | A invites a 7th | A's own check refuses before any request; a test server that takes the invite anyway gets an `add` that every Mac refuses (SHR-02.6 step 7) |
| T10 SHR-03.10, SHR-03.12 both edits survive (E18-S3) | B and C | Both edit V and save at once | One upload gets 412; its Mac updates list and keys and merges; both edits on A, B and C; each version's headers verify |
| T11 SHR-03.12 key not in the list (E18-S3) | A test server that accepts, and serves, a version signed by a key in no verified entry | A, B and C sync | Every Mac refuses it with `MSG-GROUP-BAD-VERSION`; nothing merged |
| T12 SHR-03.11 server 403 (E18-S3, E18-S6) | Team group T1 with a Read-only member R1 and a Member M1 with `view` on vault W | Each uploads W | 403 for both, nothing stored; a test server that stores them anyway: every Mac refuses both at step 4 |
| T13 SHR-03.11 stale head | B's head is seq 4; the server's is 5 | B uploads naming 4 | 412; B reads entry 5, signs again on head 5, and the next try is stored |
| T14 SHR-03.12 removed member (AT-L21) | C removed at seq 6; a test server stores and serves a version signed by C naming head 5 and epoch 1 | A and B sync | Refused at step 4 by both |
| T15 SHR-03.12 epoch goes down | B accepted a version of epoch 2; a version of epoch 1 with a higher version number, signed by A, names head 4 | B syncs | Refused at step 6 |
| T16 SHR-03.10 label | A personal-vault signature (`sync-upload-v1`) on a shared vault's PUT, and a shared one on a personal vault | Server and clients check | 403 on the server for both; refused by every client |
| T17 SHR-03.3 owners (E18-S6) | T1 with Owner O1 and Admin AD1 | AD1 signs `add X` as Owner; AD1 signs `role O1 admin`; O1 signs `role AD1 owner` | Refused; refused; accepted |
| T18 SHR-03.3 grant (E18-S6) | M1 with `manage` on W | M1 grants R1 `edit` on W; M1 grants R1 `view` on W; M1 grants M2 `edit` on vault W2 where M1 has `view` | Refused; accepted; refused |
| T19 SHR-03.5 no teams (E18-S6) | app-server built without `teams` | `POST /v1/groups` with a `create` of kind `team`; `cargo tree -p app-server` | 403 and no group row; App shows `MSG-GROUP-NO-TEAMS`; no app-server-teams in the tree |
| T20 SHR-03.9 invite pin | D has not pinned the server; the invite's fingerprint; a test server with another certificate at the same address | D pastes the invite | Pinned with no question when equal; with the other certificate `MSG-SYNC-CERT-CHANGED`, nothing added and no request sent |
| T21 SHR-03.13 read-only words (E18-S7) | R1 on W | Open W; read the members page | Editing is off; `MSG-GROUP-READ-ONLY` on the page and the badge |
| T22 SHR-03.14 names | A invites D as "Dana" | After the join, read V's custom data on B; search the server's rows and every request (test proxy) | `app.member-name.<D's id>` = "Dana" in V; "Dana" nowhere on the server or in any request in plain |
| T23 SHR-03.6 fuzz | The fuzz targets for every invite record, the claim and the three upload headers | 10 minutes each (gate G5) | No crash, no hang, no allocation over the limits |
| T24 SHR-03.4 vaults in a team | T1 with 100 vaults | O1 signs a `vault` entry for the 101st | Refused by the server (403) and every client |
| T25 SHR-03.1 family roles (E18-S3) | G1 with Organizer A and Members B, C | B edits and uploads V; B signs `add D`; B signs `rotate V`; A signs `rotate V` | B's version accepted everywhere; B's two entries refused by the server (403) and every Mac; A's `rotate` accepted |
| T26 SHR-03.2 team rights (E18-S6) | T1 with Owner O1, Admin AD1, Member M1 (W: edit, W2: none), Read-only R1 (W: view) | Each opens and uploads W and W2; M1 and R1 read their wraps | O1 and AD1 read and write both; M1 reads and writes W, holds no key of W2 (no wrap, 404 on W2); R1 reads W and every upload of R1 gets 403 and is refused by every Mac; nothing hides a password from R1 on screen |
| T27 SHR-03.15 edit right ends (E18-S6) | T1: M1 (W: edit) uploaded the newest version of W; a new Mac of AD1's account has not read W yet | AD1 grants M1 `view` on W; the new Mac then syncs W | AD1's Mac ran a sync before the entry and uploads W right after it; the new Mac accepts AD1's version; a test server that keeps serving M1's version gets it refused at step 4 |
| T28 SHR-03.12 step 6 head goes down | B accepted a version naming head 6 | A version with a higher version number, signed by A, names head 5 (same epoch) | Refused at step 6 |
| T29 SHR-03.14 two names at once | G1 also has A2 as a second Organizer; A invites D as "Dana" and A2 invites E as "Eli"; both write the name before either syncs | Both sync; read V's custom data and the members page on B; then A types the missing name with Name… | One name item is in V and the other member shows as "Member <first 8 lowercase hex digits>"; Name… shows on that row for A and A2 and for that member only; after A types it, both items are in V on every Mac |
| T30 SHR-03.3 no entry about oneself (E18-S6) | T1 with Owner O1, Admin AD1 (no grant), Member M1 with `manage` on W; G1 with Organizers A and A2 | AD1 signs `role AD1 member` naming every vault; M1 signs `grant M1 none` on W naming W; A signs `role A member` | Each gets 403 from the server and nothing is stored; every client refuses each through a test server that accepts it (SHR-02.6 step 6); then O1 signs `role AD1 member` and it is accepted |

## How this was learned

- Public sources only; the reference app has no server or sharing.
- spec/research/sync-server.md P9, P10, P11, P19 and sections 5 (invites that expire after five days; "Only a current owner can invite new owners"; collection levels View, Edit and Manage, and hidden levels that "limit but don't prevent access"; a server that rejects read-only uploads; families of 6), 6 (the ETH paper's BW01, LP07 and DL02 and the fixes of section 5.1) and 7 (ZRTP's one guess).
- Scarlata, Torrisi, Backendal, Paterson, USENIX Security 2026, section 5.1 (public key authentication; ciphertext authentication): <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>.
- RFC 6189 (ZRTP), section 4.4.1.1 (commit first; one guess): <https://www.rfc-editor.org/rfc/rfc6189.html>. RFC 4648 (base32): <https://www.rfc-editor.org/rfc/rfc4648.html>. RFC 9110 (If-Match, 412): <https://www.rfc-editor.org/rfc/rfc9110.html>.
- App's own cards: SYN-01, SYN-04.2, SYN-05, SYN-06, FMT-14, MOD-11.18, CRY-04.
- Written by E18-S1 (2026-11-01).
