# SHR-04 Removal, leaving and the list of passwords a removed member saw

Status: reviewed
Epics: E18-S5 (the remove entry, the new epoch, the server's clean-up, the list with its ticks, the deleted-for-good line, leaving, no reset and no escrow), E18-S7 (the removal list and its words), E18-S8 (the hostile-server run)
Parity rows: none in the reference app (it has no server or sharing). Larsal's own rows: SV-07 (plan/security.md); AT-L21 (plan/attacks-and-checks.md)

## What it does

An Organizer (in a team, an Owner or Admin) removes a member by signing a remove entry. The entry starts a new key epoch for every vault the person could read: the remover's Mac draws a new random key, re-keys the vault with it, wraps it to everybody who stays and uploads. The removed person gets no new key, so nothing saved after the removal opens for them, and the server stops serving them.

Larsal tells the truth: the removed person keeps every copy they already had, and only a new password at each website protects those accounts. So Larsal shows "Passwords <name> could see": every entry in the vault when they were removed, each with a tick the user sets once the password is changed. Entries deleted for good while the person was in the group cannot be named any more, so they show as one line with their count and dates.

A member can also leave. Nobody can reset another member's account, and no key is kept in escrow.

Other cards: SHR-01 owns keys, wraps and epochs; SHR-02 the member list; SHR-03 who may remove and every upload check; FMT-15 the deleted-objects list.

Design and sources: spec/research/sync-server.md P12, P13 and section 5 (decided: spec/decisions.md LD-263 (11), (12), LD-290 (5), (6)).

## Inputs and outputs

- In: the verified state (SHR-02.5); the affected vaults, open and synced; this Mac's account keys.
- Out: a `remove` (or `leave`, then `rotate`) entry; new keys and wraps; a re-keyed upload; the list of SHR-04.6 and its ticks in local state.

### Words

| ID | Words (Larsal's own) | Buttons |
|---|---|---|
| `MSG-GROUP-REMOVE-CONFIRM` | Remove <name> from "<group>"? <name> keeps every password they could see. Larsal makes a new key for the vault and lists those passwords, so you can change them. | Remove, Cancel (default) |
| `MSG-GROUP-REMOVE-WAIT` | Open and sync "<vault name>" first, with every change saved. Then remove <name>. | OK |
| `MSG-GROUP-REMOVED-LIST` | Passwords <name> could see. <name> keeps every copy they had. Only a new password at each website protects these accounts. Tick each one when you changed it. | Close list |
| `MSG-GROUP-DELETED-LINE` | <n> items deleted for good since <name> joined (<first date> to <last date>). Larsal can no longer name them. | none (a line of the list) |
| `MSG-GROUP-LEAVE-CONFIRM` | Leave "<group>"? Its vault will no longer open on this Mac. Your changes that the others' Macs have not synced yet are lost. Copy anything you want to keep into one of your own vaults first. | Leave, Cancel (default) |
| `MSG-GROUP-LEAVE-WAIT` | Open and sync "<vault name>" first, with every change saved. Then leave. | OK |
| `MSG-GROUP-LEAVE-LAST` | Make another member an Organizer first. Then you can leave. | OK |
| `MSG-GROUP-YOU-WERE-REMOVED` | You are no longer in "<group>". Larsal removed its keys from this Mac. | OK |
| `MSG-GROUP-VAULT-REMOVED` | You can no longer open "<vault name>". Larsal removed its key from this Mac. | OK |

In a team, `MSG-GROUP-LEAVE-LAST` says "an Owner", and `MSG-GROUP-LEAVE-CONFIRM` says "Its vaults will no longer open on this Mac." "<vault name>" and "<group>" are as SHR-01 and SHR-02 Words say, with their fallbacks "Vault <…>" and "Group <…>" on a Mac that has no name for them.

## Rules

SHR-04.1 **Who removes** (P12; SHR-03.3). Only a member who may sign a `remove` for that person (SHR-03.3) sees Remove. Larsal asks with `MSG-GROUP-REMOVE-CONFIRM`; Cancel is the default and does nothing. The same steps, SHR-04.2 to SHR-04.8, run for a team `role` or `grant` entry that takes away somebody's right to read a vault (SHR-02.6 step 8 makes it name that vault): for that vault, the person counts as removed.

SHR-04.2 **Before the entry.** The affected vaults are those the person may read in the state at this Mac's head. For each, Larsal needs it unlocked on this Mac, with no unsaved changes and no open editor, then runs a sync of it (SYN-03.5). When a vault is locked, has unsaved changes or its run does not end Synced, Larsal shows `MSG-GROUP-REMOVE-WAIT` and signs nothing. The list of SHR-04.6 starts from the vault as this run left it. In a group that SHR-02.11 blocks, the sync is left out and the last version this Mac accepted or uploaded stands for the version of this run (SHR-02.11 says which rules this touches).

SHR-04.3 **The remove entry** (P12: "An admin signs a remove entry, which starts a new key epoch"; RFC 9420 section 3.2). For each affected vault, Larsal draws a new key `F_{e+1}` (SHR-01.1) and keeps it in the device store (SHR-01.7) before it signs. It signs the `remove` entry with `keys` naming each affected vault and the key check of its new key (SHR-02.2, SHR-01.5), and sends it with `If-Match` on its head (SHR-02.7). On 412 it updates its list (SHR-02.9): when the person is already gone (another manager removed them), Larsal drops its new keys and goes on to SHR-04.6 with that entry, making no second epoch; otherwise it checks SHR-03.3 and SHR-03.4 again and tries again, at most 3 tries in all.

SHR-04.4 **The new epoch** (P12: "makes a new vault key, saves the shared vault with it through the existing credential change, wraps it to the remaining members and uploads with If-Match"). After the entry is in, for each affected vault:
1. Larsal wraps `F_{e+1}` to every member who may read the vault after the entry, its own account included (SHR-01.11);
2. it re-keys the open vault with `F_{e+1}` and saves it (SHR-01.14);
3. it uploads with `If-Match` on the version of SHR-04.2's run, `Upload-Epoch` e+1 and the remove entry as its head (SHR-03.10).
On 412 it downloads the newer version, checks it (SHR-03.12: a version a remaining member made before the remove entry passes; one the removed person signed fails at step 4), opens it with the key of its epoch, adds its entries to the list (SHR-04.6), merges, re-keys, saves and tries again (SYN-03.6). A version that fails SHR-03.12 is not merged: Larsal uploads with `If-Match` on it, so the server copy moves on without it. A crash at any point leaves `F_{e+1}` in the device store; the next run goes on from the first step not done, and the wraps of a lost Mac are made by the next run of a manager who holds `F_{e+1}` (SHR-01.11); when no other Mac holds it, nothing heals (the lost-Mac edge case below).

SHR-04.5 **The server's clean-up** (P12: "as a second line only"). In the transaction that appends a `remove` or `leave` entry, the server deletes the person's wraps for the group's vaults and every open invite and compare of the group that the person made or claimed. While the state at its head does not list that account (a former member, SHR-02.15), it answers that account 403 on every route of the group and of its vaults (the one exception is SHR-02.15's entries; the invite routes of SHR-03.6 still serve it, so it can be invited again), and `GET /v1/vaults` and `GET /v1/groups` no longer list them. A never-member still gets SYN-01.6's 404 (or 412 for a PUT): only a former member, who knows the group exists, gets 403. This line only stops service; the protection is the new key (SHR-04.4).

SHR-04.6 **"Passwords <name> could see"** (P12: "every entry in the vault at removal (with history, attachments and the recycle bin)"). On the Mac that signed the entry, the list holds, for each affected vault, every entry in each version of the old epoch that Larsal read during the removal (SHR-04.2's run and each try of SHR-04.4): the entries in the vault's groups and those in the recycle bin. Each row shows the entry's title, user name and URL as the vault holds them now, and says how many history items and attachments it had at removal, because the person could see those too. An entry deleted since shows as "Deleted since the removal", with its tick. Nothing else is in the list: no entry made after the removal and no entry of a vault the person could not read. Larsal shows it under `MSG-GROUP-REMOVED-LIST` as soon as the entry is in.

SHR-04.7 **Entries deleted for good** (FMT-15.1: the deleted-objects list keeps only an id and a deletion time; D-SHR04-1 (a), decided: spec/decisions.md LD-290 (5)). For each affected vault, Larsal counts the items of its deleted-objects list, in the version of SHR-04.2's run, whose deletion time is from the person's join time (the `time` of the latest `create` or `add` entry naming them, SHR-02.5) to the remove entry's `time`. When the count `n` is above 0, the list ends with one line, `MSG-GROUP-DELETED-LINE`, with `n` and the first and last of those deletion times as dates. The words say "items", because FMT-15.7 adds an item for each entry, group and custom icon deleted for good, and the list does not say which kind an item was.

SHR-04.8 **Ticks** (E18-S5: ticks survive a restart). Each row has a tick the user sets once the password is changed. Larsal keeps the list in local state never synced, written atomically with mode 0600: the remove entry's hash, the group and vault ids, each row's entry id, its two counts and its tick, and the line's count and dates. No title, user name, URL or password is written there; Larsal reads them from the vault when it shows the list. The list stays on the group's page until the user picks Close list.

SHR-04.9 **The truth in words** (P12: "the removed person keeps every copy they had, and only a new password at the website protects"; sync-server.md section 5: each hosted product studied says the same). `MSG-GROUP-REMOVE-CONFIRM` and `MSG-GROUP-REMOVED-LIST` say it before and after; Larsal never says or suggests that removal takes anything back.

SHR-04.10 **On the removed person's Macs** (sync-server.md section 5: a "well behaved client" is told to forget keys and data). Larsal acts on the state at the Mac's head after SHR-02.9 has read up to the reply's head, never on one entry of the history. When a verified entry takes this Mac's own account out of the state at its head (a `remove` naming it, SHR-02.15, or on the account's other Macs its own `leave`, SHR-04.11), Larsal wipes every key of that group from the device store (SHR-01.7), drops the group's state, its links and the pins only that group used, and shows `MSG-GROUP-YOU-WERE-REMOVED`. An older `remove` or `leave` that a later `add` of the account follows (a new invite) does not count, because the state at the head lists the account. When, in the state at its new head, its own account may no longer read a vault it could read at its old head (a verified `role` or `grant`, SHR-04.1), Larsal wipes the keys of that vault from the device store, drops its link and shows `MSG-GROUP-VAULT-REMOVED`; the group and its other vaults stay. It leaves the local vault files as they are; they no longer open, because their only key part is gone. A 403 from the server with no verified `remove` changes only the status line: the server's word is not proof.

SHR-04.11 **Leaving** (P11, P12). The user picks Leave; Larsal asks with `MSG-GROUP-LEAVE-CONFIRM` (Cancel is the default). When the user is the last Organizer (team: Owner) and others stay, Larsal shows `MSG-GROUP-LEAVE-LAST` instead and signs nothing (SHR-03.4). Otherwise, before it signs, Larsal runs SHR-04.2's checks for every vault the user may read in the group: each is unlocked, with no unsaved changes and no open editor, and a sync of it ends Synced; when one does not, Larsal shows `MSG-GROUP-LEAVE-WAIT` and signs nothing. So the leaver's last version is on the server before the `leave`; it still survives only on Macs that merged it before they read the `leave` (SHR-03.12 step 4), as `MSG-GROUP-LEAVE-CONFIRM` says. Then Larsal signs a `leave` entry with an empty `keys` (the person leaving must not know the next key, SHR-01.6), sends it, and then runs SHR-04.10's clean-up on this Mac; the account's other Macs run it at their next sync, when the `leave` takes the account out of the state at their head (SHR-04.10). After `MSG-GROUP-FORK` (SHR-02.9), or while the group is blocked (SHR-02.11), the group no longer syncs on this Mac, so Larsal leaves out SHR-04.2's checks and the last-Organizer words: it tries once to send the `leave` and runs SHR-04.10's clean-up on this Mac whether or not the server takes it. The server cleans up as SHR-04.5 says. Each vault the leaver could read is then rotation due (SHR-02.5). A rotation that is due runs for a vault only in that vault's own run, while it is unlocked on a Mac whose account may manage it (SHR-01.11): that run signs a `rotate` entry with a new key and its check, and runs SHR-04.4 for it; that Mac also shows the list of SHR-04.6 and SHR-04.7 for the leaver, with "<name> left" in place of the remove words. Until that `rotate`, uploads go on under the old key, which only an honest leaver's Mac has wiped (a known limit, named in the security notes).

SHR-04.12 **The group ends.** When the last person leaves, the server deletes the group's entries, invites, wraps and vault rows in one transaction, then their files (SYN-02.4 step 5). The leaver's Macs drop it as SHR-04.10 says.

SHR-04.13 **No admin reset and no key escrow** (P13: "BW01, BW02, BW03 and LP01 all come from escrow plus unchecked keys"). No route, entry or wrap gives any member, Organizer, Owner, Admin or the server a key of another account (its account secret, its identity or X25519 private key, a device key) or a way to set another account's password; Larsal never wraps an account's own keys to anybody. Joining a group enrols nothing (SHR-03.8). A person who lost their account (no Recovery Kit and no Mac, SYN-06.13) loses only that account: the others still hold the vault key, and an Organizer removes the old account and invites the new one (SHR-03.6). Local vaults still open with their master password.

## Edge cases and errors

- Two Organizers remove the same person at once: one entry gets in; the other Mac finds the person gone after its 412, drops its new keys and shows the list from that entry (SHR-04.3).
- The person is removed while their own Mac is offline: at its next run it reads the entries up to its removal (SHR-02.15), cleans up (SHR-04.10) and uploads nothing; its unsynced edits stay in its local file, which no longer opens.
- B uploads an edit after the remover's sync run and before the remove entry: the remover's PUT gets 412, merges B's version and adds any new entry of it to the list (SHR-04.4).
- The removed person's Mac uploads with an old head through a test server that takes it: every other Mac refuses that version (SHR-03.12 step 4).
- A vault with no item deleted for good since the person joined: no line.
- The person was removed once before and invited again: the window of SHR-04.7 starts at the latest `add`, and their Macs keep the keys of the new wraps, because the state at the head lists them (SHR-04.10, T21). The group's creator, who has no `add`, is counted from the `create`.
- A person removed from a team who could read 2 of 5 vaults: 2 new epochs, 2 lists; the other 3 keep their keys.
- The signer's Mac is lost after its entry is in and before it wrapped the new key (SHR-04.4 step 1): no other Mac holds `F_{e+1}`, so every reader of that vault stays at `MSG-GROUP-WAITING-KEY` and nothing is uploaded to it. A known limit of this build: each member's local copy still opens under `F_e`, so they can copy its items into another vault.

## Lead decisions

D-SHR04-1 **"Entries" or "items" in the deleted-for-good line.** E18-S1 and E18-S5 word it "3 entries deleted since <name> joined". The deleted-objects list holds an item for each entry, group and custom icon deleted for good (FMT-15.7) and keeps only an id and a time (FMT-15.1), so Larsal cannot count entries alone. (a) Count every item in the window and say "items" (SHR-04.7). (b) Say "entries" and count every item. Recommended: (a). Why: (b) gives a wrong word whenever a group or icon was deleted; (a) never counts too few, which is the safe side for a list of things to change. With (a), E18-S5's check reads "one line whose count and dates match the items deleted for good after the person joined". Taken: (a); decided: spec/decisions.md LD-290 (5).

## Security notes

- **New key, no wrap, no service (SV-07, AT-L21).** A removed person has no key of the new epoch (SHR-04.4), every Mac refuses their later uploads (SHR-03.12 step 4), and the server stops serving them (SHR-04.5). A hostile server can still give them the files it holds, but those files are under a key they do not have (RFC 9420 section 3.2: new entropy for all members "except the removed member").
- **What cannot be taken back.** Everything the person saw while a member stays with them; the list makes the fix (new passwords at each website) concrete (P12; sync-server.md section 5).
- **Leaving.** Between a `leave` and its `rotate`, versions stay under a key the leaver had. An honest leaver's Mac wipes it at once; a dishonest leaver who copied the key and also has a hostile server's help could read those versions until a manager rotates the key. The rotation happens in that vault's first run after a manager unlocks that vault on their Mac (SYN-03.4, SHR-01.11), not before.
- **A forked member.** A server that hides the remove entry from a member B and keeps B's uploads away from the others leaves B saving under the old key. B's Mac refuses each upload it reads from the others, which names a head it cannot reach, with `MSG-GROUP-BAD-VERSION` (SHR-02.12). When the server also keeps the vault apart, only a list-code compare finds it: after both members pick Sync now, B's Mac shows a lower entry number than the remover's (SHR-02.13).
- **No escrow (P13).** No key path exists that a hostile server or a member could turn into BW01, BW02, BW03 or LP01 (sync-server.md section 6).

## Test cases

Organizers A and A2, Members B and C of family group G1 with vault V; an in-process server on 127.0.0.1:0; demo vault content known; test clock.

| Case | Given | When | Then |
|---|---|---|---|
| T01 SHR-04.4, SHR-04.5 removed cannot open (E18-S5) | C joined; a copy of C's device store and state taken just before its removal (test only) | A removes C; A and B upload 3 versions after it | With the copy, C's client opens none of the 3 versions (`WrongKey` for each, no key of epoch 2 in it); C's real session gets 403 on GET V, on its wraps and on `entries/7` |
| T02 SHR-04.6 list (E18-S5) | V holds 5 entries (E1 with 3 history items, E2 with one attachment) and 2 in the recycle bin; C joined before all of them | A removes C; then A adds E8 | The list holds exactly the 7 entries; E1 says 3 history items, E2 one attachment; E8 is not in it |
| T03 SHR-04.7 entries deleted for good (E18-S5) | C joined on 2026-10-10. Before that, E9 was deleted for good. After it: E10 on 2026-10-12, E11 on 2026-10-15, E12 on 2026-10-20, all deleted for good | A removes C on 2026-10-30 | One line `MSG-GROUP-DELETED-LINE` with n = 3 and the dates 2026-10-12 and 2026-10-20 (in Larsal's date format) |
| T04 SHR-04.7 a group | As T03, plus group G7 holding entry E13, deleted for good on 2026-10-22 (FMT-15.7 adds E13 and G7) | A removes C | The line has n = 5 and the dates 2026-10-12 and 2026-10-22 |
| T05 SHR-04.8 ticks (E18-S5) | The list of T02 | Tick E1 and E2; quit and start Larsal; read the state file | E1 and E2 ticked, the rest not; the file holds ids, counts and ticks, and no title, user name, URL or password |
| T06 SHR-04.9 words (E18-S5) | Removal of C | Read the confirm and the list header | Both say that C keeps every copy and that only a new password at each website protects |
| T07 SHR-04.1 non-admin (E18-S5) | B (a Member) | B's Mac shows no Remove; a test client signs `remove C` as B | Server 403, nothing stored; every Mac refuses it through a test server that accepts it |
| T08 SHR-04.4 race | A's run of SHR-04.2 ends at version 9; B uploads version 10 with new entry E14 before A's remove entry | A removes C | A's PUT gets 412; A merges version 10; E14 is in V and in the list; V ends at epoch 2 with both changes |
| T09 SHR-04.3 two removers | A and A2 remove C at once | — | One `remove` entry; one new epoch; A2's new keys are wiped from its device store; both Macs show the list |
| T10 SHR-04.4 crash | A test hook stops A after the entry is in and before the wraps | Start A again; sync | A finishes the wraps, the re-key and the upload with the key it kept; B opens epoch 2 |
| T11 SHR-04.2 unsaved changes | V has an unsaved edit on A; separately, V is locked on A | Remove C | `MSG-GROUP-REMOVE-WAIT` both times; no entry signed |
| T12 SHR-04.10 the removed Mac | C removed | C's Mac syncs | Its device store holds no key of G1; G1 is gone from its screens with `MSG-GROUP-YOU-WERE-REMOVED`; its local V file is unchanged on disk and does not open. Separately, a test server that answers C 403 with no `remove` entry: C keeps its keys; only the status line changes. Separately, in team T1 Owner O1 grants Member M1 `none` on W (M1 also reads W2): M1's Mac wipes W's keys, drops W's link and shows `MSG-GROUP-VAULT-REMOVED`; it keeps W2's keys and still opens W2 |
| T13 SHR-04.11 leaving | B leaves; V is locked on A and A2 | B's Mac; then A's other vaults sync; then A unlocks V | B's entry has empty `keys`; B's keys are wiped; the server answers B 403; no `rotate` while V is locked on A; in V's first run after the unlock A signs `rotate V`, V moves to epoch 2, and A's Mac shows the list for B; C opens epoch 2 |
| T14 SHR-04.11 last Organizer | A2 gone; A is the only Organizer with B and C in G1 | A picks Leave | `MSG-GROUP-LEAVE-LAST`; no entry |
| T15 SHR-04.12 the end | Only A is left | A leaves | The server holds no row of G1 and no file only G1 named; A's Mac drops G1 |
| T16 SHR-04.5 clean-up | C has an open invite it made as Organizer (C made Organizer for this case) and wraps for V | A removes C | C's wraps and C's invite are gone in the same transaction; `GET /v1/vaults` for C does not list V |
| T17 SHR-04.13 no reset, no escrow | The routes of SYN-01 and SHR-01 to SHR-04; every server row after T01 to T16 | Search for any route or field that takes or holds another account's secret, private key or password, or a wrap to anybody of an account's own keys; look for a reset on the Organizer's screens | None |
| T18 SHR-04.7 the creator removed | A made G1 on 2026-10-01 (its `create`); E15 was deleted for good on 2026-09-20 and E16 on 2026-10-05 | A2 removes A | One line with n = 1 and the date 2026-10-05 |
| T19 SHR-04.11 before the leave | B has an unsaved edit in V; then B saves; C syncs every 60 s, A's V is locked | B picks Leave; then again after the save, and C syncs once before the `leave` is in (test hook); then A unlocks V | First `MSG-GROUP-LEAVE-WAIT` and no entry; then B's sync ends Synced and B's version is stored before the `leave` (server order); C merged it and keeps it; A's first run after the unlock refuses B's version at SHR-03.12 step 4 and gets B's change only through C's next upload |
| T20 SHR-04.11 leaving a forked group | B's Mac stopped using G1 after `MSG-GROUP-FORK`; B is G1's only Organizer on its branch | B picks Leave | No `MSG-GROUP-LEAVE-WAIT` and no `MSG-GROUP-LEAVE-LAST`; one `leave` POST tried (test proxy); B's keys of G1 are wiped and G1 is gone from B's screens |
| T21 SHR-04.10, SHR-04.11, SHR-04.5 invited again | C, with a second Mac C2, is removed at seq 6, then invited again with an `add` at seq 9; C2 is offline from seq 5 to seq 9. Separately, the same with C leaving at seq 6. Separately, in team T1, Owner O1 grants Member M1 `none` on W, then `edit` on W, while M1's Mac is offline | C's Mac checks the list from seq 1 (SHR-03.8 step 4); C2 syncs once; M1's Mac syncs once | C's Mac keeps the keys of its new wraps, opens V and shows no `MSG-GROUP-YOU-WERE-REMOVED`; C2 reads entries 6 to 9 in that sync, keeps its keys, opens its new wrap and opens V; the server answers C 200 on G1's routes and serves entries 1 to 9; the same holds after the leave; M1's Mac keeps W's keys, shows no `MSG-GROUP-VAULT-REMOVED` and opens W |

## How this was learned

- Public sources only; the reference app has no server or sharing.
- spec/research/sync-server.md P11, P12, P13 and sections 5 (a removed person keeps what they saw, in every hosted product studied; a well-behaved client forgets keys; offline devices keep a cached copy; the advice to change the credentials the member could see), 6 (BW01, BW02, BW03 and LP01 come from escrow plus unchecked keys) and 7 (MLS removal).
- RFC 9420 (MLS), read 2026-11-01: section 3.2 (the Commit "provides new entropy to all members of the group except the removed member"): <https://www.rfc-editor.org/rfc/rfc9420.html>.
- Scarlata, Torrisi, Backendal, Paterson, USENIX Security 2026, sections 5.1 and 6: <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>.
- Larsal's own cards: FMT-15.1, FMT-15.7 (which deletions add items), MOD-04 (the recycle bin), SYN-01.6, SYN-02.4, SYN-03, SYN-06.13.
- Written by E18-S1 (2026-11-01).
