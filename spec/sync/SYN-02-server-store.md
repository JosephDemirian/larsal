# SYN-02 Server store

Status: reviewed
Epics: E16-S3 (data folder, certificate files), E16-S4 (store, vault files, compare-and-swap, old versions, sweep), E16-S5 (account, device, challenge and session rows); E17 and E18 add rows
Parity rows: none in the reference app (it has no server). Larsal's own rows: SV-01 and SV-03 (plan/security.md); AT-L02 and AT-L09 (plan/attacks-and-checks.md)

## What it does

The server keeps its state in one data folder: an SQLite database for accounts, devices, challenges, sessions and vault rows, and the vault bytes as files named by their SHA-256. A new vault version is written to a file and made durable first; then one database transaction moves the vault row from the old version to the new one only if no other upload got there first. A crash at any point leaves the old version or the new one, never a mix. The server keeps the current version plus 5 old ones, for restore only.

The store never opens a vault: it holds bytes, lengths and hashes (P16). SYN-01 owns the routes that read and write the store.

Design and sources: spec/research/sync-server.md P14, P15, P16, P22 (decided: spec/decisions.md LD-263 (13), (14), LD-267 (7), LD-273 (1)).

## Inputs and outputs

- In: the routes of SYN-01; the server's start flag for the data folder.
- Out: the data folder below; replies of SYN-01.
- Limits: a vault file is at most FMT-01.31's 1,140,850,688 bytes (SYN-01.10); per-account quotas are open (spec/research/sync-server.md section 12) and not in this build.

## Rules

SYN-02.1 **Data folder.** One folder, given at start (a test uses a temp folder, P25):
- `store.sqlite` (with SQLite's `-wal` and `-shm` files);
- `blobs/<the first 2 hex digits>/<64 lowercase hex digits>`: vault files, named by the SHA-256 of their bytes;
- `tmp/`: files being written;
- `tls/cert.der` and `tls/key.der`: the demo certificate and its key (SYN-01.2).
The folder and its subfolders have mode 0700, every file 0600. The server refuses to start, with a plain error, when the folder or a file in it can be written by the group or others, or belongs to another user, or when `tls/key.der` can be read by the group or others (as SSH servers refuse a private host key that others can read; LD-309). Known limit: the check reads the mode bits and the owner, as SSH servers do for their keys; it does not read access control lists, so an inherited ACL that lets others read is not seen (LD-314).

SYN-02.2 **SQLite settings** (P15; sqlite.org "Write-Ahead Logging"). At open: `journal_mode=WAL`, `synchronous=FULL` (each commit syncs the log, so a power cut never rolls back a commit the server answered), `fullfsync=ON` (on macOS, commits and checkpoints sync with `F_FULLFSYNC`, which SQLite does only when this is on; sqlite.org "Pragma statements", F-222), `foreign_keys=ON`, `busy_timeout=5000` (5 s, the value Litestream's tips advise). `user_version` holds the schema version, 1 in this build. A store with a higher `user_version` than the server knows is refused at start; a store with none gets the schema of SYN-02.3. SQLite is built from its bundled source (`libsqlite3-sys` `bundled`, P22).

SYN-02.3 **Rows.** Ids are 16-byte blobs drawn from larsal-crypto's random source (P20); times are whole seconds UTC.
- `accounts`: id; created; from E17-S1 the identity public key, the X25519 public key and its signature, the recovery public key and the account blob (SYN-06.6), empty before.
- `devices`: id; account id; P-256 public key (65 bytes, unique over the store); name (1 to 64 Unicode scalar values, none in the Unicode category Cc, SYN-04.2); added; last seen.
- `challenges`: nonce (32 bytes); device id, or the account id for a recovery challenge (SYN-06.12); expires. Deleted when used or expired.
- `sessions`: SHA-256 of the token (the key); device id; created; last used. Never the token itself (OWASP Session Management).
- `vaults`: id; account id; version; size; SHA-256 of the bytes; uploader id and signature (from E17-S1, SYN-01.7); updated.
- `vault_versions`: the same fields for each old version kept (SYN-02.5).
- `keyparts`: vault id; the wrap record of SYN-06.9 (from E17-S1).
- `approvals`: the state of SYN-06.11 (from E17-S2), with the SHA-256 of the approval code, never the code.
E18 adds (SHR-01 to SHR-04): `groups` (id; kind; head seq and hash; created); `member_entries` (group id; seq; the record; hash); `wraps` (group id; vault id; epoch; member id; the wrap record; the current and previous epoch only, SHR-01.12); `invites` (id; group id; the SHA-256 of the code, never the code; role; inviter; invitee; expiry; the compare's messages, SHR-03.6). For a shared vault, `vaults` and `vault_versions` also hold the group id, the epoch and the uploader's list head (SHR-03.10).

SYN-02.4 **Writing a new version** (P15). In this order:
1. Stream the body into a new file in `tmp/` (its name holds 16 random bytes in hex), counting bytes and computing the SHA-256 as the bytes arrive. Over the limit, a timeout or a closed connection: delete the file, store nothing.
2. Flush it with `F_FULLFSYNC` (`fcntl`), as Larsal's safe save does (APP-05.11).
3. Rename it to `blobs/<h[0..2]>/<h>`; when that name already exists (the same bytes), delete the temp file instead. Sync the folder.
4. One transaction: for an update, first copy the current row into `vault_versions` (`INSERT INTO vault_versions SELECT … FROM vaults WHERE id = ? AND version = ?`, with the `If-Match` version), then `UPDATE vaults SET version = version + 1, size, hash, uploader, signature, updated WHERE id = ? AND version = ?`; for a new vault, `INSERT` (an existing id is a conflict). No row copied or changed, or a conflict: roll back and answer 412. Otherwise prune `vault_versions` to SYN-02.5's count, and commit.
5. After the commit, delete each blob file that no `vaults` or `vault_versions` row names any more.
A crash before step 4's commit leaves the old version served and at most one orphan file; a crash after it leaves the new version served.

SYN-02.5 **Old versions.** The store keeps the current version and the 5 versions before it (LD-263 (13), LD-267 (7)), for restore only: the merge needs no base (P15), and no route reads them in this build (restore comes with E19-S2). After the 7th upload of one vault: version 7 is current, versions 2 to 6 are kept, version 1's row and file are gone (unless another row names the same file).

SYN-02.6 **Sweep at start.** Before the listener opens: delete every file in `tmp/`, and every file in `blobs/` whose name is a well-formed hash that no row names. A file in `blobs/` with any other name is left alone and logged by its count only.

SYN-02.7 **Reads.** A GET reads the current row in a read transaction and opens the file it names before the transaction ends, then streams it. A file deleted by a later commit while it is streamed stays readable through the open handle (POSIX `unlink`), so a reader never gets half a version.

SYN-02.8 **One writer** (P14; sqlite.org "Appropriate Uses"). Every write runs on one blocking task with one database connection (tokio `spawn_blocking`); reads may use their own connections. SQLite has one writer at a time anyway.

SYN-02.9 **The store is blind** (P16). The server never parses vault bytes: the only checks are the length and the hash. `cargo tree -p larsal-server` holds none of `larsal-format`, `larsal-core`, `larsal-platform`, `larsal-ffi`, `larsal-sync` (the "server blind" line in `scripts/check.sh`); `larsal-model` `json.rs` and `larsal-crypto` are allowed (LD-263 (14)).

SYN-02.10 **What the store never holds.** No password and no value made from one, except the account blob of SYN-06.4, which also needs the 256-bit account secret (P6); no session token, only its SHA-256; no private key, key-file part or vault key, except inside a wrap record or the account blob.

## Edge cases and errors

- Two uploads of the same version at once: both write their files; one commit wins, the other rolls back with 412 and its file is deleted after (step 5), unless both bodies were equal.
- Two vaults with byte-equal files share one blob file; deleting one row's last reference keeps the file while the other row names it.
- The disk fills during step 1: the temp file is deleted, 500 `server_error`, the old version stays.
- Another server uses the data folder: the server refuses to start, before its sweep, with a plain error (an exclusive lock on the folder, held while the store is open; F-223).
- A blob file named by a row is missing (outside damage): GET answers 500 and logs the vault id; the row is not changed.
- A store from a newer server (`user_version` 2): refused at start; the folder is not changed.

## Security notes

- **Durable before visible.** The row moves only after the file is flushed with `F_FULLFSYNC` and renamed, and the commit syncs the log (`synchronous=FULL`), so a version the server answered 200 for survives a power cut (sqlite.org WAL page; P15).
- **Compare-and-swap.** The `WHERE version = ?` update is the server half of `If-Match`: two Macs cannot both replace one version (AT-L02).
- **A copy of the folder is not enough.** Whoever copies the whole data folder gets vault files that need the master password plus the key-file part (P7, SYN-03.1), token hashes that cannot sign in (SYN-04.5) and an account blob that needs the account secret (SYN-06.4) (SV-03).
- **Hostile names.** Files are named only by hashes the server computed; no client-given name reaches the file system.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 SYN-02.1 folder modes | Fresh data folder | Start the server; list the folder | Folders 0700, files 0600; `tls/cert.der`, `tls/key.der`, `store.sqlite` exist |
| T02 SYN-02.1 unsafe folder | Data folder with mode 0770 | Start | Refused with a plain error; nothing written |
| T03 SYN-02.2 pragmas | Running server | Read `PRAGMA journal_mode`, `synchronous`, `fullfsync`, `foreign_keys`, `user_version` | `wal`, 2 (FULL), 1, 1, 1 |
| T04 SYN-02.2 newer schema | A store with `user_version` 2 | Start | Refused; the store's bytes unchanged |
| T05 SYN-02.3 no plain tokens | A session made by sign-in | Read every column of `sessions` | Only the SHA-256 of the token; no column equals the token |
| T06 SYN-02.4 round trip | A demo vault file | PUT, then GET | Bytes equal (`cmp`); the file under `blobs/` is named by their SHA-256 |
| T07 SYN-02.4 crash before commit | Vault X at version 1; a test hook stops the server after step 3 | PUT, then restart | GET X gives version 1's bytes; the new file was swept at start (SYN-02.6) |
| T08 SYN-02.4 crash after commit | As T07, the hook after step 4 | PUT, then restart | GET X gives version 2's bytes; version 1 kept in `vault_versions` |
| T09 SYN-02.4 race | Vault X at version 1 | Two PUTs with `If-Match: "1"` at once | One 200, one 412; one new file kept, no orphan after step 5 |
| T10 SYN-02.5 old versions | Vault X | 7 uploads with different bytes | Row version 7; `vault_versions` holds 2 to 6; version 1's file is gone |
| T11 SYN-02.6 sweep | Data folder with a file in `tmp/`, an unnamed blob file and a file `blobs/zz/notahash` | Start | The first two are deleted; the third stays; the log names one unknown file by count |
| T12 SYN-02.7 read during a commit | A GET of version 6 streaming slowly; a PUT makes version 7 and prunes | Finish the GET | The GET gives version 6's bytes complete |
| T13 SYN-02.9 server blind | The tree; a scratch copy where larsal-server names larsal-format | Run the "server blind" line | Passes on the tree; fails on the copy |
| T14 SYN-02.10 no secrets | A full demo run: sign-up (E17-S1), sync, a key-file part wrap | Search every row and file for the demo master password, the account password, the key-file part and the account secret (and their SHA-256) | None found |
| T15 SYN-02.8 one writer | Server with 50 vaults; test rate limit raised to 200 POST, PUT and DELETE requests a minute (SYN-01.12) | 50 PUTs to different vaults at once | All succeed with no busy error; a test counter shows every write ran on the one writer connection |
| T16 SYN-02.1 key others can read | Data folder whose `tls/key.der` has mode 0644 | Start | Refused with a plain error that names the file; nothing written |

## How this was learned

- Public sources only; the reference app has no server.
- spec/research/sync-server.md P14, P15, P16, P22 and section 9 (Storage).
- SQLite: <https://www.sqlite.org/wal.html> (WAL, `synchronous=FULL`), <https://www.sqlite.org/pragma.html#pragma_fullfsync> (`fullfsync`, off by default; only macOS has `F_FULLFSYNC`), <https://www.sqlite.org/whentouse.html> (one writer), <https://www.sqlite.org/limits.html>, <https://www.sqlite.org/fasterthanfs.html> (files for large data).
- OWASP Session Management Cheat Sheet (store a hash of the token): <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>.
- A proven open source server's backup practice (SQLite online backup plus the files folder), via sync-server.md section 1.
- Larsal's own safe save: spec/app/APP-05-saving.md, APP-05.11.
- Litestream's tips (`PRAGMA busy_timeout = 5000`, "It is recommended to set this to 5 seconds"), read 2026-10-31: <https://litestream.io/tips/>.
- Larsal's own value, decided: spec/decisions.md LD-273 (1) (no proven server's default found): a device name of 1 to 64 Unicode scalar values, none in the category Cc (SYN-02.3, SYN-04.2, pinned by SYN-04 T02).
- Written by E16-S1 (2026-10-31).
