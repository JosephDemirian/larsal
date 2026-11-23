//! The SQLite store (SYN-02.2, SYN-02.3): `store.sqlite` in the data
//! folder, in WAL mode with `synchronous=FULL`. E16-S4 has the `vaults` and
//! `vault_versions` tables; E16-S5 the `accounts`, `devices`, `challenges`
//! and `sessions` tables and the vault's account (SYN-04); E17-S1 (schema 2)
//! adds the account keys (SYN-06.6), a challenge's kind (LD-327 (7)), the
//! uploader and signature of each version (SYN-01.7) and the `keyparts`
//! table (SYN-06.9). E17-S2 (schema 3) adds the `approvals` table
//! (SYN-06.11, SYN-05). As LD-327 (5) and E17-S2's ruling (8) say, a schema
//! changes in place and has no migration code: no store exists outside
//! test folders, so a store of an older schema is refused at open, before
//! anything in the folder changes.
//!
//! Guarantees: the file is made with mode 0600 (SQLite gives its `-wal` and
//! `-shm` files the mode of the database); a store whose `user_version` is
//! newer than [`SCHEMA`] is refused before anything in the folder changes;
//! the store holds lengths and hashes, never vault bytes (P16); it holds
//! the SHA-256 of each session token, never a token (SYN-02.3, SYN-04.5).
//! Revoking a device deletes its sessions (`ON DELETE CASCADE`) and its
//! open challenges with it (SYN-04.8). A challenge row's device has no
//! foreign key: SYN-04.3 stores a challenge for any device id, and
//! SYN-02.3 puts an account id there for a recovery challenge.

use crate::Error;
use larsal_proto::account::AccountKeys;
use larsal_proto::approval::{ApprovalState, DEVICE_KEY};
use larsal_proto::limits::{SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS};
use larsal_proto::messages::{AccountId, DeviceId, Id, VaultId, VaultVersion};
use larsal_proto::routes::Precondition;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The schema version this server writes and reads (SYN-02.2).
pub(crate) const SCHEMA: i64 = 3;

/// Old versions kept beside the current one, for restore only (SYN-02.5).
pub(crate) const OLD_VERSIONS: u64 = 5;

/// SYN-02.3's rows of E16-S4, E16-S5 and E17-S1. Ids are 16 bytes, hashes
/// 32, times whole seconds UTC. A device's public key is unique over the
/// store. An account's keys are empty until `PUT /v1/account/keys`; a
/// version uploaded without a signature (an account of E16, tests only:
/// `TestSeams::allow_unsigned`) has neither uploader nor signature.
const TABLES: &str = "
CREATE TABLE accounts (
    id BLOB PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL,
    identity_public_key BLOB,
    kem_public_key BLOB,
    kem_signature BLOB,
    recovery_public_key BLOB,
    blob BLOB
) STRICT;
CREATE TABLE devices (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    public_key BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    added INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
) STRICT;
CREATE INDEX devices_by_account ON devices (account);
CREATE TABLE challenges (
    nonce BLOB PRIMARY KEY NOT NULL,
    device BLOB NOT NULL,
    expires INTEGER NOT NULL,
    kind INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX challenges_by_device ON challenges (device);
CREATE INDEX challenges_by_expiry ON challenges (expires);
CREATE TABLE sessions (
    hash BLOB PRIMARY KEY NOT NULL,
    device BLOB NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_by_device ON sessions (device);
CREATE TABLE vaults (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    version INTEGER NOT NULL,
    size INTEGER NOT NULL,
    hash BLOB NOT NULL,
    updated INTEGER NOT NULL,
    uploader BLOB,
    signature BLOB
) STRICT;
CREATE INDEX vaults_by_hash ON vaults (hash);
CREATE INDEX vaults_by_account ON vaults (account, id);
CREATE TABLE vault_versions (
    id BLOB NOT NULL REFERENCES vaults (id),
    version INTEGER NOT NULL,
    size INTEGER NOT NULL,
    hash BLOB NOT NULL,
    updated INTEGER NOT NULL,
    uploader BLOB,
    signature BLOB,
    PRIMARY KEY (id, version)
) STRICT;
CREATE INDEX vault_versions_by_hash ON vault_versions (hash);
CREATE TABLE keyparts (
    vault BLOB PRIMARY KEY NOT NULL REFERENCES vaults (id),
    record BLOB NOT NULL
) STRICT;
CREATE TABLE approvals (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    code_hash BLOB NOT NULL UNIQUE,
    expires INTEGER NOT NULL,
    state INTEGER NOT NULL DEFAULT 0,
    device_public_key BLOB,
    device_name TEXT,
    commitment BLOB,
    keys_r BLOB,
    nonce_r BLOB,
    keys_c BLOB,
    nonce_c BLOB,
    seal BLOB,
    device BLOB
) STRICT;
CREATE INDEX approvals_by_expiry ON approvals (expires);
PRAGMA user_version = 3;
";

fn failed(e: rusqlite::Error) -> Error {
    Error::new(format!("the store failed: {e}"))
}

/// Opens `path` (made empty with mode 0600 when it does not exist, which
/// SQLite reads as a new database) with SYN-02.2's settings, and gives a
/// store with no schema the tables of SYN-02.3.
///
/// # Errors
/// The store is from a newer or an older server (refused before anything
/// changes), WAL cannot be turned on, or SQLite fails.
pub(crate) fn open(path: &Path) -> Result<Connection, Error> {
    if fs::symlink_metadata(path).is_err() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::new(format!("cannot make {}: {e}", path.display())))?;
    }
    let db = Connection::open(path).map_err(failed)?;
    // Litestream's tip: 5 s (SYN-02.2). A store another process holds
    // locked is refused after it.
    db.busy_timeout(Duration::from_secs(5)).map_err(failed)?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(failed)?;
    if version > SCHEMA {
        return Err(Error::new(format!(
            "{} was made by a newer server (schema {version}); this server reads schema \
             {SCHEMA}, so it changes nothing and does not start",
            path.display()
        )));
    }
    if version != 0 && version < SCHEMA {
        return Err(Error::new(format!(
            "{} was made by an older server (schema {version}); this server reads schema \
             {SCHEMA} and has no migration, so it changes nothing and does not start",
            path.display()
        )));
    }
    let mode: String = db
        .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
        .map_err(failed)?;
    if mode != "wal" {
        return Err(Error::new(format!(
            "{} cannot use write-ahead logging (journal mode {mode})",
            path.display()
        )));
    }
    // Each commit syncs the log: a version the server answered for survives
    // a power cut (sqlite.org "Write-Ahead Logging").
    db.pragma_update(None, "synchronous", "FULL")
        .map_err(failed)?;
    // On macOS a plain fsync may leave the log in the drive's cache; with
    // this SQLite syncs commits and checkpoints with F_FULLFSYNC (sqlite.org
    // "PRAGMA fullfsync"; Apple fsync(2)).
    db.pragma_update(None, "fullfsync", "ON").map_err(failed)?;
    db.pragma_update(None, "foreign_keys", "ON")
        .map_err(failed)?;
    if version == 0 {
        db.execute_batch(&format!("BEGIN; {TABLES} COMMIT;"))
            .map_err(failed)?;
    }
    Ok(db)
}

/// A vault's current row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    /// The account the vault belongs to.
    pub(crate) account: AccountId,
    /// The current version, from 1.
    pub(crate) version: u64,
    /// Its size in bytes.
    pub(crate) size: u64,
    /// The SHA-256 of its bytes: the name of its file.
    pub(crate) hash: [u8; 32],
    /// Who signed the version and the signature (SYN-01.7); `None` for a
    /// version uploaded unsigned (tests only, E16's accounts).
    pub(crate) signed: Option<Signed>,
}

/// An upload's signature as the store keeps it with its version (SYN-02.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signed {
    /// The signer's id: the account, for a personal vault (SYN-01.7).
    pub(crate) uploader: AccountId,
    /// The composite signature, 3,373 bytes (CRY-05.10).
    pub(crate) signature: Vec<u8>,
}

fn number(n: i64) -> Result<u64, Error> {
    u64::try_from(n).map_err(|_| Error::new("the store holds a negative number"))
}

fn integer(n: u64) -> Result<i64, Error> {
    i64::try_from(n).map_err(|_| Error::new("a number is too large for the store"))
}

/// The id, version and size of every vault of `account`, sorted by id
/// (SYN-01.6).
pub(crate) fn list(db: &Connection, account: &AccountId) -> Result<Vec<VaultVersion>, Error> {
    let mut query = db
        .prepare("SELECT id, version, size FROM vaults WHERE account = ?1 ORDER BY id")
        .map_err(failed)?;
    let rows = query
        .query_map([account.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(failed)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, version, size) = row.map_err(failed)?;
        out.push(VaultVersion {
            id: VaultId::from_bytes(id),
            version: number(version)?,
            size: number(size)?,
        });
    }
    Ok(out)
}

/// The current row of `id`, if the vault exists, whichever account it
/// belongs to.
pub(crate) fn current(db: &Connection, id: &VaultId) -> Result<Option<Row>, Error> {
    let row = db
        .query_row(
            "SELECT account, version, size, hash, uploader, signature FROM vaults WHERE id = ?1",
            [id.as_bytes()],
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, [u8; 32]>(3)?,
                    r.get::<_, Option<[u8; 16]>>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;
    row.map(|(account, version, size, hash, uploader, signature)| {
        Ok(Row {
            account: AccountId::from_bytes(account),
            version: number(version)?,
            size: number(size)?,
            hash,
            signed: uploader.zip(signature).map(|(uploader, signature)| Signed {
                uploader: AccountId::from_bytes(uploader),
                signature,
            }),
        })
    })
    .transpose()
}

/// True when a `vaults` or `vault_versions` row names the file `hash`.
pub(crate) fn named(db: &Connection, hash: &[u8; 32]) -> Result<bool, Error> {
    db.query_row(
        "SELECT EXISTS (SELECT 1 FROM vaults WHERE hash = ?1) \
         OR EXISTS (SELECT 1 FROM vault_versions WHERE hash = ?1)",
        [hash],
        |r| r.get(0),
    )
    .map_err(failed)
}

/// What the compare-and-swap did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cas {
    /// The row moved: the vault's new version (1 for a new vault).
    Done(u64),
    /// Another upload got there first, or the precondition names no current
    /// version: nothing changed (412).
    Conflict,
}

/// Step 4 of SYN-02.4 in one transaction: for an update, copy the row of
/// `account` that still has the `If-Match` version into `vault_versions`
/// and move it on by one (`WHERE id = ? AND version = ? AND account = ?`,
/// the server half of `If-Match`); for a new vault of `account`, insert it
/// unless the id exists in any account. Then prune `vault_versions` to
/// [`OLD_VERSIONS`] and commit. Also returns the hashes of the pruned rows,
/// whose files step 5 deletes when no row names them. The new version's
/// uploader and signature are `signed` (SYN-02.4 step 4); the copied old row
/// keeps its own.
pub(crate) fn cas(
    db: &mut Connection,
    id: &VaultId,
    account: &AccountId,
    want: Precondition,
    size: u64,
    hash: &[u8; 32],
    signed: Option<&Signed>,
) -> Result<(Cas, Vec<[u8; 32]>), Error> {
    let size = integer(size)?;
    let uploader = signed.map(|s| s.uploader.as_bytes().to_vec());
    let signature = signed.map(|s| s.signature.clone());
    let updated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let updated = integer(updated)?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let new = match want {
        Precondition::Create => {
            let exists = tx
                .query_row(
                    "SELECT 1 FROM vaults WHERE id = ?1",
                    [id.as_bytes()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(failed)?;
            if exists.is_some() {
                return Ok((Cas::Conflict, Vec::new()));
            }
            tx.execute(
                "INSERT INTO vaults (id, account, version, size, hash, updated, uploader, \
                 signature) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.as_bytes(),
                    account.as_bytes(),
                    size,
                    hash,
                    updated,
                    uploader,
                    signature
                ],
            )
            .map_err(failed)?;
            1
        }
        Precondition::Update(None) => return Ok((Cas::Conflict, Vec::new())),
        Precondition::Update(Some(old)) => {
            let (Ok(old_int), Some(new)) = (i64::try_from(old), old.checked_add(1)) else {
                return Ok((Cas::Conflict, Vec::new()));
            };
            let copied = tx
                .execute(
                    "INSERT INTO vault_versions (id, version, size, hash, updated, uploader, \
                     signature) SELECT id, version, size, hash, updated, uploader, signature \
                     FROM vaults WHERE id = ?1 AND version = ?2 AND account = ?3",
                    params![id.as_bytes(), old_int, account.as_bytes()],
                )
                .map_err(failed)?;
            let moved = tx
                .execute(
                    "UPDATE vaults SET version = version + 1, size = ?3, hash = ?4, updated = ?5, \
                     uploader = ?7, signature = ?8 WHERE id = ?1 AND version = ?2 AND account = ?6",
                    params![
                        id.as_bytes(),
                        old_int,
                        size,
                        hash,
                        updated,
                        account.as_bytes(),
                        uploader,
                        signature
                    ],
                )
                .map_err(failed)?;
            if copied != 1 || moved != 1 {
                return Ok((Cas::Conflict, Vec::new()));
            }
            new
        }
    };
    // Keep versions new - 5 to new - 1: version 7 keeps 2 to 6 (SYN-02.5).
    let keep_from = integer(new.saturating_sub(OLD_VERSIONS))?;
    let pruned = {
        let mut prune = tx
            .prepare("DELETE FROM vault_versions WHERE id = ?1 AND version < ?2 RETURNING hash")
            .map_err(failed)?;
        let hashes = prune
            .query_map(params![id.as_bytes(), keep_from], |r| {
                r.get::<_, [u8; 32]>(0)
            })
            .map_err(failed)?;
        hashes.collect::<Result<Vec<_>, _>>().map_err(failed)?
    };
    tx.commit().map_err(failed)?;
    Ok((Cas::Done(new), pruned))
}

/// Who a live session belongs to (SYN-04.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Caller {
    /// The device's account.
    pub(crate) account: AccountId,
    /// The device that signed in.
    pub(crate) device: DeviceId,
    /// The SHA-256 of the session's token: the session's key.
    pub(crate) session: [u8; 32],
}

/// The second of `now` as the store writes it.
fn at(now: u64) -> Result<i64, Error> {
    integer(now)
}

/// SYN-04.2: an account row and its first device row, in one transaction.
/// False (nothing written) when `public_key` is registered already (409).
pub(crate) fn create_account(
    db: &mut Connection,
    account: &AccountId,
    device: &DeviceId,
    public_key: &[u8; 65],
    name: &str,
    now: u64,
) -> Result<bool, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    tx.execute(
        "INSERT INTO accounts (id, created) VALUES (?1, ?2)",
        params![account.as_bytes(), at(now)?],
    )
    .map_err(failed)?;
    if !insert_device(&tx, account, device, public_key, name, now)? {
        return Ok(false);
    }
    tx.commit().map_err(failed)?;
    Ok(true)
}

/// A device row of `account`; false when the key is registered already.
fn insert_device(
    db: &Connection,
    account: &AccountId,
    device: &DeviceId,
    public_key: &[u8; 65],
    name: &str,
    now: u64,
) -> Result<bool, Error> {
    let taken = db
        .query_row(
            "SELECT 1 FROM devices WHERE public_key = ?1",
            [public_key],
            |_| Ok(()),
        )
        .optional()
        .map_err(failed)?;
    if taken.is_some() {
        return Ok(false);
    }
    db.execute(
        "INSERT INTO devices (id, account, public_key, name, added, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            device.as_bytes(),
            account.as_bytes(),
            public_key,
            name,
            at(now)?,
            at(minute(now))?
        ],
    )
    .map_err(failed)?;
    Ok(true)
}

/// SYN-06.12: a new device of `account`, registered by a passed recovery
/// sign-in, and its first session (stored as the SHA-256 `hash` of its
/// token), in one transaction. False (nothing written) when the key is
/// registered already (409).
pub(crate) fn recover_device(
    db: &mut Connection,
    account: &AccountId,
    device: &DeviceId,
    public_key: &[u8; 65],
    name: &str,
    hash: &[u8; 32],
    now: u64,
) -> Result<bool, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    if !insert_device(&tx, account, device, public_key, name, now)? {
        return Ok(false);
    }
    // As open_session: the ended sessions go first (SYN-04.5).
    tx.execute(
        "DELETE FROM sessions WHERE last_used <= ?1 OR created <= ?2",
        params![
            at(now.saturating_sub(SESSION_IDLE_SECONDS))?,
            at(now.saturating_sub(SESSION_MAX_SECONDS))?
        ],
    )
    .map_err(failed)?;
    tx.execute(
        "INSERT INTO sessions (hash, device, created, last_used) VALUES (?1, ?2, ?3, ?3)",
        params![hash, device.as_bytes(), at(now)?],
    )
    .map_err(failed)?;
    tx.commit().map_err(failed)?;
    Ok(true)
}

/// SYN-06.6: an account's keys row, as the record of `GET /v1/account/keys`
/// gives it; `None` before `PUT /v1/account/keys`.
pub(crate) fn account_keys(
    db: &Connection,
    account: &AccountId,
) -> Result<Option<AccountKeys>, Error> {
    let row = db
        .query_row(
            "SELECT identity_public_key, kem_public_key, kem_signature, recovery_public_key, \
             blob FROM accounts WHERE id = ?1 AND identity_public_key IS NOT NULL",
            [account.as_bytes()],
            |r| {
                Ok(AccountKeys {
                    identity_public_key: r.get(0)?,
                    kem_public_key: r.get(1)?,
                    kem_signature: r.get(2)?,
                    recovery_public_key: r.get(3)?,
                    blob: r.get(4)?,
                })
            },
        )
        .optional()
        .map_err(failed)?;
    Ok(row)
}

/// SYN-06.6: stores `keys` on the row of `account` once. False (nothing
/// written) when the row already has keys (412: no key change in this
/// build).
pub(crate) fn put_account_keys(
    db: &Connection,
    account: &AccountId,
    keys: &AccountKeys,
) -> Result<bool, Error> {
    let changed = db
        .execute(
            "UPDATE accounts SET identity_public_key = ?2, kem_public_key = ?3, \
             kem_signature = ?4, recovery_public_key = ?5, blob = ?6 \
             WHERE id = ?1 AND identity_public_key IS NULL",
            params![
                account.as_bytes(),
                keys.identity_public_key,
                keys.kem_public_key,
                keys.kem_signature,
                keys.recovery_public_key,
                keys.blob
            ],
        )
        .map_err(failed)?;
    Ok(changed == 1)
}

/// SYN-06.9: keeps `record` (a wrap record's JSON) as the key-file part
/// of `vault`, in place of any before it. False (nothing written) when the
/// vault does not exist or is another account's (404).
pub(crate) fn put_keypart(
    db: &Connection,
    account: &AccountId,
    vault: &VaultId,
    record: &[u8],
) -> Result<bool, Error> {
    let changed = db
        .execute(
            "INSERT INTO keyparts (vault, record) SELECT id, ?3 FROM vaults \
             WHERE id = ?1 AND account = ?2 \
             ON CONFLICT (vault) DO UPDATE SET record = excluded.record",
            params![vault.as_bytes(), account.as_bytes(), record],
        )
        .map_err(failed)?;
    Ok(changed == 1)
}

/// SYN-06.9: the key-file part record of `vault`, when the vault is
/// `account`'s and has one.
pub(crate) fn keypart(
    db: &Connection,
    account: &AccountId,
    vault: &VaultId,
) -> Result<Option<Vec<u8>>, Error> {
    db.query_row(
        "SELECT keyparts.record FROM keyparts JOIN vaults ON vaults.id = keyparts.vault \
         WHERE keyparts.vault = ?1 AND vaults.account = ?2",
        params![vault.as_bytes(), account.as_bytes()],
        |r| r.get(0),
    )
    .optional()
    .map_err(failed)
}

/// `last_seen` is kept to the minute (SYN-04.8).
fn minute(now: u64) -> u64 {
    (now / 60).saturating_mul(60)
}

/// What a challenge is for (LD-327 (7)): a device's sign-in (SYN-04.3) or
/// a recovery sign-in (SYN-06.12). A nonce of one kind never passes the
/// other's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Device = 0,
    Recovery = 1,
}

/// SYN-04.3: deletes every expired challenge, then stores `nonce` for
/// `device` until `expires`, for any device id: an unknown or revoked one
/// does the same work and gets the same reply, so ids cannot be probed by
/// its time either; its sign-in then fails. The rate limits and the expiry
/// bound the rows.
pub(crate) fn challenge(
    db: &Connection,
    nonce: &[u8; 32],
    device: &DeviceId,
    expires: u64,
    now: u64,
) -> Result<(), Error> {
    insert_challenge(db, nonce, device, Kind::Device, expires, now)
}

/// SYN-06.12: as [`challenge`], for a recovery sign-in of `account`; an
/// unknown account gets the same row and reply.
pub(crate) fn recovery_challenge(
    db: &Connection,
    nonce: &[u8; 32],
    account: &AccountId,
    expires: u64,
    now: u64,
) -> Result<(), Error> {
    insert_challenge(db, nonce, account, Kind::Recovery, expires, now)
}

fn insert_challenge(
    db: &Connection,
    nonce: &[u8; 32],
    bound: &DeviceId,
    kind: Kind,
    expires: u64,
    now: u64,
) -> Result<(), Error> {
    db.execute("DELETE FROM challenges WHERE expires <= ?1", [at(now)?])
        .map_err(failed)?;
    db.execute(
        "INSERT INTO challenges (nonce, device, expires, kind) VALUES (?1, ?2, ?3, ?4)",
        params![nonce, bound.as_bytes(), at(expires)?, kind as i64],
    )
    .map_err(failed)?;
    Ok(())
}

/// SYN-04.4's one use: deletes the challenge of `nonce`, whatever comes
/// next, and gives its device and expiry if it existed and was a device's.
/// The deletion is committed on its own, so a sign-in that then fails
/// cannot use it again.
pub(crate) fn take_challenge(
    db: &Connection,
    nonce: &[u8; 32],
) -> Result<Option<(DeviceId, u64)>, Error> {
    take(db, nonce, Kind::Device)
}

/// SYN-06.12: as [`take_challenge`] for a recovery challenge: its account
/// and expiry. A device's nonce is deleted and gives `None`.
pub(crate) fn take_recovery(
    db: &Connection,
    nonce: &[u8; 32],
) -> Result<Option<(AccountId, u64)>, Error> {
    take(db, nonce, Kind::Recovery)
}

fn take(db: &Connection, nonce: &[u8; 32], want: Kind) -> Result<Option<(DeviceId, u64)>, Error> {
    let row = db
        .query_row(
            "DELETE FROM challenges WHERE nonce = ?1 RETURNING device, expires, kind",
            [nonce],
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;
    row.filter(|(_, _, kind)| *kind == want as i64)
        .map(|(bound, expires, _)| Ok((DeviceId::from_bytes(bound), number(expires)?)))
        .transpose()
}

/// The stored public key of `device`, if the device exists (is not
/// revoked).
pub(crate) fn device_key(db: &Connection, device: &DeviceId) -> Result<Option<Vec<u8>>, Error> {
    db.query_row(
        "SELECT public_key FROM devices WHERE id = ?1",
        [device.as_bytes()],
        |r| r.get(0),
    )
    .optional()
    .map_err(failed)
}

/// SYN-04.5: deletes every session past its idle or absolute end, then
/// stores a new one under the SHA-256 of its token (`hash`). The token
/// itself never reaches the store.
pub(crate) fn open_session(
    db: &mut Connection,
    hash: &[u8; 32],
    device: &DeviceId,
    now: u64,
) -> Result<(), Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    tx.execute(
        "DELETE FROM sessions WHERE last_used <= ?1 OR created <= ?2",
        params![
            at(now.saturating_sub(SESSION_IDLE_SECONDS))?,
            at(now.saturating_sub(SESSION_MAX_SECONDS))?
        ],
    )
    .map_err(failed)?;
    tx.execute(
        "INSERT INTO sessions (hash, device, created, last_used) VALUES (?1, ?2, ?3, ?3)",
        params![hash, device.as_bytes(), at(now)?],
    )
    .map_err(failed)?;
    tx.commit().map_err(failed)
}

/// SYN-04.5, SYN-01.5: the session stored under `hash`, if it is live: used
/// less than [`SESSION_IDLE_SECONDS`] ago and made less than
/// [`SESSION_MAX_SECONDS`] ago, on the server's clock `now`. A session past
/// either end is deleted. A live one is marked used now, and its device
/// seen now (to the minute).
// ponytail: one write per request; batch the marks if load ever matters.
pub(crate) fn use_session(
    db: &mut Connection,
    hash: &[u8; 32],
    now: u64,
) -> Result<Option<Caller>, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let row = tx
        .query_row(
            "SELECT sessions.created, sessions.last_used, devices.id, devices.account \
             FROM sessions JOIN devices ON devices.id = sessions.device \
             WHERE sessions.hash = ?1",
            [hash],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, [u8; 16]>(2)?,
                    r.get::<_, [u8; 16]>(3)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;
    let Some((created, last_used, device, account)) = row else {
        return Ok(None);
    };
    let idle_end = number(last_used)?.saturating_add(SESSION_IDLE_SECONDS);
    let end = number(created)?.saturating_add(SESSION_MAX_SECONDS);
    if now >= idle_end || now >= end {
        tx.execute("DELETE FROM sessions WHERE hash = ?1", [hash])
            .map_err(failed)?;
        tx.commit().map_err(failed)?;
        return Ok(None);
    }
    tx.execute(
        "UPDATE sessions SET last_used = ?2 WHERE hash = ?1",
        params![hash, at(now)?],
    )
    .map_err(failed)?;
    tx.execute(
        "UPDATE devices SET last_seen = ?2 WHERE id = ?1",
        params![&device, at(minute(now))?],
    )
    .map_err(failed)?;
    tx.commit().map_err(failed)?;
    Ok(Some(Caller {
        account: AccountId::from_bytes(account),
        device: DeviceId::from_bytes(device),
        session: *hash,
    }))
}

/// SYN-04.7: deletes the session stored under `hash`.
pub(crate) fn end_session(db: &Connection, hash: &[u8; 32]) -> Result<(), Error> {
    db.execute("DELETE FROM sessions WHERE hash = ?1", [hash])
        .map_err(failed)
        .map(drop)
}

/// What a revoke did (SYN-04.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Revoke {
    /// The device, its sessions and its open challenges are gone (204).
    Done,
    /// No device of this account has that id (404), also when another
    /// account has it.
    NotFound,
    /// It is the account's last device (409): nothing changed.
    Last,
}

/// SYN-04.8: revokes `device` of `account` in one transaction.
pub(crate) fn revoke(
    db: &mut Connection,
    account: &AccountId,
    device: &DeviceId,
) -> Result<Revoke, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let mine = tx
        .query_row(
            "SELECT 1 FROM devices WHERE id = ?1 AND account = ?2",
            [device.as_bytes(), account.as_bytes()],
            |_| Ok(()),
        )
        .optional()
        .map_err(failed)?;
    if mine.is_none() {
        return Ok(Revoke::NotFound);
    }
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM devices WHERE account = ?1",
            [account.as_bytes()],
            |r| r.get(0),
        )
        .map_err(failed)?;
    if count <= 1 {
        return Ok(Revoke::Last);
    }
    tx.execute(
        "DELETE FROM challenges WHERE device = ?1",
        [device.as_bytes()],
    )
    .map_err(failed)?;
    tx.execute("DELETE FROM devices WHERE id = ?1", [device.as_bytes()])
        .map_err(failed)?;
    tx.commit().map_err(failed)?;
    Ok(Revoke::Done)
}

/// How far an approval request has come (SYN-06.11, SYN-05.2): each route
/// moves it one stage on, and only from the stage before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Made by E (`POST /v1/approvals`).
    Open = 0,
    /// N's claim is stored.
    Claimed = 1,
    /// N's commitment, SYN-05's message (1), is stored.
    Committed = 2,
    /// E's `K_R` and `n_R`, message (2).
    Keyed = 3,
    /// N's `K_C` and `n_C`, message (3).
    Revealed = 4,
    /// E's seal is stored and N's device registered.
    Sealed = 5,
}

/// An approval request's row (SYN-02.3): the SHA-256 of its code (never the
/// code), its account, its expiry and what the routes stored so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Approval {
    /// The request's id.
    pub(crate) id: Id,
    /// The account of the Mac that made it.
    pub(crate) account: AccountId,
    /// Its stage.
    pub(crate) stage: Stage,
    /// What `GET /v1/approvals/{approval_id}` shows; `expires` is the end of
    /// its 15 minutes on the server's clock.
    pub(crate) state: ApprovalState,
}

const APPROVAL: &str = "SELECT id, account, code_hash, expires, state, device_public_key, \
     device_name, commitment, keys_r, nonce_r, keys_c, nonce_c, seal, device FROM approvals";

fn stage(n: i64) -> Option<Stage> {
    [
        Stage::Open,
        Stage::Claimed,
        Stage::Committed,
        Stage::Keyed,
        Stage::Revealed,
        Stage::Sealed,
    ]
    .into_iter()
    .find(|s| *s as i64 == n)
}

type ApprovalColumns = (
    [u8; 16],
    [u8; 16],
    [u8; 32],
    i64,
    i64,
    (Option<[u8; DEVICE_KEY]>, Option<String>, Option<[u8; 32]>),
    (Option<Vec<u8>>, Option<[u8; 32]>),
    (Option<Vec<u8>>, Option<[u8; 32]>),
    (Option<Vec<u8>>, Option<[u8; 16]>),
);

fn approval_columns(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalColumns> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        (r.get(5)?, r.get(6)?, r.get(7)?),
        (r.get(8)?, r.get(9)?),
        (r.get(10)?, r.get(11)?),
        (r.get(12)?, r.get(13)?),
    ))
}

/// The row and its code hash.
fn approval_row(c: ApprovalColumns) -> Result<(Approval, [u8; 32]), Error> {
    let (id, account, code_hash, expires, n, claim, keys_r, keys_c, seal) = c;
    let (device_public_key, device_name, commit) = claim;
    let pair = |(k, n): (Option<Vec<u8>>, Option<[u8; 32]>)| k.zip(n);
    let state = ApprovalState {
        device_public_key,
        device_name,
        commit,
        keys_r: pair(keys_r),
        keys_c: pair(keys_c),
        seal: seal.0.zip(seal.1.map(DeviceId::from_bytes)),
        expires: number(expires)?,
    };
    let stage = stage(n).ok_or_else(|| Error::new("an approval row has no known stage"))?;
    Ok((
        Approval {
            id: Id::from_bytes(id),
            account: AccountId::from_bytes(account),
            stage,
            state,
        },
        code_hash,
    ))
}

/// SYN-06.11 step 1: ends every request past its 15 minutes (as
/// [`end_approval`]), then stores a new one for `account` under the SHA-256
/// of its code, in one transaction. False (nothing written) when a request
/// has that hash already (409).
pub(crate) fn create_approval(
    db: &mut Connection,
    id: &Id,
    account: &AccountId,
    code_hash: &[u8; 32],
    expires: u64,
    now: u64,
) -> Result<bool, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let ended: Vec<[u8; 16]> = {
        let mut q = tx
            .prepare("SELECT id FROM approvals WHERE expires <= ?1")
            .map_err(failed)?;
        q.query_map([at(now)?], |r| r.get(0))
            .map_err(failed)?
            .collect::<Result<_, _>>()
            .map_err(failed)?
    };
    for old in ended {
        end(&tx, &Id::from_bytes(old))?;
    }
    let added = tx
        .execute(
            "INSERT INTO approvals (id, account, code_hash, expires) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT DO NOTHING",
            params![id.as_bytes(), account.as_bytes(), code_hash, at(expires)?],
        )
        .map_err(failed)?;
    tx.commit().map_err(failed)?;
    Ok(added == 1)
}

/// The request whose code has the SHA-256 `code_hash`: looked up by the
/// hash, then the stored hash compared with it in constant time (CRY-04.11,
/// E17-S2's ruling (4)). Its expiry is the caller's to check.
pub(crate) fn approval_by_code(
    db: &Connection,
    code_hash: &[u8; 32],
) -> Result<Option<Approval>, Error> {
    let row = db
        .query_row(
            &format!("{APPROVAL} WHERE code_hash = ?1"),
            [code_hash],
            approval_columns,
        )
        .optional()
        .map_err(failed)?;
    let Some(row) = row.map(approval_row).transpose()? else {
        return Ok(None);
    };
    let (approval, stored) = row;
    Ok(larsal_crypto::secret::ct_eq(&stored, code_hash).then_some(approval))
}

/// The request `id` of `account`; another account's is `None` (404).
pub(crate) fn approval_of(
    db: &Connection,
    id: &Id,
    account: &AccountId,
) -> Result<Option<Approval>, Error> {
    let row = db
        .query_row(
            &format!("{APPROVAL} WHERE id = ?1 AND account = ?2"),
            [id.as_bytes(), account.as_bytes()],
            approval_columns,
        )
        .optional()
        .map_err(failed)?;
    Ok(row.map(approval_row).transpose()?.map(|(a, _)| a))
}

/// SYN-06.11's end of a request, whichever way (Codes differ, a failed
/// check, a second message, 15 minutes): the row goes with its nonces, its
/// commitment and its key lists (SYN-05.6), and a device its seal
/// registered that N has not taken yet goes with it, its sessions and
/// challenges too, so nothing stays registered.
pub(crate) fn end_approval(db: &mut Connection, id: &Id) -> Result<(), Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    end(&tx, id)?;
    tx.commit().map_err(failed)
}

fn end(db: &Connection, id: &Id) -> Result<(), Error> {
    let device: Option<Option<[u8; 16]>> = db
        .query_row(
            "SELECT device FROM approvals WHERE id = ?1",
            [id.as_bytes()],
            |r| r.get(0),
        )
        .optional()
        .map_err(failed)?;
    if let Some(Some(device)) = device {
        db.execute("DELETE FROM challenges WHERE device = ?1", [&device])
            .map_err(failed)?;
        db.execute("DELETE FROM devices WHERE id = ?1", [&device])
            .map_err(failed)?;
    }
    db.execute("DELETE FROM approvals WHERE id = ?1", [id.as_bytes()])
        .map_err(failed)?;
    Ok(())
}

/// SYN-06.11 step 6: N has read the seal; the request is done and its row
/// goes, the device it registered stays.
pub(crate) fn hand_over(db: &Connection, id: &Id) -> Result<(), Error> {
    db.execute(
        "DELETE FROM approvals WHERE id = ?1 AND state = ?2",
        params![id.as_bytes(), Stage::Sealed as i64],
    )
    .map_err(failed)
    .map(drop)
}

/// Moves request `id` from `from` to the next stage with the columns of
/// `set` (`?2` on); false when it was not at `from`.
fn step(
    db: &Connection,
    id: &Id,
    from: Stage,
    set: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<bool, Error> {
    let sql = format!(
        "UPDATE approvals SET state = state + 1, {set} WHERE id = ?1 AND state = {}",
        from as i64
    );
    let mut all: Vec<&dyn rusqlite::ToSql> = vec![id.as_bytes()];
    all.extend_from_slice(values);
    let changed = db.execute(&sql, all.as_slice()).map_err(failed)?;
    Ok(changed == 1)
}

/// Step 2: N's claim, its device key and name.
pub(crate) fn claim_approval(
    db: &Connection,
    id: &Id,
    key: &[u8; DEVICE_KEY],
    name: &str,
) -> Result<bool, Error> {
    step(
        db,
        id,
        Stage::Open,
        "device_public_key = ?2, device_name = ?3",
        &[key, &name],
    )
}

/// SYN-05's message (1).
pub(crate) fn commit_approval(db: &Connection, id: &Id, commit: &[u8; 32]) -> Result<bool, Error> {
    step(db, id, Stage::Claimed, "commitment = ?2", &[commit])
}

/// SYN-05's message (2): `K_R` and `n_R`.
pub(crate) fn keys_approval(
    db: &Connection,
    id: &Id,
    keys: &[u8],
    nonce: &[u8; 32],
) -> Result<bool, Error> {
    step(
        db,
        id,
        Stage::Committed,
        "keys_r = ?2, nonce_r = ?3",
        &[&keys, nonce],
    )
}

/// SYN-05's message (3): `K_C` and `n_C`.
pub(crate) fn reveal_approval(
    db: &Connection,
    id: &Id,
    keys: &[u8],
    nonce: &[u8; 32],
) -> Result<bool, Error> {
    step(
        db,
        id,
        Stage::Keyed,
        "keys_c = ?2, nonce_c = ?3",
        &[&keys, nonce],
    )
}

/// What a seal did (step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sealed {
    /// The seal is stored and N's device registered.
    Done,
    /// N's device key is registered already (409).
    Taken,
    /// The request was not at its reveal (409).
    Stale,
}

/// Step 5: N's device row and the seal, in one transaction; nothing when
/// the key is registered already or the request is not at its reveal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_approval(
    db: &mut Connection,
    id: &Id,
    account: &AccountId,
    device: &DeviceId,
    key: &[u8; DEVICE_KEY],
    name: &str,
    seal: &[u8],
    now: u64,
) -> Result<Sealed, Error> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    if !insert_device(&tx, account, device, key, name, now)? {
        return Ok(Sealed::Taken);
    }
    if !step(
        &tx,
        id,
        Stage::Revealed,
        "seal = ?2, device = ?3",
        &[&seal, device.as_bytes()],
    )? {
        return Ok(Sealed::Stale);
    }
    tx.commit().map_err(failed)?;
    Ok(Sealed::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::tests::Scratch;

    fn id(n: u8) -> VaultId {
        VaultId::from_bytes([n; 16])
    }

    /// T03: the pragmas read back as WAL, FULL and fullfsync on the server's
    /// own connection (synchronous, fullfsync and foreign_keys are per
    /// connection).
    #[test]
    fn syn02_2_t03_pragmas_read_back_wal_and_full() {
        let scratch = Scratch::new();
        let db = open(&scratch.0.join("store.sqlite")).unwrap();
        let text =
            |name: &str| -> String { db.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
        let int = |name: &str| -> i64 { db.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
        assert_eq!(text("journal_mode"), "wal");
        assert_eq!(int("synchronous"), 2, "2 is FULL");
        assert_eq!(int("fullfsync"), 1, "F_FULLFSYNC on macOS");
        assert_eq!(int("foreign_keys"), 1);
        assert_eq!(int("user_version"), 3);
        assert_eq!(int("busy_timeout"), 5000);
        // A second start reads the same store and keeps its schema.
        drop(db);
        let db = open(&scratch.0.join("store.sqlite")).unwrap();
        let tables: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 8);
    }

    /// The new vault's row, the compare-and-swap and the prune on their own.
    /// An account with one device, for the vault rows' foreign key.
    pub(crate) fn account(db: &mut Connection, n: u8) -> AccountId {
        let a = AccountId::from_bytes([n; 16]);
        let d = DeviceId::from_bytes([n.wrapping_add(100); 16]);
        assert!(create_account(db, &a, &d, &[n; 65], "Mac", 1_800_000_000).unwrap());
        a
    }

    #[test]
    fn syn02_4_cas_moves_only_the_named_version_and_prunes_to_five() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let x = id(1);
        let h = |n: u8| [n; 32];
        assert_eq!(
            cas(&mut db, &x, &me, Precondition::Create, 10, &h(1), None).unwrap(),
            (Cas::Done(1), vec![])
        );
        assert_eq!(
            cas(&mut db, &x, &me, Precondition::Create, 10, &h(9), None).unwrap(),
            (Cas::Conflict, vec![])
        );
        for stale in [None, Some(0), Some(2), Some(u64::MAX)] {
            assert_eq!(
                cas(
                    &mut db,
                    &x,
                    &me,
                    Precondition::Update(stale),
                    10,
                    &h(9),
                    None
                )
                .unwrap(),
                (Cas::Conflict, vec![]),
                "{stale:?}"
            );
        }
        assert!(!named(&db, &h(9)).unwrap(), "a refused swap stored nothing");
        // Another account names the right version: no such vault for it.
        let them = account(&mut db, 2);
        assert_eq!(
            cas(
                &mut db,
                &x,
                &them,
                Precondition::Update(Some(1)),
                10,
                &h(9),
                None
            )
            .unwrap(),
            (Cas::Conflict, vec![])
        );
        assert_eq!(
            cas(&mut db, &x, &them, Precondition::Create, 10, &h(9), None).unwrap(),
            (Cas::Conflict, vec![]),
            "the id exists in another account"
        );
        assert_eq!(current(&db, &x).unwrap().unwrap().account, me);
        assert_eq!(list(&db, &them).unwrap(), vec![]);
        let other = id(2);
        assert_eq!(
            cas(
                &mut db,
                &other,
                &me,
                Precondition::Update(Some(1)),
                10,
                &h(9),
                None
            )
            .unwrap(),
            (Cas::Conflict, vec![]),
            "an id that does not exist"
        );
        for n in 2..=6 {
            let (done, pruned) = cas(
                &mut db,
                &x,
                &me,
                Precondition::Update(Some(u64::from(n) - 1)),
                10,
                &h(n),
                None,
            )
            .unwrap();
            assert_eq!((done, pruned), (Cas::Done(u64::from(n)), vec![]));
        }
        // The 7th upload prunes version 1.
        let (done, pruned) = cas(
            &mut db,
            &x,
            &me,
            Precondition::Update(Some(6)),
            10,
            &h(7),
            None,
        )
        .unwrap();
        assert_eq!((done, pruned), (Cas::Done(7), vec![h(1)]));
        assert_eq!(current(&db, &x).unwrap().unwrap().hash, h(7));
        let kept: Vec<i64> = db
            .prepare("SELECT version FROM vault_versions WHERE id = ?1 ORDER BY version")
            .unwrap()
            .query_map([x.as_bytes()], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(kept, [2, 3, 4, 5, 6]);
        assert!(!named(&db, &h(1)).unwrap());
        assert!(named(&db, &h(2)).unwrap() && named(&db, &h(7)).unwrap());
    }

    /// T04: a store from a newer server is refused and nothing in the
    /// folder changes, its `-wal` and `-shm` files included.
    #[test]
    fn syn02_2_t04_newer_schema_refused_and_folder_unchanged() {
        let scratch = Scratch::new();
        let path = scratch.0.join("store.sqlite");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "PRAGMA journal_mode = WAL; CREATE TABLE t (a); PRAGMA user_version = 4;",
            )
            .unwrap();
        }
        let tree = || -> Vec<(String, Vec<u8>)> {
            let mut all: Vec<_> = fs::read_dir(&scratch.0)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.display().to_string(), fs::read(&p).unwrap())
                })
                .collect();
            all.sort();
            all
        };
        let before = tree();
        let err = open(&path).unwrap_err().to_string();
        assert!(
            err.contains("was made by a newer server (schema 4)"),
            "{err}"
        );
        assert_eq!(tree(), before);
    }

    /// SYN-04.5 at the edges: live up to the second before its idle end and
    /// its absolute end, ended (and deleted) at them; each use moves the
    /// idle end; the store holds the hash only.
    #[test]
    fn syn04_5_session_ends_at_idle_and_absolute_end() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let device = DeviceId::from_bytes([101; 16]);
        let t0 = 1_800_000_000;
        let hash = [7u8; 32];
        open_session(&mut db, &hash, &device, t0).unwrap();
        let live = |db: &mut Connection, now| use_session(db, &hash, now).unwrap();
        let caller = live(&mut db, t0 + 899).unwrap();
        assert_eq!(
            (caller.account, caller.device, caller.session),
            (me, device, hash)
        );
        assert!(
            live(&mut db, t0 + 899 + 899).is_some(),
            "the use moved the idle end"
        );
        assert!(live(&mut db, t0 + 899 + 899 + 900).is_none(), "900 s idle");
        assert!(
            live(&mut db, t0 + 899 + 899 + 1).is_none(),
            "the row was deleted"
        );
        // Used every 10 minutes: ends at 8 h all the same.
        open_session(&mut db, &hash, &device, t0).unwrap();
        let mut now = t0;
        while now + 600 < t0 + SESSION_MAX_SECONDS {
            now += 600;
            assert!(live(&mut db, now).is_some(), "{}", now - t0);
        }
        assert!(live(&mut db, t0 + SESSION_MAX_SECONDS - 1).is_some());
        assert!(live(&mut db, t0 + SESSION_MAX_SECONDS).is_none(), "8 h");
        let rows: i64 = db
            .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        // A new session sweeps the ended ones.
        open_session(&mut db, &[1; 32], &device, t0).unwrap();
        open_session(&mut db, &[2; 32], &device, t0 + 900).unwrap();
        let rows: Vec<Vec<u8>> = db
            .prepare("SELECT hash FROM sessions")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows, vec![vec![2u8; 32]]);
    }

    /// SYN-04.3, SYN-04.4: a challenge is stored for any device id, an
    /// unknown one too (the same work, so ids cannot be probed), taken
    /// once, and swept once expired.
    #[test]
    fn syn04_3_challenges_one_use_and_swept() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        account(&mut db, 1);
        let device = DeviceId::from_bytes([101; 16]);
        let t0 = 1_800_000_000;
        challenge(&db, &[1; 32], &device, t0 + 300, t0).unwrap();
        let unknown = DeviceId::from_bytes([9; 16]);
        challenge(&db, &[2; 32], &unknown, t0 + 300, t0).unwrap();
        assert_eq!(
            take_challenge(&db, &[2; 32]).unwrap(),
            Some((unknown, t0 + 300)),
            "unknown device"
        );
        assert_eq!(take_challenge(&db, &[2; 32]).unwrap(), None);
        assert_eq!(
            take_challenge(&db, &[1; 32]).unwrap(),
            Some((device, t0 + 300))
        );
        assert_eq!(take_challenge(&db, &[1; 32]).unwrap(), None, "used once");
        challenge(&db, &[3; 32], &device, t0 + 300, t0).unwrap();
        challenge(&db, &[4; 32], &device, t0 + 600, t0 + 300).unwrap();
        assert_eq!(
            take_challenge(&db, &[3; 32]).unwrap(),
            None,
            "swept at 300 s"
        );
        assert!(take_challenge(&db, &[4; 32]).unwrap().is_some());
    }

    /// SYN-04.2's 409 and SYN-04.8's revoke: a key is registered once; a
    /// revoke takes the device's sessions and challenges with it, never the
    /// last device, and never another account's.
    #[test]
    fn syn04_8_revoke_cascades_and_keeps_the_last_device() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let them = account(&mut db, 2);
        let (d1, d2) = (
            DeviceId::from_bytes([101; 16]),
            DeviceId::from_bytes([50; 16]),
        );
        let t0 = 1_800_000_000;
        let taken = AccountId::from_bytes([3; 16]);
        assert!(!create_account(&mut db, &taken, &d2, &[1; 65], "Mac", t0).unwrap());
        let accounts: i64 = db
            .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(accounts, 2, "no account row for a taken key");
        assert!(!insert_device(&db, &me, &d2, &[2; 65], "Mac", t0).unwrap());
        assert!(insert_device(&db, &me, &d2, &[50; 65], "Mac 2", t0).unwrap());
        open_session(&mut db, &[5; 32], &d2, t0).unwrap();
        challenge(&db, &[5; 32], &d2, t0 + 300, t0).unwrap();
        assert_eq!(revoke(&mut db, &them, &d2).unwrap(), Revoke::NotFound);
        assert_eq!(revoke(&mut db, &me, &d2).unwrap(), Revoke::Done);
        assert_eq!(use_session(&mut db, &[5; 32], t0 + 1).unwrap(), None);
        assert_eq!(take_challenge(&db, &[5; 32]).unwrap(), None);
        assert_eq!(device_key(&db, &d2).unwrap(), None);
        assert_eq!(revoke(&mut db, &me, &d2).unwrap(), Revoke::NotFound);
        assert_eq!(revoke(&mut db, &me, &d1).unwrap(), Revoke::Last);
        assert!(device_key(&db, &d1).unwrap().is_some());
    }

    /// The schema 1 of E16 as the server before E17-S1 made it, for the
    /// refusal check.
    const SCHEMA_1: &str = "
CREATE TABLE accounts (
    id BLOB PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL
) STRICT;
CREATE TABLE devices (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    public_key BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    added INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
) STRICT;
CREATE INDEX devices_by_account ON devices (account);
CREATE TABLE challenges (
    nonce BLOB PRIMARY KEY NOT NULL,
    device BLOB NOT NULL,
    expires INTEGER NOT NULL
) STRICT;
CREATE INDEX challenges_by_device ON challenges (device);
CREATE INDEX challenges_by_expiry ON challenges (expires);
CREATE TABLE sessions (
    hash BLOB PRIMARY KEY NOT NULL,
    device BLOB NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_by_device ON sessions (device);
CREATE TABLE vaults (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    version INTEGER NOT NULL,
    size INTEGER NOT NULL,
    hash BLOB NOT NULL,
    updated INTEGER NOT NULL
) STRICT;
CREATE INDEX vaults_by_hash ON vaults (hash);
CREATE INDEX vaults_by_account ON vaults (account, id);
CREATE TABLE vault_versions (
    id BLOB NOT NULL REFERENCES vaults (id),
    version INTEGER NOT NULL,
    size INTEGER NOT NULL,
    hash BLOB NOT NULL,
    updated INTEGER NOT NULL,
    PRIMARY KEY (id, version)
) STRICT;
CREATE INDEX vault_versions_by_hash ON vault_versions (hash);
PRAGMA user_version = 1;
";

    fn signed(n: u8) -> Signed {
        Signed {
            uploader: AccountId::from_bytes([n; 16]),
            signature: vec![n; 3373],
        }
    }

    fn keys(n: u8) -> AccountKeys {
        AccountKeys {
            identity_public_key: vec![n; 1984],
            kem_public_key: vec![n.wrapping_add(1); 1216],
            kem_signature: vec![n.wrapping_add(2); 3373],
            recovery_public_key: [n.wrapping_add(3); 32],
            blob: vec![n.wrapping_add(4); 158],
        }
    }

    /// SYN-02.2 (schema 3, E17-S2; LD-327 (5)): no migration code, so a
    /// store of schema 1 (E16) or 2 (E17-S1) is refused at open with a plain
    /// message, and nothing in the folder changes.
    #[test]
    fn syn02_2_an_older_schema_is_refused_and_folder_unchanged() {
        for (version, schema) in [(1, SCHEMA_1.to_owned()), (2, TABLES.replace("3;", "2;"))] {
            let scratch = Scratch::new();
            let path = scratch.0.join("store.sqlite");
            {
                let db = Connection::open(&path).unwrap();
                db.execute_batch(&format!("PRAGMA journal_mode = WAL; {schema}"))
                    .unwrap();
                db.execute(
                    "INSERT INTO accounts (id, created) VALUES (?1, 1)",
                    [&[1u8; 16][..]],
                )
                .unwrap();
            }
            let tree = || -> Vec<(String, Vec<u8>)> {
                let mut all: Vec<_> = fs::read_dir(&scratch.0)
                    .unwrap()
                    .map(|e| {
                        let p = e.unwrap().path();
                        (p.display().to_string(), fs::read(&p).unwrap())
                    })
                    .collect();
                all.sort();
                all
            };
            let before = tree();
            let err = open(&path).unwrap_err().to_string();
            assert!(
                err.contains(&format!("was made by an older server (schema {version})")),
                "{err}"
            );
            assert!(err.contains("has no migration"), "{err}");
            assert_eq!(tree(), before, "schema {version}: the folder is unchanged");
        }
    }

    /// SYN-02.3, SYN-05.6, SYN-06.11 (E17-S2's ruling (8)): an approval row
    /// holds the code's SHA-256 only, each stage once and in order; the row
    /// goes when the request ends, with the device its seal registered
    /// before N took it; a request past its 15 minutes goes at the next
    /// `POST /v1/approvals`.
    #[test]
    fn syn02_3_syn05_6_the_approval_row_and_its_end() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let t0 = 1_800_000_000;
        let (id, hash) = (Id::from_bytes([7; 16]), [8u8; 32]);
        assert!(create_approval(&mut db, &id, &me, &hash, t0 + 900, t0).unwrap());
        let again = Id::from_bytes([9; 16]);
        assert!(!create_approval(&mut db, &again, &me, &hash, t0 + 900, t0).unwrap());
        let row = approval_by_code(&db, &hash).unwrap().unwrap();
        assert_eq!((row.id, row.account, row.stage), (id, me, Stage::Open));
        assert_eq!(row.state.expires, t0 + 900);
        assert_eq!(approval_by_code(&db, &[9; 32]).unwrap(), None);
        assert_eq!(
            approval_of(&db, &id, &AccountId::from_bytes([2; 16])).unwrap(),
            None
        );
        // Each stage once, and only from the one before.
        assert!(
            !commit_approval(&db, &id, &[3; 32]).unwrap(),
            "no commit before the claim"
        );
        assert!(claim_approval(&db, &id, &[60; 65], "New Mac").unwrap());
        assert!(
            !claim_approval(&db, &id, &[61; 65], "Other").unwrap(),
            "one claim"
        );
        assert!(commit_approval(&db, &id, &[3; 32]).unwrap());
        assert!(
            !commit_approval(&db, &id, &[4; 32]).unwrap(),
            "one commitment"
        );
        assert!(keys_approval(&db, &id, &[5; 2057], &[6; 32]).unwrap());
        assert!(reveal_approval(&db, &id, &[7; 1289], &[8; 32]).unwrap());
        let device = DeviceId::from_bytes([60; 16]);
        let sealed = seal_approval(&mut db, &id, &me, &device, &[60; 65], "New Mac", b"s", t0);
        assert_eq!(sealed.unwrap(), Sealed::Done);
        let row = approval_of(&db, &id, &me).unwrap().unwrap();
        assert_eq!(row.stage, Stage::Sealed);
        assert_eq!(row.state.commit, Some([3; 32]));
        assert_eq!(row.state.keys_r, Some((vec![5; 2057], [6; 32])));
        assert_eq!(row.state.keys_c, Some((vec![7; 1289], [8; 32])));
        assert_eq!(row.state.seal, Some((b"s".to_vec(), device)));
        assert!(device_key(&db, &device).unwrap().is_some());
        // Ended before N took the seal: the device goes too.
        end_approval(&mut db, &id).unwrap();
        assert_eq!(approval_of(&db, &id, &me).unwrap(), None);
        assert_eq!(device_key(&db, &device).unwrap(), None);
        let rows: i64 = db
            .query_row("SELECT count(*) FROM approvals", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "no nonce, commitment or key list is left");
        // Handed over: the row goes, the device stays.
        let id2 = Id::from_bytes([10; 16]);
        assert!(create_approval(&mut db, &id2, &me, &[11; 32], t0 + 900, t0).unwrap());
        assert!(claim_approval(&db, &id2, &[62; 65], "New Mac").unwrap());
        assert!(commit_approval(&db, &id2, &[3; 32]).unwrap());
        assert!(keys_approval(&db, &id2, &[5; 2057], &[6; 32]).unwrap());
        assert!(reveal_approval(&db, &id2, &[7; 1289], &[8; 32]).unwrap());
        let d2 = DeviceId::from_bytes([62; 16]);
        let sealed = seal_approval(&mut db, &id2, &me, &d2, &[62; 65], "New Mac", b"s", t0);
        assert_eq!(sealed.unwrap(), Sealed::Done);
        hand_over(&db, &id2).unwrap();
        assert_eq!(approval_of(&db, &id2, &me).unwrap(), None);
        assert!(device_key(&db, &d2).unwrap().is_some());
        // A taken key registers nothing and leaves the request at its reveal.
        let id3 = Id::from_bytes([12; 16]);
        assert!(create_approval(&mut db, &id3, &me, &[13; 32], t0 + 900, t0).unwrap());
        assert!(claim_approval(&db, &id3, &[62; 65], "Same key").unwrap());
        assert!(commit_approval(&db, &id3, &[3; 32]).unwrap());
        assert!(keys_approval(&db, &id3, &[5; 2057], &[6; 32]).unwrap());
        assert!(reveal_approval(&db, &id3, &[7; 1289], &[8; 32]).unwrap());
        let d3 = DeviceId::from_bytes([63; 16]);
        let taken = seal_approval(&mut db, &id3, &me, &d3, &[62; 65], "Same key", b"s", t0);
        assert_eq!(taken.unwrap(), Sealed::Taken);
        assert_eq!(
            approval_of(&db, &id3, &me).unwrap().unwrap().stage,
            Stage::Revealed
        );
        // Past its 15 minutes, the next request's sweep ends it.
        let id4 = Id::from_bytes([14; 16]);
        assert!(create_approval(&mut db, &id4, &me, &[15; 32], t0 + 1800, t0 + 900).unwrap());
        assert_eq!(approval_of(&db, &id3, &me).unwrap(), None);
        assert!(approval_of(&db, &id4, &me).unwrap().is_some());
    }

    /// SYN-06.6: the keys are stored once; a second set changes nothing
    /// (412); another account's row and an unknown account have none.
    #[test]
    fn syn06_6_account_keys_are_stored_once() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let them = account(&mut db, 2);
        assert_eq!(account_keys(&db, &me).unwrap(), None);
        assert!(put_account_keys(&db, &me, &keys(1)).unwrap());
        assert!(!put_account_keys(&db, &me, &keys(9)).unwrap());
        assert_eq!(account_keys(&db, &me).unwrap(), Some(keys(1)));
        assert_eq!(account_keys(&db, &them).unwrap(), None);
        let unknown = AccountId::from_bytes([3; 16]);
        assert!(!put_account_keys(&db, &unknown, &keys(3)).unwrap());
        assert_eq!(account_keys(&db, &unknown).unwrap(), None);
    }

    /// LD-327 (7), SYN-06.12: a device's nonce never passes the recovery
    /// check and a recovery nonce never the device's; either way it is gone.
    #[test]
    fn syn06_12_challenge_kinds_are_kept_apart() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let device = DeviceId::from_bytes([101; 16]);
        let t0 = 1_800_000_000;
        challenge(&db, &[1; 32], &device, t0 + 300, t0).unwrap();
        recovery_challenge(&db, &[2; 32], &me, t0 + 300, t0).unwrap();
        assert_eq!(take_recovery(&db, &[1; 32]).unwrap(), None);
        assert_eq!(take_challenge(&db, &[1; 32]).unwrap(), None, "gone");
        assert_eq!(take_challenge(&db, &[2; 32]).unwrap(), None);
        assert_eq!(take_recovery(&db, &[2; 32]).unwrap(), None, "gone");
        recovery_challenge(&db, &[3; 32], &me, t0 + 300, t0).unwrap();
        let unknown = AccountId::from_bytes([9; 16]);
        recovery_challenge(&db, &[4; 32], &unknown, t0 + 300, t0).unwrap();
        assert_eq!(take_recovery(&db, &[3; 32]).unwrap(), Some((me, t0 + 300)));
        assert_eq!(take_recovery(&db, &[3; 32]).unwrap(), None, "used once");
        assert_eq!(
            take_recovery(&db, &[4; 32]).unwrap(),
            Some((unknown, t0 + 300)),
            "an unknown account gets the same row"
        );
    }

    /// SYN-06.9: a key-file part is kept for the owner's vault only, in
    /// place of the one before it.
    #[test]
    fn syn06_9_keypart_is_the_owners_only() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let them = account(&mut db, 2);
        let x = id(1);
        cas(&mut db, &x, &me, Precondition::Create, 10, &[1; 32], None).unwrap();
        assert!(!put_keypart(&db, &them, &x, b"theirs").unwrap());
        assert_eq!(keypart(&db, &them, &x).unwrap(), None);
        assert_eq!(keypart(&db, &me, &x).unwrap(), None);
        assert!(put_keypart(&db, &me, &x, b"first").unwrap());
        assert!(put_keypart(&db, &me, &x, b"second").unwrap());
        assert_eq!(keypart(&db, &me, &x).unwrap(), Some(b"second".to_vec()));
        assert_eq!(keypart(&db, &them, &x).unwrap(), None);
        assert!(!put_keypart(&db, &me, &id(2), b"none").unwrap());
    }

    /// SYN-01.7, SYN-02.3: each version is stored with its uploader and
    /// signature; the old row keeps its own.
    #[test]
    fn syn01_7_cas_keeps_the_signature_with_its_version() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let x = id(1);
        let first = signed(1);
        let second = signed(2);
        cas(
            &mut db,
            &x,
            &me,
            Precondition::Create,
            10,
            &[1; 32],
            Some(&first),
        )
        .unwrap();
        assert_eq!(
            current(&db, &x).unwrap().unwrap().signed,
            Some(first.clone())
        );
        cas(
            &mut db,
            &x,
            &me,
            Precondition::Update(Some(1)),
            10,
            &[2; 32],
            Some(&second),
        )
        .unwrap();
        assert_eq!(current(&db, &x).unwrap().unwrap().signed, Some(second));
        let old: (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT uploader, signature FROM vault_versions WHERE id = ?1 AND version = 1",
                [x.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(old, (first.uploader.as_bytes().to_vec(), first.signature));
    }

    /// SYN-06.12: a recovered device and its session are written together;
    /// a key that is registered already writes nothing (409).
    #[test]
    fn syn06_12_recover_device_writes_the_device_and_its_session_or_nothing() {
        let scratch = Scratch::new();
        let mut db = open(&scratch.0.join("store.sqlite")).unwrap();
        let me = account(&mut db, 1);
        let t0 = 1_800_000_000;
        let new = DeviceId::from_bytes([60; 16]);
        assert!(recover_device(&mut db, &me, &new, &[60; 65], "Mac", &[6; 32], t0).unwrap());
        let caller = use_session(&mut db, &[6; 32], t0 + 1).unwrap().unwrap();
        assert_eq!((caller.account, caller.device), (me, new));
        let other = DeviceId::from_bytes([61; 16]);
        assert!(!recover_device(&mut db, &me, &other, &[1; 65], "Mac", &[7; 32], t0).unwrap());
        assert_eq!(use_session(&mut db, &[7; 32], t0 + 1).unwrap(), None);
        assert_eq!(device_key(&db, &other).unwrap(), None);
    }
}
