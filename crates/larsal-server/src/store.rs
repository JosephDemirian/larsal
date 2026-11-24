//! The SQLite store (SYN-02.2, SYN-02.3): `store.sqlite` in the data
//! folder, in WAL mode with `synchronous=FULL`. E16-S4 has the `vaults` and
//! `vault_versions` tables; E16-S5 the `accounts`, `devices`, `challenges`
//! and `sessions` tables and the vault's account (SYN-04); E17-S1 adds the
//! uploader and signature columns.
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
use larsal_proto::limits::{SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS};
use larsal_proto::messages::{AccountId, DeviceId, VaultId, VaultVersion};
use larsal_proto::routes::Precondition;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The schema version this server writes and reads (SYN-02.2).
pub(crate) const SCHEMA: i64 = 1;

/// Old versions kept beside the current one, for restore only (SYN-02.5).
pub(crate) const OLD_VERSIONS: u64 = 5;

/// SYN-02.3's rows of E16-S4 and E16-S5. Ids are 16 bytes, hashes 32,
/// times whole seconds UTC. A device's public key is unique over the store.
const TABLES: &str = "
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

fn failed(e: rusqlite::Error) -> Error {
    Error::new(format!("the store failed: {e}"))
}

/// Opens `path` (made empty with mode 0600 when it does not exist, which
/// SQLite reads as a new database) with SYN-02.2's settings, and gives a
/// store with no schema the tables of SYN-02.3.
///
/// # Errors
/// The store is from a newer server (refused before anything changes), WAL
/// cannot be turned on, or SQLite fails.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Row {
    /// The account the vault belongs to.
    pub(crate) account: AccountId,
    /// The current version, from 1.
    pub(crate) version: u64,
    /// Its size in bytes.
    pub(crate) size: u64,
    /// The SHA-256 of its bytes: the name of its file.
    pub(crate) hash: [u8; 32],
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
            "SELECT account, version, size, hash FROM vaults WHERE id = ?1",
            [id.as_bytes()],
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, [u8; 32]>(3)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;
    row.map(|(account, version, size, hash)| {
        Ok(Row {
            account: AccountId::from_bytes(account),
            version: number(version)?,
            size: number(size)?,
            hash,
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
/// whose files step 5 deletes when no row names them.
pub(crate) fn cas(
    db: &mut Connection,
    id: &VaultId,
    account: &AccountId,
    want: Precondition,
    size: u64,
    hash: &[u8; 32],
) -> Result<(Cas, Vec<[u8; 32]>), Error> {
    let size = integer(size)?;
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
                "INSERT INTO vaults (id, account, version, size, hash, updated) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                params![id.as_bytes(), account.as_bytes(), size, hash, updated],
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
                    "INSERT INTO vault_versions (id, version, size, hash, updated) \
                     SELECT id, version, size, hash, updated FROM vaults \
                     WHERE id = ?1 AND version = ?2 AND account = ?3",
                    params![id.as_bytes(), old_int, account.as_bytes()],
                )
                .map_err(failed)?;
            let moved = tx
                .execute(
                    "UPDATE vaults SET version = version + 1, size = ?3, hash = ?4, updated = ?5 \
                     WHERE id = ?1 AND version = ?2 AND account = ?6",
                    params![
                        id.as_bytes(),
                        old_int,
                        size,
                        hash,
                        updated,
                        account.as_bytes()
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

/// SYN-04.11: another device of an existing account (tests only, until
/// E17-S2's approval). False when the key is registered already.
#[cfg(any(test, feature = "test-seams"))]
pub(crate) fn add_device(
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
    if !insert_device(&tx, account, device, public_key, name, now)? {
        return Ok(false);
    }
    tx.commit().map_err(failed)?;
    Ok(true)
}

/// `last_seen` is kept to the minute (SYN-04.8).
fn minute(now: u64) -> u64 {
    (now / 60).saturating_mul(60)
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
    db.execute("DELETE FROM challenges WHERE expires <= ?1", [at(now)?])
        .map_err(failed)?;
    db.execute(
        "INSERT INTO challenges (nonce, device, expires) VALUES (?1, ?2, ?3)",
        params![nonce, device.as_bytes(), at(expires)?],
    )
    .map_err(failed)?;
    Ok(())
}

/// SYN-04.4's one use: deletes the challenge of `nonce`, whatever comes
/// next, and gives its device and expiry if it existed. The deletion is
/// committed on its own, so a sign-in that then fails cannot use it again.
pub(crate) fn take_challenge(
    db: &Connection,
    nonce: &[u8; 32],
) -> Result<Option<(DeviceId, u64)>, Error> {
    let row = db
        .query_row(
            "DELETE FROM challenges WHERE nonce = ?1 RETURNING device, expires",
            [nonce],
            |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(failed)?;
    row.map(|(device, expires)| Ok((DeviceId::from_bytes(device), number(expires)?)))
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
        assert_eq!(int("user_version"), 1);
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
        assert_eq!(tables, 6);
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
            cas(&mut db, &x, &me, Precondition::Create, 10, &h(1)).unwrap(),
            (Cas::Done(1), vec![])
        );
        assert_eq!(
            cas(&mut db, &x, &me, Precondition::Create, 10, &h(9)).unwrap(),
            (Cas::Conflict, vec![])
        );
        for stale in [None, Some(0), Some(2), Some(u64::MAX)] {
            assert_eq!(
                cas(&mut db, &x, &me, Precondition::Update(stale), 10, &h(9)).unwrap(),
                (Cas::Conflict, vec![]),
                "{stale:?}"
            );
        }
        assert!(!named(&db, &h(9)).unwrap(), "a refused swap stored nothing");
        // Another account names the right version: no such vault for it.
        let them = account(&mut db, 2);
        assert_eq!(
            cas(&mut db, &x, &them, Precondition::Update(Some(1)), 10, &h(9)).unwrap(),
            (Cas::Conflict, vec![])
        );
        assert_eq!(
            cas(&mut db, &x, &them, Precondition::Create, 10, &h(9)).unwrap(),
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
                &h(9)
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
            )
            .unwrap();
            assert_eq!((done, pruned), (Cas::Done(u64::from(n)), vec![]));
        }
        // The 7th upload prunes version 1.
        let (done, pruned) =
            cas(&mut db, &x, &me, Precondition::Update(Some(6)), 10, &h(7)).unwrap();
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
                "PRAGMA journal_mode = WAL; CREATE TABLE t (a); PRAGMA user_version = 2;",
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
            err.contains("was made by a newer server (schema 2)"),
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
        assert!(!add_device(&mut db, &me, &d2, &[2; 65], "Mac", t0).unwrap());
        assert!(add_device(&mut db, &me, &d2, &[50; 65], "Mac 2", t0).unwrap());
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
}
