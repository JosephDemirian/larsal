//! Larsal's records of the keys it added, and the keys Larsal's own agent holds
//! (INT-06.22 to INT-06.31, INT-06.35, R06-1, R06-3, R06-5; AT-H01).

use crate::entry::{EntryKey, Step, unlock_plan};
use crate::{Agent, Error};
use larsal_crypto::secret::SecretString;
use larsal_crypto::ssh::{AgentKey, can_sign};
use larsal_model::{Uuid, Vault};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

/// Which agent holds a key Larsal added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The system agent (INT-06.15).
    System,
    /// Larsal's own agent: the key asks before each use (INT-06.31).
    Own,
}

/// One unlocked vault, as Larsal's records name it (INT-06.23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Unique for the life of Larsal; never reused.
    pub id: u64,
    /// The vault's name, for MI06-05.
    pub name: String,
}

/// A key Larsal could not add or remove, for MI06-18 and MI06-19.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The entry.
    pub entry: Uuid,
    /// Its title.
    pub title: String,
    /// Why.
    pub error: Error,
}

struct Record {
    blob: Vec<u8>,
    session: u64,
    vault: String,
    entry: Uuid,
    title: String,
    remove_on_lock: bool,
    place: Place,
    /// The system agent the key went to, kept so that a lock, a turn-off or
    /// a remove reaches that agent after S-SSH-02 changed (F-106). `None`
    /// for Larsal's own agent.
    agent: Option<Agent>,
}

/// The keys of one locking vault that still leave the system agents:
/// [`Keyring::leave`] takes them out, [`Keyring::remove_left`] removes them.
pub struct Leaving {
    session: u64,
    records: Vec<Record>,
}

/// A key in Larsal's own agent. The key wipes itself when the last `Arc`
/// drops: at once, or when a signature in progress ends.
pub(crate) struct Held {
    pub(crate) blob: Vec<u8>,
    pub(crate) key: Arc<AgentKey>,
    pub(crate) comment: String,
    pub(crate) title: String,
    pub(crate) fingerprint: String,
    session: u64,
    expires: Option<Instant>,
}

/// An own key as Larsal's agent sees it while it asks: no strong reference.
pub(crate) struct OwnKey {
    pub(crate) key: Weak<AgentKey>,
    pub(crate) title: String,
    pub(crate) comment: String,
    pub(crate) fingerprint: String,
}

/// How an open question ended.
pub(crate) enum Answer {
    /// The user chose: `true` is Allow Once.
    User(bool),
    /// The key left Larsal's agent (lock, remove, lifetime, turn off).
    Cancelled,
}

struct Pending {
    id: u64,
    blob: Vec<u8>,
    tx: Sender<Answer>,
}

#[derive(Default)]
struct State {
    records: Vec<Record>,
    own: Vec<Held>,
    socket_override: String,
    sk_provider: Option<String>,
    pending: Option<Pending>,
}

impl State {
    /// Drops every own key `gone` selects, wiped, with its record; an open
    /// question about one of them ends as Deny (SR-16).
    fn drop_own(&mut self, gone: impl Fn(&Held) -> bool) {
        let (out, keep): (Vec<Held>, Vec<Held>) = self.own.drain(..).partition(|h| gone(h));
        self.own = keep;
        for h in &out {
            self.records
                .retain(|r| !(r.place == Place::Own && r.blob == h.blob));
            if self.pending.as_ref().is_some_and(|p| p.blob == h.blob)
                && let Some(p) = self.pending.take()
            {
                let _ = p.tx.send(Answer::Cancelled);
            }
        }
    }

    /// Larsal's agent holds this very key (not only one with the same blob).
    fn holds(&self, blob: &[u8], key: &Weak<AgentKey>) -> bool {
        self.own
            .iter()
            .any(|h| h.blob == blob && std::ptr::eq(Arc::as_ptr(&h.key), key.as_ptr()))
    }

    fn record(&self, blob: &[u8]) -> Option<&Record> {
        self.records.iter().find(|r| r.blob == blob)
    }

    fn put(&mut self, record: Record) {
        self.records.retain(|r| r.blob != record.blob);
        self.records.push(record);
    }

    /// The system agent Larsal's records put this key in, if any (F-106).
    fn agent_of(&self, blob: &[u8]) -> Option<Agent> {
        self.record(blob).and_then(|r| r.agent.clone())
    }
}

/// Larsal's records and Larsal's own agent's keys, shared by the vault sessions
/// and [`crate::OwnAgent`]. Memory only.
///
/// Guarantees: a key lives in one agent only (R06-5); a key that asks is
/// never sent to the system agent; [`Keyring::lock`] drops every own key
/// of that vault, wiped, before it talks to the system agent; one
/// operation at a time; no secret in any error.
#[derive(Default)]
pub struct Keyring {
    ops: Mutex<()>,
    state: Mutex<State>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.state();
        write!(
            f,
            "Keyring({} records, {} own)",
            s.records.len(),
            s.own.len()
        )
    }
}

impl Keyring {
    /// An empty keyring.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ops(&self) -> MutexGuard<'_, ()> {
        self.ops.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// S-SSH-02 (the socket override) and the security key provider of
    /// INT-06.38 (`None`: [`crate::SK_PROVIDER_DEFAULT`]).
    pub fn set_agent_settings(&self, socket_override: &str, sk_provider: Option<&str>) {
        let mut s = self.state();
        socket_override.clone_into(&mut s.socket_override);
        s.sk_provider = sk_provider.map(str::to_owned);
    }

    /// The system agent now (INT-06.11 with S-SSH-02).
    pub fn system_agent(&self) -> Result<Agent, Error> {
        let path = self.state().socket_override.clone();
        Agent::locate(&path)
    }

    /// Adds an unlocked key (INT-06.22, INT-06.27). Before anything is sent:
    /// a lifetime out of range is [`Error::Lifetime`]; a key that asks but
    /// is not Ed25519 or P-256 is [`Error::CannotAsk`]; a key Larsal's records
    /// hold for another session is [`Error::OtherVault`]. Then:
    /// - a key that asks goes to Larsal's own agent; when Larsal's records put it
    ///   in the system agent, it is removed there first (R06-5);
    /// - a key that does not ask goes to the system agent, unless an asking
    ///   entry of this vault already put it in Larsal's agent: the asking entry
    ///   wins and nothing changes (R06-5, LD-175).
    ///
    /// The record takes the key's remove-on-lock flag (always on for a key
    /// that asks). `unlocked` is wiped when this returns, except the copy
    /// Larsal's own agent keeps. Returns where the key is now.
    pub fn load(
        &self,
        session: &Session,
        key: &EntryKey,
        unlocked: AgentKey,
    ) -> Result<Place, Error> {
        let _ops = self.ops();
        self.load_held(session, key, unlocked)
    }

    fn load_held(
        &self,
        session: &Session,
        key: &EntryKey,
        unlocked: AgentKey,
    ) -> Result<Place, Error> {
        self.purge();
        let blob = key.key().public_blob().to_vec();
        let place = key.place();
        let provider = self.state().sk_provider.clone();
        let limits = key.limits(provider.as_deref())?;
        if place == Place::Own && !can_sign(key.key().algorithm()) {
            return Err(Error::CannotAsk);
        }
        let (was, old) = match self.state().record(&blob) {
            Some(r) if r.session != session.id => return Err(Error::OtherVault(r.vault.clone())),
            Some(r) => (Some(r.place), r.agent.clone()),
            None => (None, None),
        };
        let comment = key.comment(&unlocked);
        let record = |place, agent| Record {
            blob: blob.clone(),
            session: session.id,
            vault: session.name.clone(),
            entry: key.entry(),
            title: key.title().to_owned(),
            remove_on_lock: key.remove_on_lock(),
            place,
            agent,
        };
        match (place, was) {
            (Place::System, Some(Place::Own)) => Ok(Place::Own),
            (Place::System, _) => {
                let agent = self.system_agent()?;
                // F-106: added before S-SSH-02 changed, the key leaves the
                // agent it is in first; one agent holds it (R06-5).
                if let Some(old) = old.filter(|a| *a != agent) {
                    old.remove(&blob)?;
                }
                agent.add(&unlocked, &comment, &limits)?;
                self.state().put(record(Place::System, Some(agent)));
                Ok(Place::System)
            }
            (Place::Own, _) => {
                if let Some(old) = old {
                    old.remove(&blob)?;
                }
                let expires = limits
                    .lifetime
                    .and_then(|s| Instant::now().checked_add(Duration::from_secs(s.into())));
                let title = key.question_name(&unlocked);
                let mut s = self.state();
                s.drop_own(|h| h.blob == blob);
                s.own.push(Held {
                    blob: blob.clone(),
                    key: Arc::new(unlocked),
                    comment,
                    title,
                    fingerprint: key.key().fingerprint().to_owned(),
                    session: session.id,
                    expires,
                });
                s.put(record(Place::Own, None));
                Ok(Place::Own)
            }
        }
    }

    /// INT-06.22: reads, unlocks and adds, one after another in
    /// [`unlock_plan`]'s order, every key `vault` adds when it unlocks;
    /// passwords resolve as Copy resolves them ([`EntryKey::unlock`]).
    /// Stops after the current key once `stop` is set: set it before calling
    /// [`Keyring::lock`] for this session, so no key is added after the
    /// lock. Returns every entry that failed, for MI06-18.
    pub fn add_on_unlock(
        &self,
        session: &Session,
        vault: &Vault,
        vault_dir: &Path,
        stop: &AtomicBool,
    ) -> Vec<Refused> {
        let plan = unlock_plan(vault, vault_dir);
        self.add_planned(
            session,
            plan,
            |id| {
                let entry = vault.root.all_entries().find(|e| e.uuid == id)?;
                Some(EntryKey::passphrase(vault, entry, vault_dir))
            },
            stop,
        )
    }

    /// [`Keyring::add_on_unlock`] for a caller that holds the vault behind
    /// its own lock: `plan` is [`unlock_plan`]'s, and `passphrase` gives an
    /// entry's resolved password ([`EntryKey::passphrase`]) or `None` when
    /// the entry or its vault is gone (the step is skipped). The vault is
    /// needed only inside `passphrase`; decryption and the agent run
    /// without it. Same order, stop rule and result.
    pub fn add_planned(
        &self,
        session: &Session,
        plan: Vec<Step>,
        mut passphrase: impl FnMut(Uuid) -> Option<SecretString>,
        stop: &AtomicBool,
    ) -> Vec<Refused> {
        let mut refused = Vec::new();
        for step in plan {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let result = match step.key.map(|key| (passphrase(step.entry), key)) {
                Err(e) => Err(e),
                Ok((None, _)) => continue,
                Ok((Some(pass), key)) => match key.key().unlock(&pass) {
                    Err(e) => Err(e),
                    Ok(unlocked) => {
                        let _ops = self.ops();
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        self.load_held(session, &key, unlocked)
                    }
                },
            };
            if let Err(error) = result {
                refused.push(Refused {
                    entry: step.entry,
                    title: step.title,
                    error,
                });
            }
        }
        refused
    }

    /// "Remove from SSH Agent" (INT-06.17, INT-06.27): from Larsal's own agent
    /// when it holds the key, else from the system agent Larsal's records put
    /// it in (F-106), else from the system agent now; the record goes.
    /// `true` when a key was removed; the system agent not holding it is
    /// `false`, not an error.
    pub fn unload(&self, blob: &[u8]) -> Result<bool, Error> {
        let _ops = self.ops();
        let recorded = {
            let mut s = self.state();
            let recorded = s.agent_of(blob);
            s.records.retain(|r| r.blob != blob);
            if s.own.iter().any(|h| h.blob == blob) {
                s.drop_own(|h| h.blob == blob);
                return Ok(true);
            }
            recorded
        };
        recorded
            .map_or_else(|| self.system_agent(), Ok)?
            .remove(blob)
    }

    /// The editor's "Remove the key when the vault locks" changed while the
    /// key is recorded (INT-06.27): the record changes at once. A key in
    /// Larsal's own agent always leaves at lock (R06-1).
    pub fn set_remove_on_lock(&self, blob: &[u8], on: bool) {
        let mut s = self.state();
        if let Some(r) = s
            .records
            .iter_mut()
            .find(|r| r.blob == blob && r.place == Place::System)
        {
            r.remove_on_lock = on;
        }
    }

    /// The vault of `session` locks (INT-06.24, INT-06.31, AT-H01): first
    /// every key Larsal's own agent holds for it is dropped and wiped (an open
    /// question about one ends as Deny) and every record of the session
    /// goes, then each of its system-agent keys with remove-on-lock is
    /// removed from the agent it went to. Never fails; the keys Larsal could not remove come back for
    /// MI06-19 (a key the agent no longer holds is not one of them).
    /// [`Keyring::leave`] then [`Keyring::remove_left`] on this thread.
    pub fn lock(&self, session: u64) -> Vec<Refused> {
        let leaving = self.leave(session);
        self.remove_left(leaving)
    }

    /// The part of [`Keyring::lock`] that never waits (F-108): every key
    /// Larsal's own agent holds for `session` is dropped and wiped (an open
    /// question about one ends as Deny) and the session's records go, also
    /// while another operation waits on the system agent. Hand the result
    /// to [`Keyring::remove_left`], on any thread.
    #[must_use]
    pub fn leave(&self, session: u64) -> Leaving {
        let mut s = self.state();
        s.drop_own(|h| h.session == session);
        let (records, keep) = s.records.drain(..).partition(|r| r.session == session);
        s.records = keep;
        Leaving { session, records }
    }

    /// The rest of [`Keyring::lock`]: waits for the operation in progress
    /// (a key it adds for the session then leaves too), and removes each
    /// key with remove-on-lock from the system agent it went to (F-106),
    /// except one a later unlock added again meanwhile. The keys Larsal could
    /// not remove, for MI06-19.
    pub fn remove_left(&self, leaving: Leaving) -> Vec<Refused> {
        let _ops = self.ops();
        let late = self.leave(leaving.session).records;
        let records: Vec<Record> = {
            let s = self.state();
            leaving
                .records
                .into_iter()
                .chain(late)
                .filter(|r| r.remove_on_lock && s.record(&r.blob).is_none())
                .collect()
        };
        Self::remove_from_system(records.into_iter())
    }

    /// "Remove All Keys from SSH Agent…" (INT-06.28): message 19 to the
    /// system agent, every key leaves Larsal's own agent, all records go, also
    /// when the system agent fails (its error is returned).
    pub fn remove_all(&self) -> Result<(), Error> {
        let _ops = self.ops();
        {
            let mut s = self.state();
            s.drop_own(|_| true);
            s.records.clear();
        }
        self.system_agent()?.remove_all()
    }

    /// The feature is turned off (INT-06.26): every key Larsal added leaves
    /// the system agent, with or without remove-on-lock, every key leaves
    /// Larsal's own agent, all records go. Other programs' keys stay (LD-63).
    pub fn turn_off(&self) -> Vec<Refused> {
        let _ops = self.ops();
        let records = {
            let mut s = self.state();
            s.drop_own(|_| true);
            std::mem::take(&mut s.records)
        };
        Self::remove_from_system(records.into_iter())
    }

    /// Removes each record's key from the system agent it went to (F-106).
    /// An agent that failed once is not asked again in this run (F-108): a
    /// silent one costs one [`crate::TIMEOUT`], not one per key, and
    /// each of its keys comes back with that error.
    fn remove_from_system(records: impl Iterator<Item = Record>) -> Vec<Refused> {
        let mut refused = Vec::new();
        let mut failed: Vec<(Agent, Error)> = Vec::new();
        for r in records {
            let Some(agent) = r.agent else { continue };
            let error = match failed.iter().find(|(a, _)| *a == agent) {
                Some((_, e)) => e.clone(),
                None => match agent.remove(&r.blob) {
                    Ok(_) => continue,
                    Err(e) => {
                        failed.push((agent, e.clone()));
                        e
                    }
                },
            };
            refused.push(Refused {
                entry: r.entry,
                title: r.title,
                error,
            });
        }
        refused
    }

    /// The Loaded state (INT-06.30): Larsal's own agent holds the key, or the
    /// system agent lists it.
    pub fn is_loaded(&self, blob: &[u8]) -> Result<bool, Error> {
        self.purge();
        if self.state().own.iter().any(|h| h.blob == blob) {
            return Ok(true);
        }
        Ok(self.system_agent()?.list()?.iter().any(|i| i.blob == blob))
    }

    /// Where Larsal's records put this key, if anywhere.
    #[must_use]
    pub fn place_of(&self, blob: &[u8]) -> Option<Place> {
        self.state().record(blob).map(|r| r.place)
    }

    // ---------------------------------------------------- Larsal's own agent

    /// INT-06.35: drops the own keys whose lifetime ended.
    pub(crate) fn purge(&self) {
        let now = Instant::now();
        self.state()
            .drop_own(|h| h.expires.is_some_and(|t| t <= now));
    }

    /// The public blobs and comments Larsal's own agent holds.
    pub(crate) fn own_list(&self) -> Vec<(Vec<u8>, String)> {
        self.purge();
        self.state()
            .own
            .iter()
            .map(|h| (h.blob.clone(), h.comment.clone()))
            .collect()
    }

    /// The own key with this blob, as a weak handle only (INT-06.31: a
    /// lock, remove or lifetime end frees it at once), with its title,
    /// comment and fingerprint.
    pub(crate) fn own_key(&self, blob: &[u8]) -> Option<OwnKey> {
        self.purge();
        self.state()
            .own
            .iter()
            .find(|h| h.blob == blob)
            .map(|h| OwnKey {
                key: Arc::downgrade(&h.key),
                title: h.title.clone(),
                comment: h.comment.clone(),
                fingerprint: h.fingerprint.clone(),
            })
    }

    /// The key itself, for the signature right after Allow Once; `None` once
    /// that very key left Larsal's agent.
    pub(crate) fn take_for_signing(
        &self,
        blob: &[u8],
        key: &Weak<AgentKey>,
    ) -> Option<Arc<AgentKey>> {
        self.purge();
        let s = self.state();
        s.holds(blob, key).then(|| key.upgrade()).flatten()
    }

    /// R06-3: remove-one on Larsal's socket for a key Larsal's agent holds.
    pub(crate) fn remove_own(&self, blob: &[u8]) -> bool {
        let mut s = self.state();
        let held = s.own.iter().any(|h| h.blob == blob);
        s.drop_own(|h| h.blob == blob);
        held
    }

    /// R06-3: remove-all on Larsal's socket empties Larsal's agent.
    pub(crate) fn remove_all_own(&self) {
        self.state().drop_own(|_| true);
    }

    /// Registers the one open question, under the same lock that checks
    /// Larsal's agent still holds `key`, so a lock always finds and ends it.
    /// `false` (nothing registered) once the key is gone.
    pub(crate) fn open_question(
        &self,
        id: u64,
        blob: &[u8],
        key: &Weak<AgentKey>,
        tx: Sender<Answer>,
    ) -> bool {
        self.purge();
        let mut s = self.state();
        if !s.holds(blob, key) {
            return false;
        }
        s.pending = Some(Pending {
            id,
            blob: blob.to_vec(),
            tx,
        });
        true
    }

    /// The question ended.
    pub(crate) fn close_question(&self, id: u64) {
        let mut s = self.state();
        if s.pending.as_ref().is_some_and(|p| p.id == id) {
            s.pending = None;
        }
    }

    /// Ends the open question, if any, as Cancelled (Larsal's agent stops).
    pub(crate) fn cancel_question(&self) {
        if let Some(p) = self.state().pending.take() {
            let _ = p.tx.send(Answer::Cancelled);
        }
    }
}
