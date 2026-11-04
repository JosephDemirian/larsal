//! E9-S2 wiring (spec INT-06): the session and the SSH agents. When a vault
//! unlocks, its keys go to the agents off the caller's thread (INT-06.22);
//! a lock, close or lock-all runs INT-06.24 at once (AT-H01), its removals
//! from the system agents on a thread of their own (F-108); Larsal's own
//! agent runs while the feature is on (INT-06.32) and asks through the
//! window, one question at a time (INT-06.34).
//!
//! Guarantees: while the feature is off no agent is contacted and no socket
//! is opened (INT-06.21); the vault is held only to plan and to resolve one
//! passphrase at a time, never while a key is decrypted or sent; Swift gets
//! a question's words and an error's message only, never a key, a
//! passphrase or the data to sign (AGENTS rule 4).

use crate::session::{self, LarsalError, MAX_TEXT, Session};
use larsal_crypto::secret::SecretString;
use larsal_model::{Uuid, Vault};
use larsal_sshagent::messages::{Names, text};
use larsal_sshagent::{
    Asker, EntryKey, Keyring, Leaving, Options, OwnAgent, Question, Refused, Settings, Source,
    key_path, unlock_plan,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

/// A question of Larsal's agent (INT-06.34, frame `dialogs-ssh-key-use`): its
/// words only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshQuestion {
    /// For [`Session::answer_ssh_question`].
    pub id: u64,
    /// The title, MI06-29.
    pub heading: String,
    /// The text, MI06-30, MI06-31 or MI06-37.
    pub text: String,
}

/// A key that was not added when its vault unlocked: the "Details" of
/// MI06-18.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshFailure {
    /// The entry title.
    pub title: String,
    /// The card's message id, for example `MI06-14`.
    pub id: String,
    /// The message in the card's words.
    pub message: String,
}

/// Larsal's own agent for the settings row of INT-06.36 (MI06-32; the row
/// waits for the owner's frame, D-INT06-7).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshAgentInfo {
    /// The socket path.
    pub socket: String,
    /// `IdentityAgent "<socket>"` for `~/.ssh/config`.
    pub setup_line: String,
    /// Why it does not run; `None` is "Ready".
    pub error: Option<String>,
}

/// One unlocked vault as Larsal's records name it.
struct Open {
    vault: u64,
    session: larsal_sshagent::Session,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct State {
    /// S-SSH-01.
    on: bool,
    /// Tests: a throwaway socket and `known_hosts`; else the card's places.
    options: Option<Options>,
    agent: Option<OwnAgent>,
    agent_error: Option<String>,
    open: Vec<Open>,
    next: u64,
    failures: Vec<SshFailure>,
    /// The locks' system-agent removals still running (F-108).
    removing: Vec<JoinHandle<()>>,
}

/// The session's SSH agent part.
#[derive(Default)]
pub(crate) struct Ssh {
    keyring: Arc<Keyring>,
    ask: Arc<Ask>,
    state: Mutex<State>,
}

impl Ssh {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The open question and the window's answer to it.
#[derive(Default)]
struct Ask {
    now: Mutex<Option<(SshQuestion, Option<bool>)>>,
    answered: Condvar,
    /// The ids cancelled before their question showed, read and changed
    /// only under `now`'s lock: such a question is Deny at once and never
    /// shows; `ask` removes its id. Exact ids, not the highest: a request
    /// takes its id before its turn in the queue, so ids may be asked out
    /// of order (LD-213 (1)).
    // ponytail: a cancel that lands just after its question ended (an
    // answer in the same instant as the time limit) leaves its 8-byte id
    // here for good; prune ids below the oldest waiting ticket if it matters.
    cancelled: Mutex<HashSet<u64>>,
}

impl Ask {
    fn now(&self) -> MutexGuard<'_, Option<(SshQuestion, Option<bool>)>> {
        self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take it only while holding `now`'s lock.
    fn cancelled(&self) -> MutexGuard<'_, HashSet<u64>> {
        self.cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Asker for Ask {
    /// Shows the question in the window and waits for its answer; a cancel
    /// or a newer question ends the wait as Deny. Larsal comes to the front
    /// (INT-06.34); the window keeps Return and Space from Allow Once for
    /// the first second (R06-6).
    fn ask(&self, question: &Question) -> bool {
        let id = question.id;
        let mut now = self.now();
        if self.cancelled().remove(&id) {
            return false;
        }
        *now = Some((
            SshQuestion {
                id,
                heading: question.heading(),
                text: question.text(),
            },
            None,
        ));
        drop(now);
        session::changed();
        session::front();
        now = self.now();
        let yes = loop {
            match now.as_ref() {
                Some((q, Some(yes))) if q.id == id => break *yes,
                Some((q, None)) if q.id == id => {}
                _ => return false,
            }
            now = self
                .answered
                .wait(now)
                .unwrap_or_else(PoisonError::into_inner);
        };
        *now = None;
        drop(now);
        session::changed();
        yes
    }

    fn cancel(&self, id: u64) {
        let mut now = self.now();
        if now.as_ref().is_some_and(|(q, _)| q.id == id) {
            *now = None;
        } else {
            self.cancelled().insert(id);
        }
        drop(now);
        self.answered.notify_all();
        session::changed();
    }
}

/// The system-agent half of a lock (F-108), off the window's thread: each
/// vault's marked keys leave the agents they went to; MI06-19 for the keys
/// that could not be removed.
fn remove_marked(keyring: &Keyring, me: &Weak<Session>, leaving: Vec<Leaving>) {
    let refused: Vec<Refused> = leaving
        .into_iter()
        .flat_map(|l| keyring.remove_left(l))
        .collect();
    if let (Some(text), Some(session)) = (not_removed(&refused), me.upgrade()) {
        session.set_banner(text);
        session::changed();
    }
}

/// The vault file's folder: `{DB_DIR}` and relative key paths.
fn folder(path: &Path) -> &Path {
    path.parent().unwrap_or(path)
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// MI06-19 for each key Larsal could not take out of the system agent.
fn not_removed(refused: &[Refused]) -> Option<String> {
    let lines: Vec<String> = refused
        .iter()
        .map(|r| {
            larsal_sshagent::messages::fill(
                text("MI06-19").unwrap_or_default(),
                &[("‹title›", &r.title)],
            )
        })
        .collect();
    (!lines.is_empty()).then(|| lines.join(" "))
}

/// The key's name and file for a failure's message (INT-06.5): the
/// attachment name, or the expanded file path and its last part.
fn key_names(vault: &Vault, dir: &Path, entry: Uuid) -> (String, String) {
    let settings = vault
        .root
        .all_entries()
        .find(|e| e.uuid == entry)
        .and_then(|e| Settings::of(e).ok().flatten());
    match settings {
        None => Default::default(),
        Some(s) if s.source == Source::Attachment => (s.attachment_name.clone(), s.attachment_name),
        Some(s) => {
            let path = key_path(&s.file_name, &home(), dir, &|n| std::env::var_os(n));
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            (name, path.display().to_string())
        }
    }
}

/// INT-06.22 on a thread of its own: plans and adds the keys of vault
/// `vault`; MI06-18 when some were not added.
fn add_on_unlock(
    me: &Weak<Session>,
    vault: u64,
    who: &larsal_sshagent::Session,
    stop: &AtomicBool,
) {
    let Some(session) = me.upgrade() else { return };
    let Ok(plan) = session.with_open(vault, |v, path, _| Ok(unlock_plan(v, folder(path)))) else {
        return;
    };
    let passphrase = |entry: Uuid| -> Option<SecretString> {
        session
            .with_open(vault, |v, path, _| {
                let e = v.root.all_entries().find(|e| e.uuid == entry);
                Ok(e.map(|e| EntryKey::passphrase(v, e, folder(path))))
            })
            .ok()
            .flatten()
    };
    let refused = session.ssh.keyring.add_planned(who, plan, passphrase, stop);
    if refused.is_empty() || stop.load(Ordering::SeqCst) {
        return;
    }
    let failures: Vec<SshFailure> = refused
        .iter()
        .map(|r| {
            let (name, file) = session
                .with_open(vault, |v, path, _| Ok(key_names(v, folder(path), r.entry)))
                .unwrap_or_default();
            SshFailure {
                title: r.title.clone(),
                id: r.error.id().to_owned(),
                message: r.error.message(&Names {
                    title: &r.title,
                    name: &name,
                    file: &file,
                }),
            }
        })
        .collect();
    let titles: Vec<&str> = failures.iter().map(|f| f.title.as_str()).collect();
    let banner = larsal_sshagent::messages::fill(
        text("MI06-18").unwrap_or_default(),
        &[("‹titles›", &titles.join(", "))],
    );
    // The card's row names the "Details" button after the sentence.
    let banner = banner
        .split(" Button")
        .next()
        .unwrap_or_default()
        .to_owned();
    session.ssh.state().failures.extend(failures);
    session.set_banner(banner);
    session::changed();
}

impl Session {
    /// The "vault unlocked" step (APP-06.22 step 10): while the feature is
    /// on, the vault's keys start to go to the agents off this thread.
    /// Called with the session's state lock held, so a later lock always
    /// finds this vault.
    pub(crate) fn ssh_unlocked(&self, vault: u64, name: String) {
        let mut s = self.ssh.state();
        if !s.on {
            return;
        }
        s.next = s.next.wrapping_add(1);
        let who = larsal_sshagent::Session { id: s.next, name };
        let stop = Arc::new(AtomicBool::new(false));
        let (me, run_who, run_stop) = (self.me.clone(), who.clone(), Arc::clone(&stop));
        let worker = std::thread::Builder::new()
            .name("ssh-unlock".into())
            .spawn(move || add_on_unlock(&me, vault, &run_who, &run_stop))
            .ok();
        s.open.push(Open {
            vault,
            session: who,
            stop,
            worker,
        });
    }

    /// Step 10 of the lock (APP-02.15, INT-06.24): the adds of `vault` stop
    /// after the current key, Larsal's own agent drops its keys and the
    /// records go at once; the marked keys leave the system agents on a
    /// thread of their own (F-108: an agent may take 2 s to answer, and the
    /// window locks on the main thread), then MI06-19 shows for keys that
    /// could not be removed. [`Session::ssh_settled`] and quit's
    /// [`Session::stop_ssh_agent`] wait for that thread. Call it without
    /// the state lock.
    pub(crate) fn ssh_locked(&self, vault: Option<u64>) {
        let gone: Vec<Open> = {
            let mut s = self.ssh.state();
            let (gone, keep) = std::mem::take(&mut s.open)
                .into_iter()
                .partition(|o| vault.is_none_or(|v| o.vault == v));
            s.open = keep;
            gone
        };
        if gone.is_empty() {
            return;
        }
        let leaving: Vec<Leaving> = gone
            .iter()
            .map(|open| {
                open.stop.store(true, Ordering::SeqCst);
                self.ssh.keyring.leave(open.session.id)
            })
            .collect();
        let (keyring, me) = (Arc::clone(&self.ssh.keyring), self.me.clone());
        let (give, take) = mpsc::channel::<Vec<Leaving>>();
        let worker = std::thread::Builder::new()
            .name("ssh-lock".into())
            .spawn(move || {
                if let Ok(leaving) = take.recv() {
                    remove_marked(&keyring, &me, leaving);
                }
            });
        let leaving = match worker {
            Ok(worker) => {
                let mut s = self.ssh.state();
                s.removing.retain(|w| !w.is_finished());
                s.removing.push(worker);
                drop(s);
                match give.send(leaving) {
                    Ok(()) => return,
                    Err(mpsc::SendError(leaving)) => leaving,
                }
            }
            Err(_) => leaving,
        };
        // No thread: here, as before.
        remove_marked(&self.ssh.keyring, &self.me, leaving);
    }

    /// Tests: the agent socket, `known_hosts` and question time Larsal's own
    /// agent uses from the next turn-on (a throwaway place, never the
    /// user's files).
    #[doc(hidden)]
    pub fn set_ssh_options(&self, socket: PathBuf, known_hosts: PathBuf, question_time: Duration) {
        self.ssh.state().options = Some(Options {
            socket,
            known_hosts,
            question_time,
        });
    }

    /// Tests: waits until the adds of every unlocked vault and the
    /// removals of every lock have ended.
    #[doc(hidden)]
    pub fn ssh_settled(&self) {
        let workers: Vec<JoinHandle<()>> = {
            let mut s = self.ssh.state();
            let removing = std::mem::take(&mut s.removing);
            s.open
                .iter_mut()
                .filter_map(|o| o.worker.take())
                .chain(removing)
                .collect()
        };
        for w in workers {
            let _ = w.join();
        }
    }
}

#[uniffi::export]
impl Session {
    /// S-SSH-01 to S-SSH-03 (APP-01, INT-06.38; E5-S9 stores them): the
    /// feature switch, the socket override and the security key provider
    /// (empty: `SSH_SK_PROVIDER` from Larsal's environment, else `internal`).
    /// Turning it on starts Larsal's own agent (INT-06.32); turning it off
    /// removes every key Larsal added, with or without remove-on-lock, stops
    /// the adds in progress and Larsal's agent (INT-06.26, LD-63). Off by
    /// default: until then no agent is contacted (INT-06.21).
    ///
    /// # Errors
    /// `TooLong` for a text over the limit.
    pub fn set_ssh_agent(
        &self,
        enabled: bool,
        socket_override: String,
        sk_provider: String,
    ) -> Result<(), LarsalError> {
        if socket_override.len() > MAX_TEXT || sk_provider.len() > MAX_TEXT {
            return Err(LarsalError::TooLong);
        }
        let provider = Some(sk_provider.trim().to_owned())
            .filter(|p| !p.is_empty())
            .or_else(|| {
                std::env::var("SSH_SK_PROVIDER")
                    .ok()
                    .filter(|p| !p.is_empty())
            });
        self.ssh
            .keyring
            .set_agent_settings(&socket_override, provider.as_deref());
        let mut s = self.ssh.state();
        let was = std::mem::replace(&mut s.on, enabled);
        if enabled && s.agent.is_none() {
            let options = s
                .options
                .clone()
                .unwrap_or_else(|| Options::for_home(&home()));
            let ask: Arc<dyn Asker> = self.ssh.ask.clone();
            match OwnAgent::start(options, Arc::clone(&self.ssh.keyring), ask) {
                Ok(agent) => {
                    s.agent = Some(agent);
                    s.agent_error = None;
                }
                Err(e) => s.agent_error = Some(e.to_string()),
            }
        }
        if enabled || !was {
            return Ok(());
        }
        for open in std::mem::take(&mut s.open) {
            open.stop.store(true, Ordering::SeqCst);
        }
        let agent = s.agent.take();
        drop(s);
        if let Some(agent) = agent {
            agent.stop();
        }
        if let Some(text) = not_removed(&self.ssh.keyring.turn_off()) {
            self.set_banner(text);
        }
        Ok(())
    }

    /// At quit, after [`Session::lock_all`] (INT-06.25, INT-06.32): the
    /// locks' removals from the system agent end first (F-108); Larsal's own
    /// agent stops and its socket goes; keys without remove-on-lock stay in
    /// the system agent.
    pub fn stop_ssh_agent(&self) {
        let removing = std::mem::take(&mut self.ssh.state().removing);
        for w in removing {
            let _ = w.join();
        }
        let agent = self.ssh.state().agent.take();
        if let Some(agent) = agent {
            agent.stop();
        }
    }

    /// The question Larsal's agent asks now (INT-06.34), if any.
    #[must_use]
    pub fn ssh_question(&self) -> Option<SshQuestion> {
        self.ssh
            .ask
            .now()
            .as_ref()
            .filter(|(_, answer)| answer.is_none())
            .map(|(q, _)| q.clone())
    }

    /// The window's answer to question `id`: `true` is Allow Once. A
    /// question that ended meanwhile ignores it.
    pub fn answer_ssh_question(&self, id: u64, allow: bool) {
        let mut now = self.ssh.ask.now();
        if let Some((q, answer)) = now.as_mut()
            && q.id == id
        {
            *answer = Some(allow);
        }
        drop(now);
        self.ssh.ask.answered.notify_all();
    }

    /// The keys that were not added when their vaults unlocked, once
    /// (MI06-18's "Details").
    pub fn take_ssh_failures(&self) -> Vec<SshFailure> {
        std::mem::take(&mut self.ssh.state().failures)
    }

    /// Larsal's own agent while the feature is on (INT-06.36).
    #[must_use]
    pub fn ssh_agent_info(&self) -> Option<SshAgentInfo> {
        let s = self.ssh.state();
        if !s.on {
            return None;
        }
        let socket = s.agent.as_ref().map_or_else(
            || {
                s.options
                    .clone()
                    .unwrap_or_else(|| Options::for_home(&home()))
                    .socket
            },
            |a| a.socket().to_path_buf(),
        );
        Some(SshAgentInfo {
            socket: socket.display().to_string(),
            setup_line: larsal_sshagent::setup_line(&socket),
            error: s.agent_error.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn question(id: u64) -> Question {
        Question {
            id,
            title: "Demo key".into(),
            comment: String::new(),
            fingerprint: String::new(),
            program: None,
            host: None,
            forwarded: false,
        }
    }

    /// `ask` on its own thread; its answer arrives on the receiver.
    fn ask_later(ask: &Arc<Ask>, id: u64) -> mpsc::Receiver<bool> {
        let (tx, rx) = mpsc::channel();
        let ask = Arc::clone(ask);
        std::thread::spawn(move || {
            let _ = tx.send(ask.ask(&question(id)));
        });
        rx
    }

    /// SR-16, INT-06.34: a lock's cancel can land before the question's
    /// thread asks (a busy Mac starts it late). That question is Deny at
    /// once and never shows; a newer one still does.
    #[test]
    fn int06_34_a_cancel_before_its_question_shows_is_deny_at_once() {
        let session = Session::new();
        let ask = Arc::clone(&session.ssh.ask);
        ask.cancel(7);
        let answer = ask_later(&ask, 7).recv_timeout(Duration::from_secs(2));
        let shown = session.ssh_question();
        ask.cancel(7); // ends the wait of a build without the fix
        assert_eq!(answer, Ok(false), "Deny at once");
        assert_eq!(shown, None, "a dead question on the window");
        let answer = ask_later(&ask, 8);
        let t0 = std::time::Instant::now();
        while session.ssh_question().is_none() {
            assert!(t0.elapsed() < Duration::from_secs(10), "no question");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(session.ssh_question().map(|q| q.id), Some(8));
        session.answer_ssh_question(8, true);
        assert_eq!(answer.recv_timeout(Duration::from_secs(10)), Ok(true));
        assert_eq!(session.ssh_question(), None);
    }

    /// LD-213 (1), INT-06.33, INT-06.34: a request takes its id before its
    /// turn in the queue, so two requests that arrive together can be asked
    /// out of id order. Question 8 shows first and ends without an answer
    /// (its time ran out, or its vault locked); question 7 still shows and
    /// can be allowed.
    #[test]
    fn ld213_a_lower_id_asked_after_a_cancelled_higher_one_still_shows() {
        let session = Session::new();
        let ask = Arc::clone(&session.ssh.ask);
        let eight = ask_later(&ask, 8);
        let t0 = std::time::Instant::now();
        while session.ssh_question().is_none() {
            assert!(t0.elapsed() < Duration::from_secs(10), "no question");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(session.ssh_question().map(|q| q.id), Some(8));
        ask.cancel(8);
        assert_eq!(eight.recv_timeout(Duration::from_secs(10)), Ok(false));
        let seven = ask_later(&ask, 7);
        let t0 = std::time::Instant::now();
        while session.ssh_question().is_none() && t0.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let showed = session.ssh_question().map(|q| q.id);
        session.answer_ssh_question(7, true);
        assert_eq!(showed, Some(7), "question 7 was denied unseen");
        assert_eq!(seven.recv_timeout(Duration::from_secs(10)), Ok(true));
        assert_eq!(session.ssh_question(), None);
    }

    /// F-074, MOD-13.8: the forced prompt's end adds the vault's SSH record
    /// with the session's state lock held, as an unlock does, so a lock
    /// from another thread always finds the record: no other thread sees
    /// the vault open before it.
    #[test]
    fn f_074_the_forced_prompt_ends_with_the_ssh_record_under_the_state_lock() {
        let dir =
            std::env::temp_dir().join(format!("larsal-ffi-ssh-forced-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Work.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-work-key-change.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let session = Session::new();
        let v = session.open(path.to_string_lossy().into_owned()).unwrap();
        session.unlock(v, Some("demo-pass-8".into()), None).unwrap();
        let settings = crate::vault_settings::VaultSettings::new(Arc::clone(&session), v);
        let new = "orchid-meteor-pine-quartz-41";
        settings.set_password(new.into()).unwrap();
        settings.set_repeat(new.into()).unwrap();
        assert_eq!(
            settings.change_password(vec![]).unwrap(),
            crate::wizard::Outcome::Done
        );
        // The SSH records held: the prompt's end waits at the record.
        let records = session.ssh.state();
        let s = Arc::clone(&session);
        let end = std::thread::spawn(move || s.end_key_change(v));
        std::thread::sleep(Duration::from_millis(300));
        let (tx, seen) = std::sync::mpsc::channel();
        let s = Arc::clone(&session);
        let probe = std::thread::spawn(move || {
            let _ = tx.send(s.with_slots(|slots, _| slots[0].1.is_some()));
        });
        assert_ne!(
            seen.recv_timeout(Duration::from_millis(500)),
            Ok(true),
            "the state lock went before the SSH record"
        );
        drop(records);
        assert_eq!(end.join().unwrap(), Ok(true));
        probe.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
