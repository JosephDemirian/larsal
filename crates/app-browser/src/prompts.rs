//! App's bridge dialogs (INT-02.15): at most one shows at a time, across
//! every session; the others wait in arrival order, at most
//! [`MAX_QUEUE`]. A dialog ends by its answer, by its time limit (then
//! Deny without remembering), or when its request is gone: its session
//! ended or its vault locked (SR-16). Nothing here holds a vault: the
//! caller makes each question when its turn comes, so a question asked
//! after an earlier answer sees what that answer remembered.
//!
//! The screen reads [`Prompts::current`] and answers with
//! [`Prompts::answer`]; tests answer the same way from a thread of their
//! own. Questions carry what the dialog shows only: titles and user names
//! as plain text (AT-E01), never a password.

use crate::server::Clock;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Requests that wait for a dialog, across all sessions; one more gets
/// error 42 (INT-02.15, INT-01.44).
pub const MAX_QUEUE: usize = 16;
/// The Connect dialog's time (INT-02.4, INT-01.45).
pub const CONNECT_TIME: Duration = Duration::from_secs(120);
/// The site access prompt's time (INT-02.15, INT-01.45).
pub const PROMPT_TIME: Duration = Duration::from_secs(60);
/// How often a waiting request looks at its session, its vault and the
/// clock.
const TICK: Duration = Duration::from_millis(25);

/// What one dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// The Connect dialog (INT-02.4, frame `dialogs-connect-a-browser`).
    Connect(Connect),
    /// The site access prompt (INT-02.18, frame
    /// `dialogs-browser-asks-for-an-entry`).
    Access(Access),
}

impl Question {
    /// The vault it belongs to.
    #[must_use]
    pub fn vault(&self) -> u64 {
        match self {
            Self::Connect(c) => c.vault,
            Self::Access(a) => a.vault,
        }
    }
}

/// INT-02.4: "Connect a new browser?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// The vault, as [`crate::Vaults`] names it.
    pub vault: u64,
    /// The text, naming the vault.
    pub text: String,
    /// The Name field's first value (INT-02.4).
    pub name: String,
    /// MI02-01 with the four pairing words (INT-02.5).
    pub words: String,
}

/// INT-02.18: "‹browser› asks for a sign-in on ‹P›".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// The vault of the rows.
    pub vault: u64,
    /// The title.
    pub title: String,
    /// "Choose the entries ‹browser› may use on this site."
    pub text: String,
    /// One row per entry in state ask: title and user name, resolved,
    /// plain text. Each starts checked.
    pub rows: Vec<Row>,
    /// "Remember for ‹P›", or `None` when the box is hidden (HTTP sign-in,
    /// INT-02.19).
    pub remember: Option<String>,
    /// MI02-05 or MI02-06 above the rows (INT-02.19).
    pub line: Option<String>,
}

/// One row of the site access prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The title, resolved.
    pub title: String,
    /// The user name, resolved.
    pub username: String,
}

/// The user's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Deny or Escape; `remember`: the site access prompt's Remember box
    /// (INT-02.18), false for every other dialog.
    Deny {
        /// The Remember box.
        remember: bool,
    },
    /// Connect with this name (INT-02.6).
    Connect(String),
    /// Allow Selected: each row checked or not, and Remember.
    Allow {
        /// One per row, in row order.
        checked: Vec<bool>,
        /// The Remember box.
        remember: bool,
    },
}

/// How a request's turn at the dialog ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user answered (Deny included).
    Answered(Answer),
    /// When its turn came, the question was no longer needed.
    NotNeeded,
    /// The time ran out, or its vault locked: Deny, nothing remembered.
    Ended,
    /// Its session ended: no reply is sent (INT-01.45).
    Gone,
    /// [`MAX_QUEUE`] already wait: error 42.
    Busy,
}

/// The dialog on screen.
struct Showing {
    id: u64,
    /// `None` while its question is being made.
    question: Option<Question>,
    until: Instant,
    answer: Option<Answer>,
}

#[derive(Default)]
struct Line {
    next: u64,
    waiting: VecDeque<u64>,
    shown: Option<Showing>,
}

/// The line of bridge dialogs (see the module docs).
pub struct Prompts {
    line: Mutex<Line>,
    turn: Condvar,
    clock: Clock,
    /// Called when the dialog on screen changes: App's window reads
    /// [`Prompts::current`] again and comes to the front (INT-02.15).
    changed: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Prompts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let line = self.line();
        f.debug_struct("Prompts")
            .field("waiting", &line.waiting.len())
            .field("shown", &line.shown.as_ref().map(|s| s.id))
            .finish()
    }
}

impl Prompts {
    /// An empty line; `changed` runs on each change of the dialog on screen.
    #[must_use]
    pub fn new(clock: Clock, changed: Box<dyn Fn() + Send + Sync>) -> Self {
        Self {
            line: Mutex::default(),
            turn: Condvar::new(),
            clock,
            changed,
        }
    }

    fn line(&self) -> MutexGuard<'_, Line> {
        self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The dialog on screen: its id for [`Prompts::answer`] and its
    /// question.
    #[must_use]
    pub fn current(&self) -> Option<(u64, Question)> {
        let line = self.line();
        let shown = line.shown.as_ref()?;
        Some((shown.id, shown.question.clone()?))
    }

    /// Answers dialog `id`; false when it is no longer on screen.
    pub fn answer(&self, id: u64, answer: Answer) -> bool {
        let mut line = self.line();
        let Some(shown) = line
            .shown
            .as_mut()
            .filter(|s| s.id == id && s.question.is_some() && s.answer.is_none())
        else {
            return false;
        };
        shown.answer = Some(answer);
        drop(line);
        self.turn.notify_all();
        true
    }

    /// Waits for this request's turn, shows the question `make` gives then
    /// (`None`: no longer needed), and waits for its answer, at most
    /// `limit` from when it shows. `gone` tells that the session ended;
    /// `locked` that the vault locked. The caller holds no vault while
    /// waiting: `make` runs with no lock of the line held.
    pub fn ask(
        &self,
        limit: Duration,
        gone: &dyn Fn() -> bool,
        locked: &dyn Fn() -> bool,
        make: &mut dyn FnMut() -> Option<Question>,
    ) -> Outcome {
        let mut line = self.line();
        if line.waiting.len() >= MAX_QUEUE {
            return Outcome::Busy;
        }
        let id = line.next;
        line.next = line.next.wrapping_add(1);
        line.waiting.push_back(id);
        loop {
            let now = (self.clock)();
            let mine = line.shown.as_ref().is_some_and(|s| s.id == id);
            let ended = if gone() {
                Some(Outcome::Gone)
            } else if locked() || (mine && line.shown.as_ref().is_some_and(|s| now >= s.until)) {
                Some(Outcome::Ended)
            } else {
                None
            };
            if let Some(outcome) = ended {
                line.waiting.retain(|w| *w != id);
                if mine {
                    line.shown = None;
                }
                drop(line);
                self.after(mine);
                return outcome;
            }
            if mine && let Some(answer) = line.shown.as_mut().and_then(|s| s.answer.take()) {
                line.shown = None;
                drop(line);
                self.after(true);
                return Outcome::Answered(answer);
            }
            if line.shown.is_none() && line.waiting.front() == Some(&id) {
                line.waiting.pop_front();
                line.shown = Some(Showing {
                    id,
                    question: None,
                    until: now,
                    answer: None,
                });
                drop(line);
                let question = make();
                line = self.line();
                let Some(question) = question else {
                    line.shown = None;
                    drop(line);
                    self.turn.notify_all();
                    return Outcome::NotNeeded;
                };
                if let Some(shown) = line.shown.as_mut() {
                    shown.question = Some(question);
                    shown.until = (self.clock)().checked_add(limit).unwrap_or(now);
                }
                drop(line);
                (self.changed)();
                line = self.line();
                continue;
            }
            line = self
                .turn
                .wait_timeout(line, TICK)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// A request left the line: the next may go, and the screen reads again
    /// when the dialog on it closed.
    fn after(&self, was_shown: bool) {
        self.turn.notify_all();
        if was_shown {
            (self.changed)();
        }
    }
}
