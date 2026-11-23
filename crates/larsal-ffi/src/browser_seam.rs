//! LD-556: Larsal.app's Connect-dialog seam for the extension's tests. It
//! exists only in debug builds (the `cfg` in lib.rs) and works only in a
//! launch started by a test (`LARSAL_TEST_INSTANCE_DIR`,
//! [`instance::started_by_test`]) that also sets `LARSAL_TEST_BROWSER_LINES=1`.
//! It speaks the test Larsal's lines
//! (`crates/larsal-browser/examples/test_larsal.rs`): standard output gets
//! `request <type> url=… top_url=… identity=…` before a bridge request runs,
//! `reply <type> ok` or `reply <type> error <n>` after, `question <id>
//! connect <words>` when the Connect dialog shows and `sessions <n>` when the
//! number of live sessions changes; standard input takes `allow <id> <name>`
//! and `deny <id>`, answered on the app's one dialog line as the window's
//! Connect and Deny buttons answer it, and (LD-611) `open <path> <password>`
//! (`opened <id>` once the demo vault is open and unlocked in the app's
//! session, else `open error`), `lock` (every vault, as the Lock command;
//! `locked`) and `unlock` (the vaults `open` opened, again; `unlocked`, else
//! `unlock error`). Demo data only; no secret is written: the words are the
//! dialog's pairing words, the identity a public key, and a demo password
//! goes into a secret type at once and is never told back.

use crate::instance;
use crate::session::{Session, UnlockResult};
use larsal_browser::{Answer, Bridge, Prompts, Question, Request, SharedHandler};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::secret::SecretString;
use larsal_model::json::{Map, Value};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The switch next to the test instance folder.
pub const LINES_VARIABLE: &str = "LARSAL_TEST_BROWSER_LINES";

/// True in a debug launch started by a test that asked for the seam.
#[must_use]
pub fn on() -> bool {
    instance::started_by_test() && std::env::var_os(LINES_VARIABLE).is_some_and(|v| v == "1")
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The vault side with each request told on standard output.
struct Logged(Arc<dyn SharedHandler>);

impl SharedHandler for Logged {
    fn handle(&self, r: &Request<'_>) -> Result<Map, u8> {
        let field = |k: &str| r.content.get(k).and_then(Value::as_str).unwrap_or("");
        let identity = r
            .identity
            .map(|k| base64::encode(Form::Padded, k))
            .unwrap_or_default();
        say(&format!(
            "request {} url={} top_url={} identity={identity}",
            r.kind,
            field("url"),
            field("top_url")
        ));
        let result = self.0.handle(r);
        match &result {
            Ok(_) => say(&format!("reply {} ok", r.kind)),
            Err(n) => say(&format!("reply {} error {n}", r.kind)),
        }
        result
    }
}

/// `vaults` with its requests told on standard output.
#[must_use]
pub fn logged(vaults: Arc<dyn SharedHandler>) -> Arc<dyn SharedHandler> {
    Arc::new(Logged(vaults))
}

/// The demo vaults `open` opened, each with its demo password, for `unlock`.
#[derive(Default)]
struct Opened(Mutex<Vec<(u64, SecretString)>>);

impl Opened {
    fn all(&self) -> std::sync::MutexGuard<'_, Vec<(u64, SecretString)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One input line answered on `line` and in `session`; the reply line to
/// write.
fn answer(line: &Prompts, session: &Session, opened: &Opened, input: &str) -> String {
    // A path may hold spaces; a demo password holds none.
    if let Some((path, password)) = input.strip_prefix("open ").and_then(|r| r.rsplit_once(' ')) {
        return open(session, opened, path, password);
    }
    let words: Vec<&str> = input.splitn(3, ' ').collect();
    let (id, given) = match words.as_slice() {
        ["allow", id, name] => (id.parse::<u64>(), Answer::Connect((*name).into())),
        ["deny", id] => (id.parse::<u64>(), Answer::Deny { remember: false }),
        ["lock"] => {
            session.lock_all();
            return "locked".into();
        }
        ["unlock"] => {
            let ids: Vec<u64> = opened
                .all()
                .iter()
                .map(|(id, password)| {
                    // An open vault answers Ignored and stays open.
                    let _ = session.unlock(*id, Some(password.expose().to_owned()), None);
                    *id
                })
                .collect();
            let vaults = session.vaults();
            let open = |id: &u64| vaults.iter().any(|v| v.id == *id && !v.locked);
            return if ids.iter().all(open) {
                "unlocked"
            } else {
                "unlock error"
            }
            .into();
        }
        _ => return format!("unknown {input}"),
    };
    match id {
        Ok(id) => format!("answered {id} {}", line.answer(id, given)),
        Err(_) => format!("unknown {input}"),
    }
}

/// `open <path> <password>` (LD-611): opens the demo vault at `path` in
/// `session` and unlocks it, as the unlock form does.
fn open(session: &Session, opened: &Opened, path: &str, password: &str) -> String {
    let password = SecretString::new(password.to_owned());
    let unlocked = session.open(path.to_owned()).ok().filter(|&id| {
        let given = Some(password.expose().to_owned());
        matches!(session.unlock(id, given, None), Ok(UnlockResult::Unlocked))
    });
    match unlocked {
        Some(id) => {
            opened.all().push((id, password));
            format!("opened {id}")
        }
        None => "open error".into(),
    }
}

/// Answers each line of `input` until it ends.
fn serve(
    line: &Prompts,
    session: &Session,
    opened: &Opened,
    input: impl BufRead,
    out: &dyn Fn(&str),
) {
    for text in input.lines().map_while(Result::ok) {
        out(&answer(line, session, opened, &text));
    }
}

/// The dialog shown now, when it is a Connect dialog other than `last`.
fn shown(line: &Prompts, last: Option<u64>) -> Option<(u64, String)> {
    match line.current() {
        Some((id, Question::Connect(c))) if last != Some(id) => {
            Some((id, format!("question {id} connect {}", c.words)))
        }
        _ => None,
    }
}

/// Starts the seam's two threads over the app's dialog line and bridge.
pub fn start(line: Arc<Prompts>, bridge: Arc<Mutex<Bridge>>) {
    let watched = Arc::clone(&line);
    std::thread::spawn(move || {
        let (mut last, mut sessions) = (None, 0);
        loop {
            if let Some((id, text)) = shown(&watched, last) {
                last = Some(id);
                say(&text);
            }
            let now = bridge.lock().map_or(sessions, |b| b.sessions());
            if now != sessions {
                sessions = now;
                say(&format!("sessions {now}"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    std::thread::spawn(move || {
        let (session, opened) = (Session::shared(), Opened::default());
        serve(&line, &session, &opened, std::io::stdin().lock(), &say);
    });
}

/// Told once the sockets follow the settings, as the test Larsal does.
pub fn ready() {
    say("ready");
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_browser::{Connect, Outcome};
    use std::time::Instant;

    fn connect(words: &str) -> Question {
        Question::Connect(Connect {
            vault: 1,
            text: "Connect demo-vault?".into(),
            name: "Chrome".into(),
            words: words.into(),
        })
    }

    /// LD-556: a shown Connect dialog is told once with its words; `allow`
    /// answers it with the name as the Connect button does, `deny` as Deny,
    /// and anything else is told back as unknown.
    #[test]
    fn ld556_the_seam_tells_the_connect_dialog_and_answers_it_from_lines() {
        let line = Arc::new(Prompts::new(Arc::new(Instant::now), Box::new(|| {})));
        assert_eq!(shown(&line, None), None);
        let asking = Arc::clone(&line);
        let ask = std::thread::spawn(move || {
            let never = || false;
            asking.ask(Duration::from_secs(30), &never, &never, &mut || {
                Some(connect("nutshell speech regretful pretense"))
            })
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let (id, text) = loop {
            if let Some(found) = shown(&line, None) {
                break found;
            }
            assert!(Instant::now() < deadline, "the dialog never showed");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            text,
            format!("question {id} connect nutshell speech regretful pretense")
        );
        assert_eq!(shown(&line, Some(id)), None, "told once");
        let said = Mutex::new(Vec::new());
        let (session, opened) = (Session::new(), Opened::default());
        let input = format!("hello\nallow x Chrome\nallow {id} Work Chrome\n");
        serve(&line, &session, &opened, input.as_bytes(), &|l| {
            said.lock().unwrap().push(l.to_owned())
        });
        assert_eq!(
            *said.lock().unwrap(),
            [
                "unknown hello".to_owned(),
                "unknown allow x Chrome".to_owned(),
                format!("answered {id} true"),
            ]
        );
        assert_eq!(
            ask.join().unwrap(),
            Outcome::Answered(Answer::Connect("Work Chrome".into()))
        );
        // A second dialog, denied.
        let asking = Arc::clone(&line);
        let ask = std::thread::spawn(move || {
            let never = || false;
            asking.ask(Duration::from_secs(30), &never, &never, &mut || {
                Some(connect("a b c d"))
            })
        });
        let (id, _) = loop {
            if let Some(found) = shown(&line, Some(id)) {
                break found;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            answer(&line, &session, &opened, &format!("deny {id}")),
            format!("answered {id} true")
        );
        assert_eq!(
            ask.join().unwrap(),
            Outcome::Answered(Answer::Deny { remember: false })
        );
    }

    /// LD-556: the seam is off in a launch that did not ask for it (the
    /// test program has no `LARSAL_TEST_BROWSER_LINES`).
    #[test]
    fn ld556_the_seam_is_off_without_its_switch() {
        assert!(std::env::var_os(LINES_VARIABLE).is_none());
        assert!(!on());
    }

    /// LD-610 (lead ruling 7): the seam's own switch does nothing in a
    /// launch not started by a test (no `LARSAL_TEST_INSTANCE_DIR`); with
    /// both, it is on.
    #[test]
    fn ld610_the_seam_needs_a_launch_started_by_a_test() {
        const NAME: &str = "browser_seam::tests::ld610_the_seam_needs_a_launch_started_by_a_test";
        const WANT: &str = "LARSAL_TEST_SEAM_WANT";
        if let Some(want) = std::env::var_os(WANT) {
            // The child of the run below: its environment is the case.
            assert_eq!(on(), want == "on");
            return;
        }
        // A test may not set a variable (no unsafe code), so each case runs
        // in a child of this test program.
        let dir = crate::test_dir::TempDir::new("e7s6-seam-gate");
        for (started_by_test, want) in [(false, "off"), (true, "on")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", NAME, "--test-threads=1"])
                .env(LINES_VARIABLE, "1")
                .env(WANT, want)
                .env_remove(instance::TEST_DIR_VARIABLE);
            if started_by_test {
                child.env(instance::TEST_DIR_VARIABLE, &*dir);
            }
            let out = child.output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{want}: {text}");
            assert!(
                text.contains("1 passed"),
                "{want}: the child ran no test: {text}"
            );
        }
    }

    /// LD-611 (lead ruling 6 (c)): `open <path> <password>` (the path may
    /// hold a space) opens and unlocks a demo vault in the session, `lock`
    /// locks every vault and `unlock` unlocks again those `open` opened; a
    /// vault that does not unlock is `open error`, and no reply holds the
    /// password.
    #[test]
    fn ld611_the_seam_opens_locks_and_unlocks_a_demo_vault() {
        let dir = crate::test_dir::TempDir::new("e7s6-seam-open");
        let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault");
        std::fs::create_dir(dir.join("with space")).unwrap();
        let good = dir.join("with space/demo-vault.larsalvault");
        let other = dir.join("other.larsalvault");
        for path in [&good, &other] {
            std::fs::copy(&demo, path).unwrap();
        }
        let session = Session::new();
        let line = Prompts::new(Arc::new(Instant::now), Box::new(|| {}));
        let opened = Opened::default();
        let say = |input: &str| answer(&line, &session, &opened, input);
        let locked = || {
            session
                .vaults()
                .iter()
                .map(|v| v.locked)
                .collect::<Vec<_>>()
        };
        let reply = say(&format!("open {} demo-pass-7", good.display()));
        assert!(reply.starts_with("opened "), "{reply}");
        assert_eq!(locked(), [false]);
        assert_eq!(say("lock"), "locked");
        assert_eq!(locked(), [true]);
        assert_eq!(say("unlock"), "unlocked");
        assert_eq!(locked(), [false]);
        let wrong = say(&format!("open {} not-the-demo-pass", other.display()));
        assert_eq!(wrong, "open error");
        assert_eq!(say("open"), "unknown open");
        assert_eq!(say("lock now"), "unknown lock now");
        assert_eq!(say("unlock"), "unlocked", "only the vaults open opened");
    }
}
