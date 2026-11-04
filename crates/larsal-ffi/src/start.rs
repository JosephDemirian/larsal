//! Start-up of the Mac app (APP-09.1). The Swift entry calls [`start`] before
//! it makes anything of AppKit: steps 1 to 9 run here, so no window is shown,
//! no password is read and no vault is read before step 9 has passed. Rust
//! prints every message and keeps every secret (F06 passwords go straight into
//! `SecretString`); Swift only exits, shows the M09-06 alert, or opens the
//! window and then calls [`launch_finished`].

use crate::instance::{self, Request, Sent};
use crate::session::{self, OpenRequest};
use crate::{SettingsFiles, cli};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// What the Mac app does after [`start`].
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Launch {
    /// Quit at once with `code`; Larsal's text is already on stdout or stderr.
    Exit {
        /// The process exit code.
        code: i32,
    },
    /// M09-06 (APP-09.8): `message` is already on stderr; show it in a modal
    /// error alert when `alert` is true (not in a debug build started by a
    /// test, where nobody can close it), then quit with exit code 1.
    Refuse {
        /// The M09-06 text.
        message: String,
        /// Whether to show the alert.
        alert: bool,
    },
    /// This process is the primary: open the main window (step 10).
    Run,
}

/// The window side of Larsal, implemented in Swift. Called from the instance
/// channel's thread.
#[uniffi::export(with_foreign)]
pub trait LarsalEvents: Send + Sync {
    /// APP-09.22: un-minimize, show, raise, and make Larsal the active
    /// application with the main window as key window.
    fn bring_to_front(&self);

    /// The session changed outside a Swift call (a channel `open`, an
    /// unlock with passed-in credentials): read it again.
    fn session_changed(&self);

    /// APP-09.12 `lock`, an automatic trigger (APP-02.16, LD-217 (4)):
    /// return at once, then lock every vault as the lock signals do, on
    /// the main queue: the step 8 save by the settings, a recovery copy of
    /// what could not be saved, then the lock (APP-02.15).
    fn lock_all(&self);

    /// LD-277 (4), APP-05.24: run `work` (an F06 passed-in unlock's read of
    /// the vault file at `path`) off the main thread, inside a coordinated
    /// read, once the file is on this Mac.
    fn on_file(&self, path: String, work: Arc<session::FileWork>);
}

/// The primary's state from step 7 until the process ends.
struct Primary {
    /// The instance lock (APP-09.8): held while the process lives.
    _lock: File,
    /// F08 (APP-09.21).
    minimized: bool,
    /// F07 (APP-10.5).
    allow_screen_capture: bool,
    /// The file arguments with F05 and F06, opened at step 12.
    files: Mutex<Option<OpenRequest>>,
    /// Set by [`launch_finished`]; channel requests wait for it.
    events: OnceLock<Arc<dyn LarsalEvents>>,
}

static PRIMARY: OnceLock<Primary> = OnceLock::new();

/// APP-09.1 steps 1 to 9, for the process arguments. Prints help, version,
/// debug info and the M09 messages itself. As a secondary it sends its one
/// request and returns [`Launch::Exit`]. As the primary it holds the instance
/// lock, reads the F06 password lines (kept in Rust) and returns
/// [`Launch::Run`]; the channel answers once [`launch_finished`] was called.
/// Call it once, before any window.
#[uniffi::export]
#[must_use]
pub fn start() -> Launch {
    // (1) Process hardening.
    harden();
    // (2) Flags.
    let flags = match cli::parse(std::env::args_os().skip(1)) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("{}", error.message());
            return exit(1);
        }
    };
    // (3) Help and version; version wins.
    if flags.version {
        println!("{}", cli::version());
        return exit(0);
    }
    if flags.help {
        print!("{}", cli::HELP);
        return exit(0);
    }
    // (4) Debug info.
    if flags.debug_info {
        print!("{}", cli::debug_info());
        return exit(0);
    }
    // (5) Settings files; the primary reads them after step 7, so a
    // secondary never touches them (APP-09.10).
    let settings = SettingsFiles {
        config: flags.config.clone(),
        local_config: flags.local_config.clone(),
    };
    // (6) File arguments.
    let files = cli::existing_files(&flags.files);
    // LD-344: validate the stored attachment selection before any start-up writes.
    let session = session::Session::shared();
    if session.open_copies.validate().is_err() {
        return refuse("Larsal cannot start: the attachment folder is not private.".to_owned());
    }
    // (7) Single instance.
    let paths = match instance::dir() {
        Ok(dir) => instance::Paths::in_dir(&dir),
        Err(error) => {
            return refuse(format!(
                "Larsal cannot start: the per-user temp folder could not be found ({error})."
            ));
        }
    };
    let lock = match instance::take_lock(&paths) {
        Ok(Some(lock)) => lock,
        Ok(None) => return secondary(&paths, flags.lock, files),
        Err(refused) => return refuse(refused.message()),
    };
    // (8) A lock request with no instance running.
    if flags.lock {
        eprintln!("{}", instance::NOT_RUNNING);
        return exit(0);
    }
    // The settings are read once, by the primary (APP-01, D-01-1).
    crate::larsal_settings::load_at_start(&settings);
    let listener = match instance::listen(&paths) {
        Ok(listener) => listener,
        Err(refused) => return refuse(refused.message()),
    };
    // (9) Crypto self-test: M11-02 on stderr and in the alert, exit code 1.
    if let Err(message) = crypto_self_test() {
        return refuse(message);
    }
    // F06 lines are read here, after the self-test and before the window, so
    // the window never waits on standard input; step 12 hands them on.
    let passwords = if flags.password_stdin && !files.is_empty() {
        cli::read_passwords(files.len())
    } else {
        Vec::new()
    };
    let primary = Primary {
        _lock: lock,
        minimized: flags.minimized,
        allow_screen_capture: flags.allow_screen_capture,
        files: Mutex::new((!files.is_empty()).then(|| OpenRequest {
            paths: files,
            key_file: flags.key_file,
            passwords,
        })),
        events: OnceLock::new(),
    };
    if PRIMARY.set(primary).is_err() {
        eprintln!("Larsal cannot start: start-up ran twice.");
        return exit(1);
    }
    // A request waits until the window exists; the secondary's one second
    // covers the start-up.
    let own = larsal_platform::macos::effective_uid();
    let served = instance::serve(listener, own, |request| match PRIMARY.get() {
        Some(primary) => answer(primary.events.wait().as_ref(), request),
        None => false,
    });
    if served.is_err() {
        eprintln!("Larsal cannot start: a start-up thread could not be created.");
        return exit(1);
    }
    // MOD-05.12 rule 4: attachment copies a crash left behind; only the
    // primary instance gets here.
    crate::edit::clean_open_copies(&session.open_copies);
    Launch::Run
}

/// APP-09.1 steps 11 to 13, once the main window exists: reopen previous
/// vaults (E5-S9), open the file arguments with F05 and F06 (APP-09.15 to
/// APP-09.17, through the session), start minimized (E5-S9). From here the
/// instance channel answers, with `events` for the window. Later calls do
/// nothing.
#[uniffi::export]
pub fn launch_finished(events: Arc<dyn LarsalEvents>) {
    let Some(primary) = PRIMARY.get() else { return };
    session::set_events(events.clone());
    // (11) Reopen previous vaults (APP-09.20, APP-01.17): locked, in the
    // saved order, then the one shown last.
    let session = session::Session::shared();
    let reopen = session.settings.reopen();
    if !reopen.is_empty() {
        session::open(OpenRequest {
            paths: reopen,
            key_file: None,
            passwords: Vec::new(),
        });
    }
    // S-SSH-01 stored on: Larsal's agent starts (INT-06.21).
    crate::larsal_settings::start_ssh(&session);
    // (12) The file arguments.
    let files = primary
        .files
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(request) = files {
        session::open(request);
    }
    // (13) Start minimized or come to the front: the window asks
    // [`starts_minimized`] (APP-09.21).
    let _ = primary.events.set(events);
}

/// APP-09.21: after step 12 the window starts minimized when F08 was given
/// or S-START-03 is on; else it comes to the front.
#[uniffi::export]
#[must_use]
pub fn starts_minimized() -> bool {
    let flag = PRIMARY.get().is_some_and(|p| p.minimized);
    minimize_at_start(flag, &session::Session::shared().settings)
}

/// APP-10.5: F07 was given to this launch, which is the primary: the window
/// starts with screen capture allowed (APP-10.4). False before [`start`] and
/// in a secondary, which never applies F07 (APP-09.10); no setting, settings
/// file or environment variable can make it true (APP-10.1).
#[uniffi::export]
#[must_use]
pub fn allows_screen_capture() -> bool {
    capture_at_start(PRIMARY.get())
}

fn capture_at_start(primary: Option<&Primary>) -> bool {
    primary.is_some_and(|p| p.allow_screen_capture)
}

fn minimize_at_start(flag: bool, settings: &crate::larsal_settings::LarsalSettingsStore) -> bool {
    flag || settings.flag("window.start_minimized".to_owned())
}

/// (1) Process hardening, APP-11.1 to APP-11.5: in a release build, core
/// dumps off and debugger attach denied; a failed step writes M11-01 and the
/// start goes on.
fn harden() {
    larsal_platform::hardening::harden();
    // The window app starts in Swift, where SIGPIPE is not ignored: a write
    // to a closed socket must be an error, not the end of Larsal (LD-179).
    if larsal_platform::macos::ignore_broken_pipes().is_err() {
        eprintln!(
            "Larsal could not turn off the broken-pipe signal; a closed connection may end Larsal."
        );
    }
}

/// (9) Crypto self-test, APP-11.10: `Err` holds M11-02 for the first wrong
/// answer.
fn crypto_self_test() -> Result<(), String> {
    larsal_crypto::selftest::run().map_err(m11_02)
}

/// M11-02, naming the failed check.
fn m11_02(check: larsal_crypto::selftest::Check) -> String {
    format!(
        "Larsal cannot start: a self-check of its encryption code failed. {} gave a wrong answer.",
        check.name()
    )
}

/// Stdout is flushed first: the Swift side ends the process with `exit`.
fn exit(code: i32) -> Launch {
    let _ = std::io::stdout().flush();
    Launch::Exit { code }
}

/// M09-06 on stderr; the alert is the Swift side's.
fn refuse(message: String) -> Launch {
    eprintln!("{message}");
    Launch::Refuse {
        alert: !instance::started_by_test(),
        message,
    }
}

/// APP-09.10: one request to the running instance, then the message and exit code.
fn secondary(paths: &instance::Paths, lock: bool, files: Vec<PathBuf>) -> Launch {
    let request = if lock {
        Request::Lock
    } else if files.is_empty() {
        Request::Activate
    } else {
        Request::Open(files)
    };
    let (text, code) = match (lock, instance::send(&paths.socket, &request)) {
        (_, Sent::NoAnswer) => (instance::NO_ANSWER, 1),
        (true, Sent::Answered(true)) => (instance::LOCKED, 0),
        (true, _) => (instance::NOT_LOCKED, 1),
        (false, _) => (instance::PASSED_ON, 0),
    };
    eprintln!("{text}");
    exit(code)
}

/// APP-09.12: what the primary does with a channel request; the answer is
/// `{"ok":true}` when it returns true.
fn answer(events: &dyn LarsalEvents, request: Request) -> bool {
    match request {
        Request::Activate => {
            events.bring_to_front();
            true
        }
        Request::Open(paths) => {
            events.bring_to_front();
            session::open(OpenRequest {
                paths,
                key_file: None,
                passwords: Vec::new(),
            });
            true
        }
        // D-APP09-2: a lock request does not raise the window.
        Request::Lock => lock(Some(events)),
    }
}

/// APP-09.12 `lock`: answered at once, the sender does not wait (LD-217
/// (4)); the window saves, keeps a recovery copy and locks. With no window
/// events (a run without the window), Rust locks every vault here.
fn lock(events: Option<&dyn LarsalEvents>) -> bool {
    let Some(events) = events else {
        return session::lock_all();
    };
    events.lock_all();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts the raises and the lock requests handed to the window.
    #[derive(Default)]
    struct Window(AtomicUsize, AtomicUsize);

    impl LarsalEvents for Window {
        fn bring_to_front(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn session_changed(&self) {}

        fn lock_all(&self) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }

        fn on_file(&self, _: String, work: Arc<session::FileWork>) {
            work.run();
        }
    }

    #[test]
    fn app09_12_activate_and_open_raise_the_window_lock_does_not() {
        let window = Window::default();
        assert!(answer(&window, Request::Activate));
        assert_eq!(window.0.load(Ordering::SeqCst), 1);
        assert!(answer(
            &window,
            Request::Open(vec!["/demo/a.larsalvault".into()])
        ));
        assert_eq!(window.0.load(Ordering::SeqCst), 2);
        // D-APP09-2: the lock locks every vault and always succeeds.
        assert!(answer(&window, Request::Lock));
        assert_eq!(window.0.load(Ordering::SeqCst), 2);
    }

    /// APP-09.12, APP-02.16 (LD-217 (4)): a lock request is answered at
    /// once and hands the lock to the window, which saves or keeps a
    /// recovery copy first; Rust's lock-all locks nothing then. With no
    /// window events, Rust locks every vault itself.
    #[test]
    fn app09_12_a_lock_request_goes_to_the_window_else_rust_locks() {
        let dir =
            std::env::temp_dir().join(format!("larsal-ffi-start-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Personal.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let shared = session::Session::shared();
        let v = shared.open(path.display().to_string()).unwrap();
        shared.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let locked = || shared.vaults().iter().find(|i| i.id == v).unwrap().locked;
        let window = Window::default();
        assert!(answer(&window, Request::Lock));
        assert_eq!(window.1.load(Ordering::SeqCst), 1, "the window locks");
        assert!(!locked(), "not Rust: the window saves first");
        assert!(lock(None));
        assert!(locked(), "no window: Rust locks");
        shared.close(v).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn app09_21_start_minimized_by_flag_or_setting() {
        let settings = crate::larsal_settings::LarsalSettingsStore::default();
        assert!(!minimize_at_start(false, &settings));
        assert!(minimize_at_start(true, &settings));
        let on = crate::larsal_settings::LarsalSetting {
            key: "window.start_minimized".into(),
            value: crate::larsal_settings::LarsalSettingValue::Flag { on: true },
        };
        let session = session::Session::new();
        session.save_settings(vec![on]).unwrap();
        assert!(minimize_at_start(false, &session.settings));
    }

    #[test]
    fn app10_1_protected_unless_the_primary_had_f07() {
        // No primary in a test process: every window starts protected.
        assert!(PRIMARY.get().is_none());
        assert!(!allows_screen_capture());
        assert!(!capture_at_start(None));
        // APP-10.5: the primary's F07, and only that, allows capture.
        let primary = |f07| Primary {
            _lock: File::open(env!("CARGO_MANIFEST_DIR")).unwrap(),
            minimized: false,
            allow_screen_capture: f07,
            files: Mutex::new(None),
            events: OnceLock::new(),
        };
        assert!(capture_at_start(Some(&primary(true))));
        assert!(!capture_at_start(Some(&primary(false))));
    }

    #[test]
    fn app11_10_self_test_passes_and_m11_02_names_the_check() {
        assert_eq!(crypto_self_test(), Ok(()));
        assert_eq!(
            m11_02(larsal_crypto::selftest::Check::Sha256),
            "Larsal cannot start: a self-check of its encryption code failed. \
             SHA-256 gave a wrong answer."
        );
    }
}
