//! E8-S3: typing through the session (INT-05.39, INT-05.41, LD-186 (3)) on
//! a copy of the Option A Personal demo vault (password in
//! testdata/README.md). The session never posts here: these tests do not
//! call `autotype_post_events`, so a recorder takes every event (AGENTS.md
//! rule 10).

use larsal_ffi::autotype::{
    AutoTypeAction, AutoTypeChosen, AutoTypeEnd, AutoTypeFocus, AutoTypeStart,
};
use larsal_ffi::autotype_typing::AutoTypeKey;
use larsal_ffi::edit::EditText;
use larsal_ffi::session::Session;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Personal unlocked in a test session, with the entry "Zeta portal"
/// (password `demo-zeta`, sequence `sequence`).
fn zeta(name: &str, sequence: &str) -> (Arc<Session>, u64) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("autotype-typing");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.larsalvault"));
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/option-a-personal.larsalvault"
    );
    std::fs::copy(source, &path).unwrap();
    let s = Session::new();
    let v = s.open(path.to_string_lossy().into_owned()).unwrap();
    s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "Zeta portal".into())
        .unwrap();
    s.set_password(v, "demo-zeta".into()).unwrap();
    s.set_auto_type(v, true, sequence.into()).unwrap();
    s.commit_edit(v).unwrap();
    (s, v)
}

/// The plan for the window "Zeta portal" (one row, picker on).
fn choose(s: &Session) -> AutoTypeChosen {
    let AutoTypeStart::Picker { list } = s.autotype_start("Zeta portal".into(), 0) else {
        panic!("always ask is on: a picker")
    };
    assert_eq!(list.rows.len(), 1);
    s.autotype_choose(0, AutoTypeAction::Login, 0)
}

/// The captured window stays in front; at check `at` it runs `then`.
struct Focus {
    checks: Mutex<u32>,
    at: u32,
    then: Box<dyn Fn() + Send + Sync>,
}

impl AutoTypeFocus for Focus {
    fn same_window(&self) -> bool {
        let mut n = self.checks.lock().unwrap();
        *n += 1;
        if *n == self.at {
            (self.then)();
        }
        true
    }
}

fn focus(at: u32, then: impl Fn() + Send + Sync + 'static) -> Arc<Focus> {
    Arc::new(Focus {
        checks: Mutex::new(0),
        at,
        then: Box::new(then),
    })
}

#[test]
fn int_05_39_t92_a_lock_or_the_shortcut_again_stops_typing() {
    // Checks: INT-05.38 step 1, then one per key. A lock during the third
    // key's check: that key does not go out either (the flag is read again
    // after the window check).
    let (s, v) = zeta("t92-lock", "{PASSWORD}");
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let locker = Arc::clone(&s);
    let end = s.autotype_type(plan, focus(1 + 3, move || locker.lock(v).unwrap()));
    assert_eq!(
        end,
        AutoTypeEnd::Stopped {
            keys: 2,
            reason: "stopped".into()
        }
    );
    // The shortcut pressed again (`autotype_stop`) during the second key's
    // check: one key.
    let (s, _) = zeta("t92-stop", "{PASSWORD}");
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let stopper = Arc::clone(&s);
    let end = s.autotype_type(plan, focus(1 + 2, move || stopper.autotype_stop()));
    assert_eq!(
        end,
        AutoTypeEnd::Stopped {
            keys: 1,
            reason: "stopped".into()
        }
    );
    // A stop before a run does not reach the next run.
    s.autotype_stop();
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let end = s.autotype_type(plan, focus(0, || {}));
    assert_eq!(end, AutoTypeEnd::Finished { keys: 9 });
}

#[test]
fn int_05_41_int_05_45_ld_186_3_the_layout_table_from_swift_makes_combinations() {
    // Without a layout, ⌘A of `{CLEARFIELD}` has no key: MI05-23.
    let (s, _) = zeta("layout", "{CLEARFIELD}{PASSWORD}");
    let AutoTypeChosen::Failed { reason, code } = choose(&s) else {
        panic!("no layout: MI05-23")
    };
    assert_eq!(reason, "a can't be typed with ⌘ on this keyboard layout.");
    assert_eq!(code, "MI05-23");
    // With the AZERTY keys Swift reads: ⌘ on 0x0C, Delete, 9 characters.
    let key = |c: &str, code| AutoTypeKey {
        character: c.into(),
        code,
        shift: false,
        option: false,
    };
    s.autotype_layout(vec![key("a", 0x0C), key("q", 0x00)]);
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let end = s.autotype_type(plan, focus(0, || {}));
    assert_eq!(end, AutoTypeEnd::Finished { keys: 2 + 9 });
}

/// No app or window in front of the captured one; at check `at` it runs
/// `then`.
struct NotInFront {
    checks: Mutex<u32>,
    at: u32,
    then: Box<dyn Fn() + Send + Sync>,
}

impl AutoTypeFocus for NotInFront {
    fn same_window(&self) -> bool {
        let mut n = self.checks.lock().unwrap();
        *n += 1;
        if *n == self.at {
            (self.then)();
        }
        false
    }
}

/// LD-234 (1): a stop raised while step 1 waits for the target ends the run
/// as `stopped`, not `not-in-front`; with no stop the line says
/// `not-in-front` after step 1's 41 looks.
#[test]
fn ld_234_a_stop_during_step_1_logs_stopped() {
    let (s, _) = zeta("step1-stop", "{PASSWORD}");
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let stopper = Arc::clone(&s);
    let never = Arc::new(NotInFront {
        checks: Mutex::new(0),
        at: 3,
        then: Box::new(move || stopper.autotype_stop()),
    });
    let end = s.autotype_type(plan, Arc::clone(&never) as Arc<dyn AutoTypeFocus>);
    let stopped = |reason: &str| AutoTypeEnd::Stopped {
        keys: 0,
        reason: reason.into(),
    };
    assert_eq!(end, stopped("stopped"));
    assert!(
        *never.checks.lock().unwrap() <= 3,
        "no window check after the stop"
    );
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    let never = Arc::new(NotInFront {
        checks: Mutex::new(0),
        at: 0,
        then: Box::new(|| {}),
    });
    let end = s.autotype_type(plan, Arc::clone(&never) as Arc<dyn AutoTypeFocus>);
    assert_eq!(end, stopped("not-in-front"));
    assert_eq!(*never.checks.lock().unwrap(), 41, "every 50 ms for 2 s");
}

/// LD-234 (1), INT-05.46: the shortcut pressed after Swift marked the run
/// typing but before the typing thread began (the plan is made, the run
/// not started) still stops that run: nothing is typed.
#[test]
fn ld_234_a_press_before_the_typing_thread_starts_stops_the_run() {
    let (s, _) = zeta("early-stop", "{PASSWORD}");
    let AutoTypeChosen::Type { plan } = choose(&s) else {
        panic!("a plan")
    };
    s.autotype_stop();
    let end = s.autotype_type(plan, focus(0, || {}));
    assert_eq!(
        end,
        AutoTypeEnd::Stopped {
            keys: 0,
            reason: "stopped".into()
        }
    );
}
