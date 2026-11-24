//! The key list while a screen shows it (F-126; APP-06.8, APP-07.15,
//! MOD-12.10, INT-07.14): larsal-hwkey's `KeyWatcher` looks once at start,
//! 0.5 s after a key is plugged in, and on "Look for keys again", and hands
//! each look to the screen. Only list items cross (not secret).

use crate::hwkey::{KeyLook, look};
use std::sync::{Arc, Mutex, PoisonError};

/// The screen side of a key watch, implemented in Swift: told each look,
/// on the watcher's own thread.
#[uniffi::export(with_foreign)]
pub trait KeyLooks: Send + Sync {
    /// One look's list and M06-36's note (MI07-01 when macOS refused).
    fn found(&self, look: KeyLook);
}

/// A running key watch (INT-07.14). Swift holds one while the unlock
/// screen, or the wizard's or the credentials page's key list, shows.
#[derive(uniffi::Object)]
pub struct KeyWatch(Mutex<Option<larsal_hwkey::KeyWatcher>>);

impl KeyWatch {
    /// The watch over `bus`; `None` inside when its thread cannot start.
    fn on<B>(bus: B, screen: Arc<dyn KeyLooks>) -> Arc<Self>
    where
        B: larsal_hwkey::Bus + Send + 'static,
    {
        let watcher = larsal_hwkey::KeyWatcher::start(bus, move |found| screen.found(look(found)));
        Arc::new(Self(Mutex::new(watcher.ok())))
    }
}

#[uniffi::export]
impl KeyWatch {
    /// Starts watching: a look now, then one 0.5 s after each plug-in;
    /// each look goes to `screen`. Never asks for a touch.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(screen: Arc<dyn KeyLooks>) -> Arc<Self> {
        #[cfg(not(test))]
        let bus = larsal_hwkey::usb::UsbBus::new();
        // Unit tests never reach USB (OD-01).
        #[cfg(test)]
        let bus = tests::Quiet::default();
        Self::on(bus, screen)
    }

    /// "Look for keys again" (APP-06.8): a look now, or one more after the
    /// running one.
    pub fn look_again(&self) {
        if let Some(watcher) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            watcher.look_again();
        }
    }

    /// Stops the watch without waiting: a running look ends on its own
    /// thread.
    pub fn stop(&self) {
        let watcher = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(watcher) = watcher {
            let _ = std::thread::Builder::new()
                .name("larsal-hwkey-stop".to_owned())
                .spawn(move || drop(watcher));
        }
    }
}

impl Drop for KeyWatch {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hwkey::tests::{PICK, hardware_vault};
    use crate::session::{Session, UnlockResult};
    use crate::vault_settings::VaultSettings;
    use crate::wizard::{Answer, Outcome, Wizard};
    use larsal_hwkey::{Bus, Change, Device, DeviceInfo, Interface, Reason};
    use std::sync::mpsc;
    use std::time::Duration;

    type Sink = Box<dyn Fn(Change) + Send>;

    /// A bus with no device; `watch` keeps its sink for the test.
    #[derive(Default, Clone)]
    pub(crate) struct Quiet(Arc<Mutex<Option<Sink>>>);

    pub(crate) struct NoDevice;

    impl Device for NoDevice {
        fn read(&mut self, _: &mut [u8; 8]) -> Result<(), Reason> {
            Err(Reason::Missing)
        }
        fn write(&mut self, _: &[u8; 8]) -> Result<(), Reason> {
            Err(Reason::Missing)
        }
    }

    impl Bus for Quiet {
        type Device = NoDevice;
        type Watch = ();
        fn list(&self) -> Result<Vec<DeviceInfo>, Reason> {
            Ok(Vec::new())
        }
        fn open(&self, _: &DeviceInfo, _: Interface) -> Result<NoDevice, Reason> {
            Err(Reason::Missing)
        }
        fn now(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _: Duration) {}
        fn watch(&self, sink: Sink) -> Result<(), Reason> {
            *self.0.lock().unwrap() = Some(sink);
            Ok(())
        }
    }

    struct Screen(Mutex<mpsc::Sender<KeyLook>>);

    impl KeyLooks for Screen {
        fn found(&self, look: KeyLook) {
            let _ = self.0.lock().unwrap().send(look);
        }
    }

    /// F-126 (APP-06.8 T18): the watch hands the screen a look at start,
    /// another after a plug-in, and one on "Look for keys again".
    #[test]
    fn f_126_key_watch_looks_at_start_after_a_plug_in_and_on_request() {
        let bus = Quiet::default();
        let (tx, rx) = mpsc::channel();
        let watch = KeyWatch::on(bus.clone(), Arc::new(Screen(Mutex::new(tx))));
        let wait = Duration::from_secs(5);
        let first = rx.recv_timeout(wait).expect("a look at start");
        assert!(first.items.is_empty());
        assert!(first.note.starts_with("Larsal sees no security key"));
        // The plug-in: the sink is in place once the first look came.
        (bus.0.lock().unwrap().as_ref().expect("watching"))(Change::Arrived);
        rx.recv_timeout(wait).expect("a look after the plug-in");
        watch.look_again();
        rx.recv_timeout(wait).expect("a look on request");
        watch.stop();
        watch.look_again();
        assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    }

    /// F-126 (APP-07.15 to APP-07.17, INT-07.2): the wizard's security key
    /// part makes a vault that opens only with the password and that key;
    /// a key that is not plugged in is refused with M06-17 before anything
    /// is written (check 6).
    #[test]
    fn f_126_wizard_creates_a_vault_with_the_security_key() {
        let path = crate::test_dir::TempDir::new("f126-wizard").file("Keyed.larsalvault");
        let s = Session::new();
        let wizard = Wizard::new(Arc::clone(&s));
        let mut choice = wizard.defaults();
        choice.kdf = crate::wizard::KdfChoice::AesKdf;
        choice.unlock_ms = 100;
        assert!(wizard.measure(choice).unwrap());
        let yes = || vec![Answer::WeakAesKdf, Answer::SafeMinimum, Answer::SlowArgon2];
        wizard
            .set_password("orchid-meteor-pine-quartz-41".into())
            .unwrap();
        wizard
            .set_repeat("orchid-meteor-pine-quartz-41".into())
            .unwrap();
        let create = |path: &str, answers: Vec<Answer>| {
            wizard
                .create(
                    "Keyed".into(),
                    String::new(),
                    path.into(),
                    choice,
                    false,
                    answers,
                )
                .unwrap()
        };
        // Not plugged in: M06-17, nothing written.
        wizard.set_security_key(Some(crate::hwkey::KeyPick { serial: 7, ..PICK }));
        let target = path.to_string_lossy().into_owned();
        let missing = create(&target, yes());
        assert!(
            matches!(&missing, Outcome::Refused { id, .. } if id == "M06-17"),
            "{missing:?}"
        );
        assert!(!path.exists());
        // "Remove", then the plugged-in key.
        wizard.set_security_key(None);
        wizard.set_security_key(Some(PICK));
        let made = create(&target, yes());
        assert!(matches!(made, Outcome::Created { .. }), "{made:?}");
        let open = || {
            let s = Session::new();
            let v = s.open(target.clone()).unwrap();
            (s, v)
        };
        let (s2, v) = open();
        let failed = s2
            .unlock(v, Some("orchid-meteor-pine-quartz-41".into()), None)
            .unwrap();
        assert!(matches!(failed, UnlockResult::Failed { .. }), "{failed:?}");
        let got = s2
            .unlock_with_key(
                v,
                Some("orchid-meteor-pine-quartz-41".into()),
                None,
                Some(PICK),
                s2.lock_epoch(v).unwrap(),
            )
            .unwrap();
        assert_eq!(got, UnlockResult::Unlocked);
        // The new vault keeps the key for its saves (APP-07.18).
        let id = s.vaults()[0].id;
        assert_eq!(
            VaultSettings::new(Arc::clone(&s), id)
                .view()
                .unwrap()
                .security_key,
            Some(PICK)
        );
    }

    /// LD-243 (3), MOD-12.10 step 6: a pick of slot 1 on the plugged-in
    /// key, which has only slot 2 set up, is refused with M06-17 and
    /// changes nothing (the slot check in `hwkey::plugged`).
    #[test]
    fn ld_243_3_slot_1_on_a_key_with_only_slot_2_is_refused() {
        let path = hardware_vault("slot-1");
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        let got = s
            .unlock_with_key(
                v,
                Some("demo-pass".into()),
                None,
                Some(PICK),
                s.lock_epoch(v).unwrap(),
            )
            .unwrap();
        assert_eq!(got, UnlockResult::Unlocked);
        let settings = VaultSettings::new(Arc::clone(&s), v);
        let pick = crate::hwkey::KeyPick { slot: 1, ..PICK };
        let refused = settings.set_security_key(Some(pick), vec![]).unwrap();
        assert!(
            matches!(&refused, Outcome::Refused { id, .. } if id == "M06-17"),
            "{refused:?}"
        );
        assert_eq!(settings.view().unwrap().security_key, Some(PICK));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
    }

    /// F-126 (MOD-12.10, INT-07.25): the credentials page adds a security
    /// key to a password vault, changes it and removes it; each takes
    /// effect with the next save. A key that is not plugged in is refused
    /// with M06-17 and changes nothing.
    #[test]
    fn f_126_vault_settings_add_change_and_remove_the_security_key() {
        // A password-and-key vault; first take the key off.
        let path = hardware_vault("f126-settings");
        let target = path.to_string_lossy().into_owned();
        let unlock = |hardware| {
            let s = Session::new();
            let v = s.open(target.clone()).unwrap();
            let got = s
                .unlock_with_key(
                    v,
                    Some("demo-pass".into()),
                    None,
                    hardware,
                    s.lock_epoch(v).unwrap(),
                )
                .unwrap();
            (s, v, got)
        };
        let (s, v, got) = unlock(Some(PICK));
        assert_eq!(got, UnlockResult::Unlocked);
        let settings = VaultSettings::new(Arc::clone(&s), v);
        assert_eq!(settings.view().unwrap().security_key, Some(PICK));
        assert_eq!(
            settings.set_security_key(None, vec![]).unwrap(),
            Outcome::Done
        );
        assert_eq!(settings.view().unwrap().security_key, None);
        assert_eq!(s.save(v).unwrap().failure, None);
        let (s, v, got) = unlock(None);
        assert_eq!(
            got,
            UnlockResult::Unlocked,
            "removed: the password alone opens it"
        );
        // Not plugged in: refused, nothing changed.
        let settings = VaultSettings::new(Arc::clone(&s), v);
        let refused = settings
            .set_security_key(Some(crate::hwkey::KeyPick { serial: 7, ..PICK }), vec![])
            .unwrap();
        assert!(
            matches!(&refused, Outcome::Refused { id, .. } if id == "M06-17"),
            "{refused:?}"
        );
        assert_eq!(settings.view().unwrap().security_key, None);
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        // Added (and so changed): the next save needs the key.
        let added = settings.set_security_key(Some(PICK), vec![]).unwrap();
        assert_eq!(added, Outcome::Done);
        assert_eq!(settings.view().unwrap().security_key, Some(PICK));
        assert_eq!(s.save(v).unwrap().failure, None);
        let (_, _, got) = unlock(None);
        assert!(matches!(got, UnlockResult::Failed { .. }), "{got:?}");
        let (_, _, got) = unlock(Some(PICK));
        assert_eq!(got, UnlockResult::Unlocked);
    }
}
