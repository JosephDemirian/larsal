//! Hardware keys in unlock and save (F-107; INT-07, APP-06.8, APP-06.15,
//! LD-225 (1)): the key and slot the user chose go into the key flow
//! through app-hwkey's USB layer. Swift sees the list items and the choice
//! (a serial and a slot, not secret), never a challenge or an answer.

use app_format::error::HardwareKeyReason;
use app_format::keys::ChallengeResponse;
use app_hwkey::{Detection, Event, KeyChoice, Reason, Slot};
use std::sync::atomic::{AtomicBool, Ordering};

/// A key and slot (INT-07.5). `serial` 0 asks the first usable key
/// (D-INT07-6). Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct KeyPick {
    /// The key's serial number; 0 when it cannot be read.
    pub serial: u32,
    /// 1 or 2.
    pub slot: u8,
    /// Detection said the slot waits for a touch (INT-07.19).
    pub needs_touch: bool,
}

/// One usable slot of one key in UL-HW's list (INT-07.16, LD-101).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyItem {
    /// "<model> · serial <serial> · slot <n>".
    pub label: String,
    /// The key and slot this item asks.
    pub pick: KeyPick,
}

/// One look for keys (APP-06.8).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyLook {
    /// The usable slots, sorted by serial, then slot.
    pub items: Vec<KeyItem>,
    /// M06-36's toast for "Look for keys again", or MI07-01 when macOS
    /// refused the key.
    pub note: String,
}

/// The hardware key part of one vault's credentials: kept by the unlock
/// for every later save (FMT-04.10, edit.rs `Saver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Choice {
    key: KeyChoice,
    needs_touch: bool,
}

impl Choice {
    /// The choice of `pick`; `None` for a slot other than 1 or 2.
    pub(crate) fn of(pick: KeyPick) -> Option<Self> {
        let slot = match pick.slot {
            1 => Slot::One,
            2 => Slot::Two,
            _ => return None,
        };
        Some(Self {
            key: KeyChoice {
                serial: pick.serial,
                slot,
            },
            needs_touch: pick.needs_touch,
        })
    }

    /// The pick of this choice, for the screens (not secret).
    pub(crate) fn pick(self) -> KeyPick {
        KeyPick {
            serial: self.key.serial,
            slot: self.key.slot.number(),
            needs_touch: self.needs_touch,
        }
    }

    /// APP-01.16: the `serial:slot` text of S-STATE-03.
    pub(crate) fn remembered(self) -> String {
        format!("{}:{}", self.key.serial, self.key.slot.number())
    }

    /// The pick of a remembered `serial:slot` text; `None` when malformed.
    pub(crate) fn parse(text: &str) -> Option<KeyPick> {
        let (serial, slot) = text.split_once(':')?;
        let pick = KeyPick {
            serial: serial.parse().ok()?,
            slot: slot.parse().ok()?,
            needs_touch: false,
        };
        Self::of(pick).map(|_| pick)
    }

    /// The part the key flow asks: the chosen key on USB, found again at
    /// each challenge (INT-07.18); touch waits show M06-35.
    #[cfg(not(test))]
    pub(crate) fn part(self) -> Box<dyn ChallengeResponse> {
        Box::new(app_hwkey::HardwareKey {
            bus: app_hwkey::usb::UsbBus::new(),
            choice: self.key,
            needs_touch: self.needs_touch,
            events: Some(Box::new(touch)),
        })
    }

    /// Unit tests never reach USB (OD-01, as app-hwkey's T47): every
    /// choice answers with the software key of [`tests::software`].
    #[cfg(test)]
    pub(crate) fn part(self) -> Box<dyn ChallengeResponse> {
        Box::new(tests::software())
    }
}

/// Whether a challenge waits for a touch now (M06-35).
static WAITS: AtomicBool = AtomicBool::new(false);

/// A touch event: the flag for M06-35, then the window reads again.
fn touch(event: Event) {
    WAITS.store(event == Event::TouchNeeded, Ordering::SeqCst);
    crate::session::changed();
}

/// Takes nothing; true while a security key challenge waits for a touch,
/// so the unlock screen and the save line show M06-35 (APP-06.15). The
/// window hears of each change through `session_changed`.
#[uniffi::export]
#[must_use]
pub fn security_key_waits() -> bool {
    WAITS.load(Ordering::SeqCst)
}

/// MOD-12.10 step 6, APP-07.16 check 6 (F-126): the chosen key and slot
/// must be plugged in now (INT-07). The choice, else M06-17 (MI07-01 when
/// macOS refused the key). Call it off the main thread: a look gives each
/// key a short test challenge (INT-07.15). The screens' lists come from
/// `security_keys::KeyWatch`.
pub(crate) fn plugged(pick: KeyPick) -> Result<Choice, crate::messages::Message> {
    let found = detect_now();
    if let Ok(found) = &found
        && found.items.iter().any(|item| {
            item.slot.number() == pick.slot && (pick.serial == 0 || item.serial == pick.serial)
        })
        && let Some(choice) = Choice::of(pick)
    {
        return Ok(choice);
    }
    let reason = if found == Err(Reason::NotPermitted) {
        HardwareKeyReason::NotPermitted
    } else {
        HardwareKeyReason::Missing
    };
    Err(crate::messages::for_open_error(
        &app_format::error::Error::HardwareKey(reason),
        "",
        "",
    ))
}

#[cfg(not(test))]
fn detect_now() -> Result<Detection, Reason> {
    app_hwkey::detect(&app_hwkey::usb::UsbBus::new())
}

/// Unit tests never reach USB (OD-01): one key is plugged in, with the
/// slot of [`tests::PICK`].
#[cfg(test)]
fn detect_now() -> Result<Detection, Reason> {
    Ok(tests::plugged())
}

/// The list and M06-36's toast (or MI07-01) of one detection.
pub(crate) fn look(found: Result<Detection, Reason>) -> KeyLook {
    let found = match found {
        Ok(found) => found,
        Err(Reason::NotPermitted) => {
            return KeyLook {
                items: Vec::new(),
                note: app_hwkey::MI07_01.to_owned(),
            };
        }
        Err(_) => Detection::default(),
    };
    let items: Vec<KeyItem> = found
        .items
        .iter()
        .map(|item| KeyItem {
            label: item.label(),
            pick: KeyPick {
                serial: item.serial,
                slot: item.slot.number(),
                needs_touch: item.needs_touch,
            },
        })
        .collect();
    let note = match (items.is_empty(), found.devices) {
        (true, 0) => "App sees no security key. Plug one in and look again.".to_owned(),
        (true, _) => {
            "No slot on the plugged-in security key is set up for challenge-response.".to_owned()
        }
        (false, 1) => "Found 1 security key.".to_owned(),
        (false, n) => format!("Found {n} security keys."),
    };
    KeyLook { items, note }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_dir::TempDir;
    use app_crypto::secret::{SecretBytes, SecretString};
    use app_format::keys::{SlotMode, SoftwareKey};
    use app_hwkey::Item;

    /// Demo secret D of INT-07 and FMT-04 (OD-01: software only).
    pub(crate) const D: &[u8] = b"App demo HMAC secret";

    /// The software key every unit-test choice answers with.
    pub(crate) fn software() -> SoftwareKey {
        SoftwareKey {
            secret: SecretBytes::new(D.to_vec()),
            mode: SlotMode::Variable,
        }
    }

    /// The pick tests unlock with.
    pub(crate) const PICK: KeyPick = KeyPick {
        serial: 24_531_878,
        slot: 2,
        needs_touch: false,
    };

    /// What a look finds in unit tests: the key and slot of [`PICK`].
    pub(crate) fn plugged() -> Detection {
        Detection {
            items: vec![Item {
                model: "YubiKey 5".to_owned(),
                serial: PICK.serial,
                slot: Slot::Two,
                needs_touch: false,
            }],
            devices: 1,
            without_slot: false,
        }
    }

    /// A small demo vault (1 AES-KDF round) saved with `demo-pass` and the
    /// software key, at `name` in a private folder removed when the value
    /// drops (LD-240 (5)).
    pub(crate) fn hardware_vault(name: &str) -> TempDir {
        use app_crypto::kdf::Host;
        use app_format::keys::Credentials;
        use app_format::limits::Limits;
        let now = app_model::Time::from_unix(1_700_000_000).unwrap();
        let root = app_model::Group::new(app_model::Uuid([1; 16]), "Root".to_owned(), now);
        let mut vault = app_model::Vault::new(root, now);
        vault.encryption.kdf = app_model::Kdf::AesKdf { rounds: 1 };
        let password = SecretString::new("demo-pass".to_owned());
        let key = software();
        let credentials = Credentials {
            password: Some(&password),
            key_file: None,
            hardware_key: Some(&key),
        };
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        };
        let saved = app_format::save(
            &vault,
            &credentials,
            None,
            &mut host,
            &Limits::DEFAULT,
            None,
        );
        let Ok(app_format::Saved::File(file)) = saved else {
            panic!("1 AES-KDF round never asks");
        };
        let path = TempDir::new(&format!("hwkey-{name}")).file(&format!("{name}.appvault"));
        std::fs::write(&path, &file.bytes).unwrap();
        path
    }

    /// F-107 (AT-H03, AT-H04 through the session): a vault protected by a
    /// password and a hardware key opens only with the chosen key, and a
    /// save asks the key again, so the saved file still needs it.
    #[test]
    fn f_107_unlock_and_save_use_the_hardware_key() {
        use crate::edit::EditText;
        use crate::session::{Session, UnlockResult};
        let path = hardware_vault("unlock");
        let open = || {
            let s = Session::new();
            let v = s.open(path.to_string_lossy().into_owned()).unwrap();
            (s, v)
        };
        // Without the key: M06-06, as before the fix.
        let (s, v) = open();
        let failed = s.unlock(v, Some("demo-pass".into()), None).unwrap();
        assert!(
            matches!(&failed, UnlockResult::Failed { message } if message.id == "M06-06"),
            "{failed:?}"
        );
        // With the chosen key: unlocked.
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
        // One change and a save: the kept choice is asked with the new seed.
        s.begin_new(v, None).unwrap();
        s.set_text(v, EditText::Title, "After the save".into())
            .unwrap();
        s.commit_edit(v).unwrap();
        let status = s.save(v).unwrap();
        assert_eq!((status.changes, &status.failure), (0, &None), "{status:?}");
        let (s, v) = open();
        let failed = s.unlock(v, Some("demo-pass".into()), None).unwrap();
        assert!(matches!(failed, UnlockResult::Failed { .. }), "{failed:?}");
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
    }

    /// F-080 (SR-12, APP-01.16, APP-06.9): each unlock attempt sets the
    /// remembered key file and key slot, only while S-START-08 is on, and
    /// the unlock screen reads them back.
    #[test]
    fn f_080_unlock_remembers_key_parts_while_the_option_is_on() {
        use crate::app_settings::{AppSetting, AppSettingValue};
        use crate::session::{RememberedKeys, Session, UnlockResult};
        let path = hardware_vault("remember");
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        let none = RememberedKeys {
            key_file: None,
            hardware: None,
        };
        // Off (the default): nothing is written, so turning it on later
        // finds nothing (APP-01.16 c).
        s.unlock_with_key(
            v,
            Some("x".into()),
            Some("k.appkey".into()),
            Some(PICK),
            s.lock_epoch(v).unwrap(),
        )
        .unwrap();
        s.save_settings(vec![AppSetting {
            key: "recent.remember_keys".to_owned(),
            value: AppSettingValue::Flag { on: true },
        }])
        .unwrap();
        assert_eq!(s.remembered_keys(v).unwrap(), none);
        // A failed attempt with a key file: the key file, no slot.
        let failed = s
            .unlock_with_key(
                v,
                Some("x".into()),
                Some("~/k.appkey".into()),
                None,
                s.lock_epoch(v).unwrap(),
            )
            .unwrap();
        assert!(matches!(failed, UnlockResult::Failed { .. }), "{failed:?}");
        assert_eq!(
            s.remembered_keys(v).unwrap(),
            RememberedKeys {
                key_file: Some("~/k.appkey".to_owned()),
                hardware: None,
            }
        );
        // The unlock with the key: the slot, no key file.
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
        assert_eq!(
            s.remembered_keys(v).unwrap(),
            RememberedKeys {
                key_file: None,
                hardware: Some(PICK),
            }
        );
    }

    /// F-079, F-080 (APP-06.24 bullet 3): a passed-in unlock (auto-open, a
    /// vault link) uses the slot remembered for the vault while S-START-08
    /// is on, and the slot stays remembered.
    #[test]
    fn f_107_passed_in_unlock_uses_the_remembered_slot() {
        use crate::app_settings::{AppSetting, AppSettingValue};
        use crate::session::{RememberedKeys, Session, UnlockResult};
        let path = hardware_vault("passed");
        let s = Session::new();
        s.save_settings(vec![AppSetting {
            key: "recent.remember_keys".to_owned(),
            value: AppSettingValue::Flag { on: true },
        }])
        .unwrap();
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
        s.lock(v).unwrap();
        s.unlock_passed(v, Some(SecretString::new("demo-pass".into())), None, false);
        assert!(!s.vaults()[0].locked, "{:?}", s.take_message(v));
        assert_eq!(
            s.remembered_keys(v).unwrap(),
            RememberedKeys {
                key_file: None,
                hardware: Some(PICK),
            }
        );
    }

    /// F-107: a reload from disk opens the disk version with the kept key,
    /// and a key change in vault settings keeps the hardware key as a part
    /// (removing the password leaves it the only part, which is allowed).
    #[test]
    fn f_107_reload_and_key_change_keep_the_hardware_key() {
        use crate::saving::{DiskChoice, DiskEvent};
        use crate::session::{Session, UnlockResult};
        use crate::vault_settings::VaultSettings;
        use crate::wizard::Outcome;
        let path = hardware_vault("reload");
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock_with_key(
            v,
            Some("demo-pass".into()),
            None,
            Some(PICK),
            s.lock_epoch(v).unwrap(),
        )
        .unwrap();
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Reload).unwrap(),
            DiskEvent::Reloaded
        );
        let settings = VaultSettings::new(std::sync::Arc::clone(&s), v);
        settings.set_password(String::new()).unwrap();
        settings.set_repeat(String::new()).unwrap();
        let asked = settings.change_password(vec![]).unwrap();
        let Outcome::Ask { question } = asked else {
            panic!("M07-21 asks first: {asked:?}");
        };
        let done = settings.change_password(vec![question.answer]).unwrap();
        assert_eq!(done, Outcome::Done);
        let status = s.save(v).unwrap();
        assert_eq!(status.failure, None, "{status:?}");
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        let got = s
            .unlock_with_key(v, None, None, Some(PICK), s.lock_epoch(v).unwrap())
            .unwrap();
        assert_eq!(got, UnlockResult::Unlocked);
    }

    #[test]
    fn f_107_touch_events_drive_m06_35() {
        touch(Event::TouchNeeded);
        assert!(security_key_waits());
        touch(Event::TouchEnded);
        assert!(!security_key_waits());
    }

    #[test]
    fn f_107_choice_round_trips_through_the_remembered_text() {
        let choice = Choice::of(PICK).unwrap();
        assert_eq!(choice.remembered(), "24531878:2");
        assert_eq!(Choice::parse("24531878:2"), Some(PICK));
        for bad in ["", "2", "x:2", "1:3", "1:0", ":2", "-1:2"] {
            assert_eq!(Choice::parse(bad), None, "{bad}");
        }
        assert!(Choice::of(KeyPick { slot: 3, ..PICK }).is_none());
    }

    #[test]
    fn f_107_look_lists_items_with_the_m06_36_note() {
        let item = |serial, slot| Item {
            model: "YubiKey 5".to_owned(),
            serial,
            slot,
            needs_touch: slot == Slot::Two,
        };
        let two = look(Ok(Detection {
            items: vec![item(7, Slot::One), item(7, Slot::Two), item(9, Slot::Two)],
            devices: 2,
            without_slot: false,
        }));
        assert_eq!(two.note, "Found 2 security keys.");
        assert_eq!(two.items.len(), 3);
        assert_eq!(two.items[0].label, "YubiKey 5 · serial 7 · slot 1");
        assert_eq!(
            two.items[1].pick,
            KeyPick {
                serial: 7,
                slot: 2,
                needs_touch: true
            }
        );
        let one = look(Ok(Detection {
            items: vec![item(7, Slot::Two)],
            devices: 1,
            without_slot: false,
        }));
        assert_eq!(one.note, "Found 1 security key.");
        let none = look(Ok(Detection::default()));
        assert!(none.items.is_empty());
        assert_eq!(
            none.note,
            "App sees no security key. Plug one in and look again."
        );
        let bare = look(Ok(Detection {
            devices: 1,
            without_slot: true,
            ..Detection::default()
        }));
        assert!(bare.note.starts_with("No slot on the plugged-in"));
        assert_eq!(look(Err(Reason::NotPermitted)).note, app_hwkey::MI07_01);
        assert!(look(Err(Reason::Failed)).note.starts_with("App sees no"));
    }
}
