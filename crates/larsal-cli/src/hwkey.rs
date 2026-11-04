//! The hardware key part of `--hw-key` and `--hw-key-from` (F-107;
//! INT-10.14, INT-07.27): the chosen slot, asked through larsal-hwkey's USB
//! layer at each challenge; M10-18 while it waits for a touch.

use larsal_format::keys::ChallengeResponse;
use larsal_hwkey::{KeyChoice, Slot};

/// The key and slot of a checked `SLOT[:SERIAL]` value (args::hw_key_ok);
/// serial 0, or none, asks the first usable key (INT-07.5).
pub fn choice(value: &str) -> KeyChoice {
    let (slot, serial) = value.split_once(':').unwrap_or((value, "0"));
    KeyChoice {
        serial: serial.parse().unwrap_or(0),
        slot: if slot == "1" { Slot::One } else { Slot::Two },
    }
}

/// The part the key flow asks for `value`.
#[cfg(not(test))]
pub fn part(value: &str) -> Box<dyn ChallengeResponse> {
    Box::new(larsal_hwkey::HardwareKey {
        bus: larsal_hwkey::usb::UsbBus::new(),
        choice: choice(value),
        needs_touch: false,
        events: Some(Box::new(|event| {
            if event == larsal_hwkey::Event::TouchNeeded {
                crate::term::err("Touch your security key to go on.");
            }
        })),
    })
}

/// Unit tests never reach USB (OD-01, as larsal-hwkey's T47): every slot
/// answers with the software key of [`tests::software`].
#[cfg(test)]
pub fn part(value: &str) -> Box<dyn ChallengeResponse> {
    let _ = choice(value);
    Box::new(tests::software())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vault::{Creds, Unlock, open, unlock};
    use larsal_crypto::kdf::Host;
    use larsal_crypto::secret::{SecretBytes, SecretString};
    use larsal_format::keys::{Credentials, SlotMode, SoftwareKey};
    use larsal_format::limits::Limits;

    /// The software key of INT-10.14-a (OD-01): demo secret D, variable.
    pub fn software() -> SoftwareKey {
        SoftwareKey {
            secret: SecretBytes::new(b"Larsal demo HMAC key".to_vec()),
            mode: SlotMode::Variable,
        }
    }

    #[test]
    fn f_107_slot_values_become_choices() {
        let c = |v| {
            let k = choice(v);
            (k.slot, k.serial)
        };
        assert_eq!(c("2"), (Slot::Two, 0));
        assert_eq!(c("1"), (Slot::One, 0));
        assert_eq!(c("2:24531878"), (Slot::Two, 24_531_878));
        assert_eq!(c("1:4294967295"), (Slot::One, u32::MAX));
    }

    /// F-107 (INT-10.14-a, AT-H03 through the tool): a vault protected by
    /// the hardware key alone opens with `--no-password --hw-key 2`, a save
    /// asks the key again, and the saved file still needs it.
    #[test]
    fn f_107_hw_key_unlocks_and_saves() {
        let dir = std::env::temp_dir().join(format!("larsal-cli-hwkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hk.larsalvault");
        let now = larsal_model::Time::from_unix(1_700_000_000).unwrap();
        let root = larsal_model::Group::new(larsal_model::Uuid([1; 16]), "Root".to_owned(), now);
        let mut vault = larsal_model::Vault::new(root, now);
        vault.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1 };
        let key = software();
        let credentials = Credentials {
            hardware_key: Some(&key),
            ..Credentials::default()
        };
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        };
        let saved = larsal_format::save(
            &vault,
            &credentials,
            None,
            &mut host,
            &Limits::DEFAULT,
            None,
        );
        let Ok(larsal_format::Saved::File(file)) = saved else {
            panic!("1 AES-KDF round never asks");
        };
        std::fs::write(&path, &file.bytes).unwrap();
        let path = path.to_string_lossy().into_owned();
        let u = Unlock {
            key_file: None,
            no_password: true,
            hw_key: Some("2"),
            quiet: true,
            slow: false,
        };
        let Ok(mut s) = unlock(&path, &u) else {
            panic!("the hardware key opens the vault");
        };
        s.vault.meta.name = "Saved with the key".to_owned();
        assert!(s.save().is_ok());
        drop(s);
        let Ok(again) = unlock(&path, &u) else {
            panic!("the saved file opens with the key");
        };
        assert_eq!(again.vault.meta.name, "Saved with the key");
        // Without the key part the saved file does not open.
        let other = Creds::new(Some(SecretString::new("x".into())), None);
        assert!(open(&path, other, &u).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F-107 (INT-10.38): `db-edit --unset-password` on a vault opened with
    /// `--hw-key` keeps the slot as a key part, so the change is allowed
    /// and the saved file opens with the key alone.
    #[test]
    fn f_107_db_edit_keeps_the_hw_key_part() {
        let dir =
            std::env::temp_dir().join(format!("larsal-cli-hwkey-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw-hk.larsalvault");
        let now = larsal_model::Time::from_unix(1_700_000_000).unwrap();
        let root = larsal_model::Group::new(larsal_model::Uuid([1; 16]), "Root".to_owned(), now);
        let mut vault = larsal_model::Vault::new(root, now);
        vault.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1 };
        let key = software();
        let password = SecretString::new("demo-pass".into());
        let credentials = Credentials {
            password: Some(&password),
            hardware_key: Some(&key),
            ..Credentials::default()
        };
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        };
        let saved = larsal_format::save(
            &vault,
            &credentials,
            None,
            &mut host,
            &Limits::DEFAULT,
            None,
        );
        let Ok(larsal_format::Saved::File(file)) = saved else {
            panic!("1 AES-KDF round never asks");
        };
        std::fs::write(&path, &file.bytes).unwrap();
        let path = path.to_string_lossy().into_owned();
        let with_password = Unlock {
            key_file: None,
            no_password: false,
            hw_key: Some("2"),
            quiet: true,
            slow: false,
        };
        let creds = Creds {
            hardware: Some(part("2")),
            ..Creds::new(Some(password), None)
        };
        let Ok(s) = open(&path, creds, &with_password) else {
            panic!("the password and the key open the vault");
        };
        let cmd = crate::args::lookup("db-edit", true).unwrap();
        let words = ["--unset-password".to_owned(), "-q".to_owned()];
        let Ok(p) = crate::args::parse(cmd, &words, true) else {
            panic!("db-edit --unset-password parses");
        };
        assert!(crate::commands::run(&p, &mut Some(s)).is_ok());
        let key_only = Unlock {
            no_password: true,
            ..with_password
        };
        assert!(unlock(&path, &key_only).is_ok(), "the key alone opens it");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
