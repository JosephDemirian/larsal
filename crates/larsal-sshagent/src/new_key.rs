//! New SSH Key (E24-S2, spec INT-06.E24.04): what a key larsal-crypto made
//! adds to an entry, so that E9's agent path finds it there (INT-06.4).

use crate::settings::{SETTINGS_NAME, Settings, Source};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::ssh::NewSshKey;
use larsal_model::Entry;

/// The attachments New SSH Key adds to an entry, as (name, content), in this
/// order: the public line and a line feed as `id_<type>.pub`, the SSH
/// settings that point the agent at the private key, and the private key
/// file text as `id_<type>` (one key, `openssh-key-v1`, unprotected: it
/// lives only inside the vault's encryption). The settings allow the key,
/// take it from that attachment and remove it when the vault locks; nothing
/// is added at unlock, no question and no lifetime are set (the INT-06.1
/// defaults). The private text moves; nothing copies it.
#[must_use]
pub fn new_key_files(key: NewSshKey) -> [(String, SecretBytes); 3] {
    let name = key.kind().file_name().to_owned();
    let public = format!("{}\n", key.public_line()).into_bytes();
    let settings = Settings {
        allow: true,
        remove_at_close: true,
        source: Source::Attachment,
        attachment_name: name.clone(),
        ..Settings::default()
    };
    // Never the defaults (the key is allowed), so `write` gives the document.
    let settings = settings.write().unwrap_or_default();
    [
        (format!("{name}.pub"), SecretBytes::new(public)),
        (
            String::from_utf8_lossy(&SETTINGS_NAME).into_owned(),
            SecretBytes::new(settings),
        ),
        (name, key.into_private()),
    ]
}

/// Why New SSH Key cannot add a key to `entry` (INT-06.E24.04: a key is never
/// replaced by a name collision): `Some` with the name in the way when the
/// entry already has SSH settings, or an attachment of one of the names the
/// new key's files take (`file_name` and `file_name.pub`); `None` when it
/// can.
#[must_use]
pub fn new_key_blocked(entry: &Entry, file_name: &str) -> Option<String> {
    let settings = String::from_utf8_lossy(&SETTINGS_NAME).into_owned();
    let public = format!("{file_name}.pub");
    [settings.as_str(), file_name, public.as_str()]
        .into_iter()
        .find(|n| entry.attachments.iter().any(|a| a.name == *n))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;
    use larsal_crypto::ssh::{NewKeyKind, OpenSshKey, new_key};
    use larsal_model::{Attachment, Time, Uuid};
    use std::sync::Arc;

    #[test]
    fn e24_s04_the_key_goes_in_as_three_new_attachments_the_agent_reads() {
        let key = new_key(NewKeyKind::EcdsaP384, "demo@larsal").unwrap();
        let (line, fingerprint) = (key.public_line().to_owned(), key.fingerprint().to_owned());
        let files = new_key_files(key);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names[0], "id_ecdsa.pub");
        assert_eq!(names[2], "id_ecdsa");
        assert_eq!(files[0].1.expose(), format!("{line}\n").as_bytes());
        let read = OpenSshKey::parse(files[2].1.expose()).unwrap();
        assert_eq!(read.fingerprint(), fingerprint);
        let mut e = Entry::new(Uuid([7; 16]), Time(0));
        assert_eq!(new_key_blocked(&e, "id_ecdsa"), None);
        e.attachments = files
            .into_iter()
            .map(|(name, data)| Attachment {
                name,
                data: Arc::new(data),
            })
            .collect();
        let s = Settings::of(&e).unwrap().unwrap();
        assert!(s.allow && s.remove_at_close && s.source_set());
        assert!(!s.add_at_open && !s.confirm && !s.use_lifetime);
        assert_eq!(s.attachment_name, "id_ecdsa");
        // A second key never replaces the first by name.
        assert!(new_key_blocked(&e, "id_ecdsa").is_some());
        assert!(
            new_key_blocked(&e, "id_rsa").is_some(),
            "the settings are taken"
        );
        e.attachments
            .retain(|a| a.name == "id_rsa.pub" || a.name == "id_ecdsa");
        assert_eq!(new_key_blocked(&e, "id_ed25519"), None);
        assert_eq!(new_key_blocked(&e, "id_ecdsa").as_deref(), Some("id_ecdsa"));
    }
}
