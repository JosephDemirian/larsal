//! The messages of spec INT-06 (MI06-01 to MI06-37), in the card's words, as
//! data. ‹…› marks a placeholder. Swift shows them; Rust fills them.
//!
//! Guarantees: placeholders are filled in one pass, so text inside a value
//! (an entry title, a path) is never expanded again; no message holds a
//! secret, because no [`Error`] holds one.

use crate::Error;

/// Every message of the card, by ID. MI06-04 holds its first sentence; its
/// two hints are [`MI06_04_LIFETIME`] and [`MI06_04_SECURITY_KEY`].
pub const MESSAGES: [(&str, &str); 37] = [
    (
        "MI06-01",
        "No SSH agent was found. macOS normally provides one through SSH_AUTH_SOCK; you can also set a socket in SSH Agent settings.",
    ),
    ("MI06-02", "Larsal couldn't reach the SSH agent at ‹path›."),
    (
        "MI06-03",
        "Larsal won't use ‹path›: it is not an SSH agent socket that belongs to you.",
    ),
    (
        "MI06-04",
        "The SSH agent did not take the key of “‹title›”.",
    ),
    (
        "MI06-05",
        "This key is already loaded from another open vault, ‹vault name›. Lock that vault or remove the key there first.",
    ),
    ("MI06-06", "“‹title›” has no attachment named ‹name›."),
    ("MI06-07", "Larsal can't open the key file ‹path›."),
    (
        "MI06-08",
        "‹name› is over 1 MiB, so it can't be an SSH key.",
    ),
    ("MI06-09", "‹name› has no content."),
    (
        "MI06-10",
        "‹name› is not an SSH private key Larsal can read.",
    ),
    (
        "MI06-11",
        "‹name› uses an older key format. Convert a copy with \"ssh-keygen -p -f ‹file›\", then use the converted file.",
    ),
    (
        "MI06-12",
        "‹name› is a DSA key, which OpenSSH no longer supports. Use an Ed25519 key instead.",
    ),
    (
        "MI06-13",
        "‹name› uses ‹cipher or type›, which Larsal can't read.",
    ),
    (
        "MI06-14",
        "This key is protected by a passphrase. Put the passphrase in the entry's Password field.",
    ),
    ("MI06-15", "The entry's password does not unlock this key."),
    (
        "MI06-16",
        "This key's passphrase protection uses ‹n› rounds; Larsal allows at most 1,000. Protect it again with fewer rounds, for example \"ssh-keygen -p -a 100 -f ‹file›\".",
    ),
    ("MI06-17", "The time limit must be at least 1 minute."),
    (
        "MI06-18",
        "Some SSH keys were not loaded: ‹titles›. Button \"Details\" lists each title with its message.",
    ),
    (
        "MI06-19",
        "Larsal couldn't take the key of “‹title›” out of the SSH agent. Use Remove All Keys from SSH Agent… to clear it.",
    ),
    ("MI06-20", "Every key was removed from the SSH agent."),
    ("MI06-21", "The SSH agent did not remove its keys."),
    ("MI06-22", "Connected / Not connected"),
    ("MI06-23", "Loaded in agent / Loaded / Not loaded"),
    (
        "MI06-24",
        "Larsal can't read this entry's SSH settings. Saving this page replaces them.",
    ),
    (
        "MI06-25",
        "Removed when the vault locks / Stays loaded after the vault locks / , removed after ‹n› min",
    ),
    ("MI06-26", "Built-in / Choose a library…"),
    ("MI06-27", "Shown after the key is unlocked"),
    (
        "MI06-28",
        "The SSH agent built into macOS has no built-in provider. To use keys that live on a security key, choose a provider library.",
    ),
    ("MI06-29", "Allow ‹program› to use “‹entry title›”?"),
    (
        "MI06-30",
        "‹program› wants to sign in to ‹host› with this key.",
    ),
    ("MI06-31", "‹program› wants to sign with this key."),
    (
        "MI06-32",
        "Larsal's agent · ‹path› · Ready. Button \"Copy Setup Line\"; toast after copying: Setup line copied. Add it to ~/.ssh/config for the hosts that should use keys that ask first.",
    ),
    (
        "MI06-33",
        "Asking before each use works with Ed25519 and ECDSA P-256 keys.",
    ),
    (
        "MI06-34",
        "The SSH agent in macOS can't ask you. With this on, every use of the key is refused unless the agent has an askpass helper.",
    ),
    ("MI06-35", "Public key copied / Fingerprint copied"),
    (
        "MI06-36",
        "Choose the private key: an attachment or a file.",
    ),
    // LD-175 (R06-2): the question's text for a forwarded connection.
    (
        "MI06-37",
        "‹program› wants to sign in to ‹host› through a forwarded connection.",
    ),
];

/// MI06-04's hint when a lifetime was sent.
pub const MI06_04_LIFETIME: &str = "It may not accept a time limit.";
/// MI06-04's hint for `sk-` keys.
pub const MI06_04_SECURITY_KEY: &str =
    "Keys on a security key need a provider the agent accepts. Check SSH Agent settings.";

/// The card's text for `id`, placeholders unfilled; `None` for an unknown ID.
#[must_use]
pub fn text(id: &str) -> Option<&'static str> {
    MESSAGES.iter().find(|(i, _)| *i == id).map(|(_, t)| *t)
}

/// What the caller knows and the error does not, for its message.
#[derive(Debug, Clone, Copy, Default)]
pub struct Names<'a> {
    /// The entry title (‹title›).
    pub title: &'a str,
    /// The key attachment name or file name (‹name›).
    pub name: &'a str,
    /// The key file path for the `ssh-keygen` advice (‹file›).
    pub file: &'a str,
}

impl Error {
    /// The card's message ID for this error.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::NoAgent => "MI06-01",
            Self::Unreachable { .. } => "MI06-02",
            Self::NotOurSocket { .. } => "MI06-03",
            Self::AddRefused { .. } => "MI06-04",
            Self::TooLarge => "MI06-08",
            Self::Empty => "MI06-09",
            Self::NotAKey => "MI06-10",
            Self::OldFormat => "MI06-11",
            Self::Dsa => "MI06-12",
            Self::Unsupported(_) => "MI06-13",
            Self::NoPassphrase => "MI06-14",
            Self::WrongPassphrase => "MI06-15",
            Self::TooManyRounds(_) => "MI06-16",
            Self::Lifetime => "MI06-17",
            Self::RemoveAllRefused => "MI06-21",
            Self::OtherVault(_) => "MI06-05",
            Self::NoAttachment => "MI06-06",
            Self::CannotOpen { .. } => "MI06-07",
            Self::SettingsUnreadable => "MI06-24",
            Self::CannotAsk => "MI06-33",
        }
    }

    /// The message the screen shows, in the card's words, filled from this
    /// error and `names`. MI06-04 adds the hints that apply.
    #[must_use]
    pub fn message(&self, names: &Names<'_>) -> String {
        let (path, what, rounds) = match self {
            Self::Unreachable { path, .. }
            | Self::NotOurSocket { path }
            | Self::CannotOpen { path } => {
                (path.display().to_string(), String::new(), String::new())
            }
            Self::Unsupported(what) | Self::OtherVault(what) => {
                (String::new(), what.clone(), String::new())
            }
            Self::TooManyRounds(n) => (String::new(), String::new(), n.to_string()),
            _ => Default::default(),
        };
        let values = [
            ("‹title›", names.title),
            ("‹name›", names.name),
            ("‹file›", names.file),
            ("‹path›", path.as_str()),
            ("‹cipher or type›", what.as_str()),
            ("‹vault name›", what.as_str()),
            ("‹n›", rounds.as_str()),
        ];
        let mut out = fill(text(self.id()).unwrap_or_default(), &values);
        if let Self::AddRefused {
            lifetime,
            security_key,
        } = self
        {
            for (on, hint) in [
                (*lifetime, MI06_04_LIFETIME),
                (*security_key, MI06_04_SECURITY_KEY),
            ] {
                if on {
                    out.push(' ');
                    out.push_str(hint);
                }
            }
        }
        out
    }
}

/// Replaces each ‹…› placeholder of `text` that `values` names, in one pass.
#[must_use]
pub fn fill(text: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, from)) = rest.find('‹').and_then(|i| rest.split_at_checked(i)) {
        out.push_str(before);
        let Some((mark, after)) = from
            .find('›')
            .and_then(|i| from.split_at_checked(i.saturating_add('›'.len_utf8())))
        else {
            rest = from;
            break;
        };
        out.push_str(
            values
                .iter()
                .find(|(k, _)| *k == mark)
                .map_or(mark, |(_, v)| v),
        );
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn table_has_every_id_once_in_order() {
        for (n, (id, text)) in MESSAGES.iter().enumerate() {
            assert_eq!(*id, format!("MI06-{:02}", n + 1));
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn messages_fill_in_the_cards_words() {
        let names = Names {
            title: "Server root · web-01",
            name: "id_ed25519",
            file: "/tmp/k",
        };
        assert_eq!(
            Error::TooManyRounds(1001).message(&names),
            "This key's passphrase protection uses 1001 rounds; Larsal allows at most 1,000. Protect it again with fewer rounds, for example \"ssh-keygen -p -a 100 -f /tmp/k\"."
        );
        assert_eq!(
            Error::AddRefused {
                lifetime: true,
                security_key: true
            }
            .message(&names),
            "The SSH agent did not take the key of “Server root · web-01”. It may not accept a time limit. Keys on a security key need a provider the agent accepts. Check SSH Agent settings."
        );
        assert_eq!(
            Error::Unsupported("3des-cbc".into()).message(&names),
            "id_ed25519 uses 3des-cbc, which Larsal can't read."
        );
        let path = PathBuf::from("/tmp/a.sock");
        assert_eq!(
            Error::NotOurSocket { path }.message(&names),
            "Larsal won't use /tmp/a.sock: it is not an SSH agent socket that belongs to you."
        );
    }

    #[test]
    fn fill_is_one_pass() {
        let title = "‹name›";
        assert_eq!(
            fill(
                "“‹title›” has ‹name› ‹other›",
                &[("‹title›", title), ("‹name›", "x")]
            ),
            "“‹name›” has x ‹other›"
        );
        assert_eq!(fill("open ‹ end", &[]), "open ‹ end");
    }
}
