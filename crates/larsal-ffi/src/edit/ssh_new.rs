//! New SSH Key (E24-S2; spec INT-06.E24.01 to .06, Option A frames
//! `e24-s1-new-ssh` to `e24-s1-ssh-save-error`): a key made in Rust joins the
//! open draft's entry as new attachments and is committed in one edit
//! session, as Save commits; Swift gets its public parts only, then saves
//! the vault the normal way (APP-05) and reports the key saved only after
//! that save.
//!
//! Guarantees:
//! - the private key never crosses to Swift: it moves from larsal-crypto into
//!   the draft's attachment (a wiping buffer) and is committed into the vault
//!   (AGENTS rule 4, INT-06.E24.02); no file holds it;
//! - keys come only from the OS random source; a failed source makes no key
//!   and changes nothing;
//! - a key never replaces an attachment or SSH settings by name, and never
//!   joins an entry that shows a key already (.04);
//! - a key commits only into the draft revision it was asked for: a draft
//!   changed, gone, replaced or cancelled meanwhile, or a vault locked or
//!   closed meanwhile, gets nothing; the key is wiped (.06);
//! - Copy Public Key and Save Public Key handle the public line only (.05).

use super::{commit_draft, refused, save_named};
use crate::session::{LarsalError, Session};
use crate::views::{Copied, entry_of, ssh_key, ssh_public, ssh_public_line};
use larsal_core::attachments;
use larsal_crypto::ssh::{NewKeyKind, comment_ok, new_key};
use larsal_model::Entry;

/// New SSH Key's key types (INT-06.E24.01), in the dialog's order: Ed25519
/// (the default), ECDSA on three curves, RSA in two sizes. Nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshKeyKind {
    /// Ed25519, the default, with no size to choose.
    Ed25519,
    /// ECDSA P-256, the curve first selected.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// RSA 3072, the size first selected.
    Rsa3072,
    /// RSA 4096.
    Rsa4096,
}

impl From<SshKeyKind> for NewKeyKind {
    fn from(k: SshKeyKind) -> Self {
        match k {
            SshKeyKind::Ed25519 => Self::Ed25519,
            SshKeyKind::EcdsaP256 => Self::EcdsaP256,
            SshKeyKind::EcdsaP384 => Self::EcdsaP384,
            SshKeyKind::EcdsaP521 => Self::EcdsaP521,
            SshKeyKind::Rsa3072 => Self::Rsa3072,
            SshKeyKind::Rsa4096 => Self::Rsa4096,
        }
    }
}

/// A new key, committed into its entry: public parts only (INT-06.E24.05).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewSshKeyView {
    /// The entry's id.
    pub entry: String,
    /// The private key's attachment, `id_ed25519`, `id_ecdsa` or `id_rsa`;
    /// its public line is the attachment of the same name with `.pub`.
    pub attachment: String,
    /// Type and size: `ED25519`, `ECDSA P-256`, `ECDSA P-384`,
    /// `ECDSA P-521`, `RSA 3072` or `RSA 4096`.
    pub kind: String,
    /// `SHA256:` and the unpadded base64, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
    /// The OpenSSH public line, without a line end.
    pub public_key: String,
}

/// INT-06.E24.03's labelled error: the comment is refused, never rewritten.
pub const MSG_SSH_COMMENT: &str = "The public comment can have at most 256 bytes on one line, with no control or text direction characters.";
/// INT-06.E24.29's `Key not saved`, when the OS random source failed.
pub const MSG_SSH_RANDOM: &str = "Key not saved. The system random source failed.";
/// The key could not be made or encoded (no reason holds key bytes).
pub const MSG_SSH_FAILED: &str = "Key not saved. The key could not be made.";
/// INT-06.E24.06: the editor closed, changed or cancelled meanwhile.
pub const MSG_SSH_STALE: &str =
    "Key not saved. The editor closed or changed while the key was made.";
/// INT-06.E24.04: the entry already has a key; a new one never replaces it.
pub const MSG_SSH_HAS_KEY: &str = "This entry already has an SSH key. A new key never replaces it.";

/// Refused when the entry shows a key already (the rule that hides New SSH
/// Key in the editor: [`ssh_key`] picks one), has SSH settings or has an
/// attachment of a name the key's files take. The settings' name is never
/// shown (AGENTS rule 1).
fn blocked(e: &Entry, kind: NewKeyKind) -> Result<(), LarsalError> {
    if ssh_key(e).is_some() {
        return Err(LarsalError::Refused(MSG_SSH_HAS_KEY.to_owned()));
    }
    let Some(name) = larsal_sshagent::new_key_blocked(e, kind.file_name()) else {
        return Ok(());
    };
    let public = format!("{}.pub", kind.file_name());
    Err(LarsalError::Refused(
        if name == kind.file_name() || name == public {
            format!(
                "This entry already has an attachment named “{name}”. Rename or remove it first."
            )
        } else {
            MSG_SSH_HAS_KEY.to_owned()
        },
    ))
}

#[uniffi::export]
impl Session {
    /// Generate and Add Key (INT-06.E24.01 to .04, .06): checks `comment`
    /// (`MSG_SSH_COMMENT`) and the draft (no key shown, no SSH settings, no
    /// attachment of the key's names), makes the key from the OS random
    /// source off the session lock (seconds for RSA: call it off the screen
    /// thread), then, if the draft is still at the revision taken here (no
    /// change since, the vault still open and unlocked), adds the private
    /// key, its public line and the SSH settings (larsal-sshagent's
    /// `new_key_files`) and commits the editor as [`Session::commit_edit`]
    /// does. The editor is then closed. The caller saves the vault and shows
    /// the key saved only when that save succeeded.
    ///
    /// # Errors
    /// `Refused` with `MSG_SSH_COMMENT`, `MSG_SSH_HAS_KEY`, the attachment
    /// in the way, `MSG_SSH_RANDOM`, `MSG_SSH_FAILED`, `MSG_SSH_STALE` (the
    /// draft changed, cancelled or replaced, no editor, or the vault locked
    /// or closed while the key was made) or the core's reason at commit
    /// (the draft then stays open without the key); `UnknownVault`, `Locked`
    /// before the key is made. On every error nothing changed and the key
    /// is wiped.
    pub fn new_ssh_key(
        &self,
        vault: u64,
        kind: SshKeyKind,
        comment: String,
    ) -> Result<NewSshKeyView, LarsalError> {
        if !comment_ok(&comment) {
            return Err(LarsalError::Refused(MSG_SSH_COMMENT.to_owned()));
        }
        let kind = NewKeyKind::from(kind);
        let revision = self.with_draft(vault, |_, d| {
            blocked(&d.entry, kind)?;
            Ok(d.revision)
        })?;
        let key = new_key(kind, &comment).map_err(|e| {
            LarsalError::Refused(
                if e == larsal_crypto::Error::RandomSource {
                    MSG_SSH_RANDOM
                } else {
                    MSG_SSH_FAILED
                }
                .to_owned(),
            )
        })?;
        let (public_key, fingerprint) =
            (key.public_line().to_owned(), key.fingerprint().to_owned());
        #[cfg(test)]
        tests::gate();
        let late = self.with_edit(vault, |v, _, rated, state| {
            // INT-06.E24.06: the draft of the request, unchanged since. Its
            // entry is the one checked above, so nothing is checked again.
            let d = state
                .draft
                .as_mut()
                .filter(|d| d.revision == revision)
                .ok_or_else(|| LarsalError::Refused(MSG_SSH_STALE.to_owned()))?;
            let mut ready = Vec::new();
            for (name, data) in larsal_sshagent::new_key_files(key) {
                let limits = attachments::Limits::DEFAULT;
                ready.push(
                    attachments::prepare(v, &d.entry, &name, data, &limits)
                        .map_err(|e| refused(&e))?,
                );
            }
            let names: Vec<String> = ready.iter().map(|a| a.name.clone()).collect();
            for a in ready {
                attachments::put(&mut d.entry, a);
            }
            match commit_draft(v, rated, state) {
                Ok(entry) => Ok(NewSshKeyView {
                    entry,
                    attachment: kind.file_name().to_owned(),
                    kind: kind.label().to_owned(),
                    fingerprint,
                    public_key,
                }),
                Err(e) => {
                    // The draft stays open as it was before the key.
                    if let Some(d) = state.draft.as_mut() {
                        let names: Vec<&str> = names.iter().map(String::as_str).collect();
                        attachments::remove(&mut d.entry, &names);
                    }
                    Err(e)
                }
            }
        });
        late.map_err(|e| match e {
            LarsalError::Locked | LarsalError::UnknownVault => {
                LarsalError::Refused(MSG_SSH_STALE.to_owned())
            }
            e => e,
        })
    }

    /// Cancel while the key is made (INT-06.E24.04, .06): that key is thrown
    /// away (wiped) when it is done; the draft stays open, unchanged.
    pub fn cancel_new_ssh_key(&self, vault: u64) {
        let _ = self.with_draft(vault, |_, d| {
            d.touch();
            Ok(())
        });
    }

    /// Copy Public Key (INT-06.E24.05): entry `entry`'s OpenSSH public line,
    /// copied under Copy's APP-03 rules. Public; nothing private is read.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `UnknownField` without a
    /// public key; `NotAvailable` when the clipboard could not be written.
    pub fn copy_ssh_public_key(&self, vault: u64, entry: String) -> Result<Copied, LarsalError> {
        self.with_vault(vault, |v| {
            let line = ssh_public_line(entry_of(v, &entry)?).ok_or(LarsalError::UnknownField)?;
            self.copy_value("Public key".to_owned(), &line)
        })
    }

    /// Save Public Key… (INT-06.E24.05): the public line of the key entry
    /// `entry` shows, with a line end, written into `folder` under that key's
    /// `.pub` name (its attachment's name, `.pub` added when missing; `/`,
    /// `\` and `:` removed), as Save… writes an attachment: 0600, one step,
    /// no link followed. Returns false, writing nothing, when that file
    /// exists and `overwrite` is off: the screen asks, then calls again.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `UnknownField` without a
    /// public key; `TooLong`; `Refused` when the file cannot be written.
    pub fn save_ssh_public_key(
        &self,
        vault: u64,
        entry: String,
        folder: String,
        overwrite: bool,
    ) -> Result<bool, LarsalError> {
        if folder.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let (name, line) = self.with_vault(vault, |v| {
            let key = ssh_public(entry_of(v, &entry)?).ok_or(LarsalError::UnknownField)?;
            let name = key.name.strip_suffix(".pub").unwrap_or(key.name);
            Ok((
                format!("{name}.pub"),
                key.line.ok_or(LarsalError::UnknownField)?,
            ))
        })?;
        let file: String = name
            .chars()
            .filter(|c| !matches!(c, '/' | '\\' | ':'))
            .collect();
        if file.is_empty() || file == "." || file == ".." {
            return Err(LarsalError::Refused(format!(
                "“{name}” cannot be saved under that name."
            )));
        }
        save_named(
            &name,
            &file,
            &folder,
            format!("{line}\n").as_bytes(),
            overwrite,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex, PoisonError};

    /// Set by a race test: New SSH Key stops there twice after the key is
    /// made, before it goes back under the session lock.
    static GATE: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);
    /// One race at a time (the gate is the process's).
    static ONE: Mutex<()> = Mutex::new(());

    pub(super) fn gate() {
        let g = GATE.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(b) = g {
            b.wait();
            b.wait();
        }
    }

    /// Where [`personal`] puts its copy for `tag`.
    fn vault_file(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("larsal-ffi-{tag}-{}", std::process::id()))
            .join("Personal.larsalvault")
    }

    /// A fresh copy of the Personal demo vault, unlocked in a new session.
    fn personal(tag: &str) -> (Arc<Session>, u64) {
        let path = vault_file(tag);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        (s, v)
    }

    fn id_of(s: &Session, v: u64, title: &str) -> String {
        s.list(v, crate::views::ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == title)
            .unwrap()
            .id
    }

    /// New SSH Key on a thread, held after its key is made while `between`
    /// runs, then let go.
    fn race(
        s: &Arc<Session>,
        v: u64,
        between: impl FnOnce(),
    ) -> Result<NewSshKeyView, LarsalError> {
        let _one = ONE.lock().unwrap_or_else(PoisonError::into_inner);
        let b = Arc::new(Barrier::new(2));
        *GATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&b));
        let s2 = Arc::clone(s);
        let h = std::thread::spawn(move || s2.new_ssh_key(v, SshKeyKind::Ed25519, "demo".into()));
        b.wait();
        between();
        *GATE.lock().unwrap_or_else(PoisonError::into_inner) = None;
        b.wait();
        h.join().unwrap()
    }

    fn stale() -> Result<NewSshKeyView, LarsalError> {
        Err(LarsalError::Refused(MSG_SSH_STALE.to_owned()))
    }

    #[test]
    fn e24_s06_cancel_while_the_key_is_made_drops_it_and_changes_nothing() {
        let (s, v) = personal("e24-cancel");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let before = s.editor(v).unwrap();
        assert_eq!(race(&s, v, || s.cancel_new_ssh_key(v)), stale());
        assert!(s.has_draft(v), "the editor stays open");
        assert_eq!(s.editor(v).unwrap().attachments, before.attachments);
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        // A new start after the cancel works.
        let _one = ONE.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(s.new_ssh_key(v, SshKeyKind::Ed25519, String::new()).is_ok());
    }

    #[test]
    fn e24_s06_another_draft_while_the_key_is_made_gets_nothing() {
        let (s, v) = personal("e24-other");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let wise = id_of(&s, v, "Wise");
        let result = race(&s, v, || {
            s.cancel_edit(v).unwrap();
            s.begin_edit(v, wise.clone()).unwrap();
        });
        assert_eq!(result, stale());
        assert!(
            s.editor(v).unwrap().attachments.is_empty(),
            "not the new draft"
        );
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        // The other editor closed meanwhile: nothing either.
        let result = race(&s, v, || s.cancel_edit(v).unwrap());
        assert_eq!(result, Err(LarsalError::Refused(MSG_SSH_STALE.to_owned())));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
    }

    #[test]
    fn e24_s06_a_lock_while_the_key_is_made_drops_it() {
        let (s, v) = personal("e24-lock");
        let github = id_of(&s, v, "GitHub");
        s.begin_edit(v, github.clone()).unwrap();
        let result = race(&s, v, || s.lock(v).unwrap());
        assert_eq!(result, stale(), "a locked vault gets nothing");
        assert!(!s.has_draft(v), "the lock dropped the draft");
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        assert!(s.entry(v, github).unwrap().ssh.is_none());
    }

    /// E24-S06 (lead ruling (3), INT-06.E24.06): a change to the draft while
    /// the key is made (here the title) moves its revision: the late key is
    /// dropped, nothing is committed, the change stays in the editor.
    #[test]
    fn e24_s06_a_title_changed_while_the_key_is_made_drops_it() {
        let (s, v) = personal("e24-title");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let before = s.editor(v).unwrap();
        let result = race(&s, v, || {
            s.set_text(v, crate::edit::EditText::Title, "Changed".into())
                .unwrap();
        });
        assert_eq!(result, stale());
        let after = s.editor(v).unwrap();
        assert_eq!(after.title, "Changed", "the change stays");
        assert_eq!(after.attachments, before.attachments, "no key joined");
        assert!(s.has_draft(v), "the editor stays open");
        assert_eq!(s.save_status(v).unwrap().changes, 0, "nothing committed");
    }

    /// E24-S06 (lead ruling (3)): reading the draft while the key is made
    /// (the screen draws the editor) moves no revision: the key joins.
    #[test]
    fn e24_s06_reads_while_the_key_is_made_keep_the_revision() {
        let (s, v) = personal("e24-reads");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let result = race(&s, v, || {
            s.editor(v).unwrap();
            s.draft_password(v).unwrap();
            s.draft_code(v).unwrap();
            s.totp_setup(v).unwrap();
        });
        let view = result.expect("the key joins");
        assert!(!s.has_draft(v), "committed: the editor closed");
        assert_eq!(s.save_status(v).unwrap().changes, 1);
        let shown = s.entry(v, view.entry).unwrap().ssh.unwrap();
        assert_eq!(shown.fingerprint, view.fingerprint);
    }

    /// E24-S04, E24-S06 (Checker 1 C1-F3, lead ruling (3)): an attachment of
    /// the key's own name added to the draft while the key is made moves its
    /// revision: the late key is refused as stale and that attachment stays
    /// as it was.
    #[test]
    fn e24_s04_s06_c1_a_name_taken_while_the_key_is_made_is_refused_and_kept() {
        let (s, v) = personal("c1-e24-taken");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "larsal-ffi-c1-e24-taken-src-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let own: &[u8] = b"a demo file of this name, not a key";
        std::fs::write(dir.join("id_ed25519"), own).unwrap();
        let file = dir.join("id_ed25519").to_string_lossy().into_owned();
        let result = race(&s, v, || s.attach_file(v, file.clone()).unwrap());
        let after = s.editor(v).unwrap();
        assert_eq!(result, stale(), "refused, nothing committed");
        let kept = after
            .attachments
            .iter()
            .find(|a| a.name == "id_ed25519")
            .map(|a| a.size);
        assert_eq!(
            kept,
            Some(own.len() as u64),
            "the attachment added meanwhile is kept"
        );
        assert!(after.attachments.iter().all(|a| a.name != "id_ed25519.pub"));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
    }

    /// E24-S06 (lead ruling (3)): an attachment removed from the draft while
    /// the key is made moves its revision: the late key is dropped and the
    /// removal stays.
    #[test]
    fn e24_s06_an_attachment_removed_while_the_key_is_made_drops_it() {
        let (s, v) = personal("e24-removed");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let source = vault_file("e24-removed").with_file_name("notes.txt");
        std::fs::write(&source, b"demo notes").unwrap();
        s.attach_file(v, source.to_string_lossy().into_owned())
            .unwrap();
        let result = race(&s, v, || {
            s.remove_attachment(v, "notes.txt".into()).unwrap();
        });
        assert_eq!(result, stale());
        let after = s.editor(v).unwrap();
        assert!(after.attachments.iter().all(|a| a.name != "notes.txt"));
        assert!(after.attachments.iter().all(|a| a.name != "id_ed25519"));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
    }

    /// E24-S06 (lead ruling (3)): a changed attachment taken back into the
    /// draft while the key is made moves its revision: the late key is
    /// dropped and the taken change stays.
    #[test]
    fn e24_s06_a_changed_attachment_taken_while_the_key_is_made_drops_it() {
        let (s, v) = personal("e24-taken-back");
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let source = vault_file("e24-taken-back").with_file_name("codes.txt");
        std::fs::write(&source, b"first").unwrap();
        s.attach_file(v, source.to_string_lossy().into_owned())
            .unwrap();
        let crate::edit::OpenAttachment::Opened { path: copy } =
            s.open_attachment(v, "codes.txt".into(), false).unwrap()
        else {
            panic!("opened")
        };
        std::fs::write(&copy, b"second edit").unwrap();
        let result = race(&s, v, || {
            s.take_changed_attachment(v, "codes.txt".into(), true)
                .unwrap();
        });
        assert_eq!(result, stale());
        let after = s.editor(v).unwrap();
        let size = after
            .attachments
            .iter()
            .find(|a| a.name == "codes.txt")
            .map(|a| a.size);
        assert_eq!(size, Some(11), "the taken change stays");
        assert!(after.attachments.iter().all(|a| a.name != "id_ed25519"));
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        s.cancel_edit(v).unwrap();
    }

    /// E24-S06 (lead ruling (3)): a commit that fails after it put the title
    /// on one line changed the open draft, so its revision moves: a key made
    /// meanwhile is dropped, not committed with that title.
    #[test]
    fn e24_s06_a_failed_commit_that_screens_the_title_drops_the_late_key() {
        let (s, v) = personal("e24-screened");
        let group = s
            .add_group(v, None, "Demo servers".into(), 0, None)
            .unwrap();
        s.begin_new(v, Some(group)).unwrap();
        s.set_text(v, crate::edit::EditText::Title, "Demo\nserver".into())
            .unwrap();
        let result = race(&s, v, || {
            // The draft's group goes for a moment, so the commit fails after
            // it screened the title; then the group comes back.
            let taken = s
                .with_edit(v, |vault, _, _, _| Ok(vault.root.groups.pop()))
                .unwrap()
                .unwrap();
            assert_eq!(taken.name, "Demo servers");
            assert!(s.commit_edit(v).is_err(), "no group for the entry");
            s.with_edit(v, |vault, _, _, _| {
                vault.root.groups.push(taken);
                Ok(())
            })
            .unwrap();
        });
        assert_eq!(result, stale());
        let after = s.editor(v).unwrap();
        assert_eq!(after.title, "Demo server", "the screened title stays");
        assert!(after.attachments.iter().all(|a| a.name != "id_ed25519"));
        assert!(s.has_draft(v), "the editor stays open");
        assert_eq!(s.save_status(v).unwrap().changes, 1, "the new group only");
    }

    /// Puts the OS source back however the test ends.
    struct SourceDown;

    impl Drop for SourceDown {
        fn drop(&mut self) {
            larsal_crypto::random::test_os_source_down(false);
        }
    }

    /// E24-S02 (Checker 1 C1-F4, lead ruling (4)): a failed OS random source
    /// makes no key and saves nothing: `MSG_SSH_RANDOM`, the draft and the
    /// vault file as they were.
    #[test]
    fn e24_s02_c1_a_failed_random_source_makes_no_key_and_saves_nothing() {
        let _one = ONE.lock().unwrap_or_else(PoisonError::into_inner);
        let (s, v) = personal("e24-random");
        let file = std::fs::read(vault_file("e24-random")).unwrap();
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let before = s.editor(v).unwrap();
        for kind in [
            SshKeyKind::Ed25519,
            SshKeyKind::EcdsaP256,
            SshKeyKind::Rsa3072,
        ] {
            let down = SourceDown;
            assert!(!larsal_crypto::random::test_os_source_down(true));
            let result = s.new_ssh_key(v, kind, "demo".into());
            drop(down);
            assert_eq!(
                result,
                Err(LarsalError::Refused(MSG_SSH_RANDOM.to_owned())),
                "{kind:?}"
            );
            assert_eq!(s.editor(v).unwrap().attachments, before.attachments);
            assert!(s.has_draft(v), "the editor stays open");
            assert_eq!(s.save_status(v).unwrap().changes, 0);
        }
        assert_eq!(
            std::fs::read(vault_file("e24-random")).unwrap(),
            file,
            "the vault file as it was"
        );
        // The source works again: the key is made.
        assert!(s.new_ssh_key(v, SshKeyKind::Ed25519, "demo".into()).is_ok());
    }

    // ---------------------------------------- rule 4 (E24-S2, round 3)

    const MASK: u8 = 0x5a;
    /// Set only in the process a stack test starts for its child.
    const CHILD: &str = "LARSAL_E24_FFI_STACK_CHILD";

    /// One length-prefixed string of the SSH wire form, taken off `rest`.
    fn wire<'a>(rest: &mut &'a [u8]) -> &'a [u8] {
        let (len, tail) = rest.split_at(4);
        let (s, tail) = tail.split_at(u32::from_be_bytes(len.try_into().unwrap()) as usize);
        *rest = tail;
        s
    }

    /// The private values of a one-key unprotected `openssh-key-v1` text,
    /// each byte XOR `MASK`: the Ed25519 seed, or d at the curve's size in
    /// big-endian and little-endian order.
    fn masked_values(text: &[u8]) -> Vec<Vec<u8>> {
        let body: String = std::str::from_utf8(text)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, body).unwrap();
        let mut rest = raw.strip_prefix(b"openssh-key-v1\0".as_slice()).unwrap();
        for _ in 0..3 {
            wire(&mut rest); // cipher, KDF, KDF options
        }
        rest = &rest[4..]; // one key
        wire(&mut rest); // the public key
        let mut private = wire(&mut rest);
        private = &private[8..]; // the two check values
        let masked = |b: &[u8]| -> Vec<u8> { b.iter().map(|x| x ^ MASK).collect() };
        let kind = wire(&mut private);
        if kind == b"ssh-ed25519" {
            wire(&mut private);
            return vec![masked(&wire(&mut private)[..32])];
        }
        let size = match wire(&mut private) {
            b"nistp256" => 32,
            b"nistp384" => 48,
            _ => 66,
        };
        wire(&mut private); // Q
        let d = wire(&mut private);
        let d = d.strip_prefix(&[0]).unwrap_or(d);
        let mut be = vec![MASK; size - d.len()];
        be.extend(masked(d));
        let mut le = be.clone();
        le.reverse();
        vec![be, le]
    }

    /// `f` with the text of the key New SSH Key saved for `view`, on a thread
    /// of its own that ends (its stack is gone) before the caller counts.
    fn with_key_text<T: Send>(
        s: &Session,
        v: u64,
        view: &NewSshKeyView,
        f: impl Fn(&[u8]) -> T + Sync,
    ) -> T {
        std::thread::scope(|t| {
            t.spawn(|| {
                s.with_vault(v, |vault| {
                    let entry = entry_of(vault, &view.entry)?;
                    let a = entry.attachments.iter().find(|a| a.name == view.attachment);
                    Ok(f(a.ok_or(LarsalError::UnknownField)?.data.expose()))
                })
            })
            .join()
            .unwrap()
            .unwrap()
        })
    }

    /// The child: New SSH Key of `kind` on GitHub's draft through the bridge
    /// call on this thread; once it returned, the copies of the key's seed or
    /// d in all writable memory (the vault holds only the key's text). Then,
    /// as a control, the same markers while E9 holds that key parsed.
    fn stack_after_new_ssh_key(kind: SshKeyKind) {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let (s, v) = personal(&format!("e24-stack-{kind:?}"));
        s.begin_edit(v, id_of(&s, v, "GitHub")).unwrap();
        let view = s.new_ssh_key(v, kind, "demo@larsal".into()).unwrap();
        let count = |m: &[Vec<u8>]| -> Vec<usize> {
            m.iter()
                .map(|m| larsal_platform::memory::copies_in_memory(m, MASK))
                .collect()
        };
        let markers = with_key_text(&s, v, &view, masked_values);
        let left = count(&markers);
        // The control: E9's parse of that text, alive while the count runs.
        let parsed = with_key_text(&s, v, &view, |text| {
            let key = larsal_crypto::ssh::OpenSshKey::parse(text);
            count(&markers)[0] * usize::from(key.is_some())
        });
        println!(
            "ROW {kind:?} new_ssh_key: after the call {left:?}; while E9 holds the key parsed {parsed}"
        );
        assert!(parsed > 0, "the markers find a live key");
        assert!(
            left.iter().all(|&n| n == 0),
            "{kind:?}: copies left after new_ssh_key: {left:?}"
        );
    }

    /// Runs `child` alone in a new process of this program.
    fn alone(child: &str) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                child,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("{text}");
        assert!(
            out.status.success() && text.contains("1 passed") && text.contains("ROW "),
            "{child}:\n{text}"
        );
    }

    #[test]
    #[ignore = "a child of e24_s02_rule4_int06_e24_02_ed25519_seed_leaves_no_copy_after_new_ssh_key"]
    fn stack_child_ed25519() {
        stack_after_new_ssh_key(SshKeyKind::Ed25519);
    }

    #[test]
    #[ignore = "a child of e24_s02_rule4_int06_e24_02_p256_scalar_leaves_no_copy_after_new_ssh_key"]
    fn stack_child_p256() {
        stack_after_new_ssh_key(SshKeyKind::EcdsaP256);
    }

    #[test]
    #[ignore = "a child of e24_s02_rule4_int06_e24_02_p384_scalar_leaves_no_copy_after_new_ssh_key"]
    fn stack_child_p384() {
        stack_after_new_ssh_key(SshKeyKind::EcdsaP384);
    }

    #[test]
    #[ignore = "a child of e24_s02_rule4_int06_e24_02_p521_scalar_leaves_no_copy_after_new_ssh_key"]
    fn stack_child_p521() {
        stack_after_new_ssh_key(SshKeyKind::EcdsaP521);
    }

    /// E24-S02, rule 4, INT-06.E24.02 (lead rulings (9), (10) of round 3):
    /// New SSH Key's bridge call moves only the key's pointer: once it
    /// returned, no copy of the Ed25519 seed is left on the calling thread's
    /// stack or anywhere. The count reads all memory: the child runs alone.
    #[test]
    fn e24_s02_rule4_int06_e24_02_ed25519_seed_leaves_no_copy_after_new_ssh_key() {
        alone("edit::ssh_new::tests::stack_child_ed25519");
    }

    /// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-256 key's d.
    #[test]
    fn e24_s02_rule4_int06_e24_02_p256_scalar_leaves_no_copy_after_new_ssh_key() {
        alone("edit::ssh_new::tests::stack_child_p256");
    }

    /// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-384 key's d.
    #[test]
    fn e24_s02_rule4_int06_e24_02_p384_scalar_leaves_no_copy_after_new_ssh_key() {
        alone("edit::ssh_new::tests::stack_child_p384");
    }

    /// E24-S02, rule 4, INT-06.E24.02: the same for an ECDSA P-521 key's d.
    #[test]
    fn e24_s02_rule4_int06_e24_02_p521_scalar_leaves_no_copy_after_new_ssh_key() {
        alone("edit::ssh_new::tests::stack_child_p521");
    }
}
