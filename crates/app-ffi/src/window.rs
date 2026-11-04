//! The window's small calls of E13-S6 part d: what shows once after an
//! unlock (the expiry notice, MOD-09.7 and APP-01.18; the key change
//! reminder, MOD-13.7 to MOD-13.10), the end of the forced key change
//! prompt (MOD-13.8), the clipboard countdown's time left for lock on
//! minimize (APP-02.8), and the attachment preview (MOD-05.9, L05-3,
//! LD-65).
//!
//! No export returns a secret except the preview, a Show value the user
//! asked for (LD-220 (1)); Swift drops it when the preview closes.

use crate::session::{AppError, Session};
use crate::views::{Offset, entry_of, now};
use app_core::expiry::{self, NoticeSettings};
use app_core::settings::{Reminder, reminder};
use app_core::time::Instant;
use app_core::{attachments, icons};
use app_model::Meta;

/// What the window shows once after an unlock (MOD-09.7, MOD-13.10).
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct AfterUnlock {
    /// MOD-09.7: the text for the search field, `is:expired-N`; `None`
    /// when nothing is due or the notice is off.
    pub expiry_search: Option<String>,
    /// `MSG-09-1` or `MSG-09-2`: the title of those results.
    pub expiry_title: Option<String>,
    /// MOD-13.10 `keychange.msg.recommended`; `None` when no change is
    /// recommended.
    pub key_change: Option<String>,
    /// APP-05.26: the rollback guard's warning of the unlock read,
    /// `MSG-DISK-ROLLBACK-UNLOCK` or `MSG-DISK-WEAKER`; `None` when the
    /// file is neither older nor weaker than App has seen.
    pub disk_notice: Option<String>,
}

/// What Preview shows of one attachment (MOD-05.9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentPreview {
    /// A PNG or ICO image, decoded with App's limits and re-encoded as PNG
    /// in Rust at its own size, at most 4,096 pixels a side (LD-65, LD-109).
    Image {
        /// The PNG bytes Rust wrote.
        png: Vec<u8>,
    },
    /// Text, plain only (L05-3 (b)): HTML and Markdown are not rendered,
    /// so no script runs, nothing loads and no link is followed. The first
    /// MiB.
    Text {
        /// The text.
        text: String,
    },
    /// Any other type: the preview says it cannot be shown.
    Unsupported,
}

/// The longest text a preview shows, in bytes.
const PREVIEW_TEXT: usize = 1 << 20;

fn days(n: i64) -> String {
    if n == 1 {
        "1 day".to_owned()
    } else {
        format!("{n} days")
    }
}

/// MOD-13.8 `keychange.msg.forced`: the prompt's words, or `None` when no
/// change is required now (MOD-13.4 to MOD-13.6). Day counts only.
pub(crate) fn forced(meta: &Meta) -> Option<String> {
    match reminder(meta, now()) {
        Reminder::Forced { every: None, .. } => Some(
            "This vault requires a new master key: it asks for a change at this unlock.".to_owned(),
        ),
        Reminder::Forced {
            days: n,
            every: Some(f),
        } => Some(format!(
            "This vault requires a new master key: it was last changed {} ago, and it requires a change every {}.",
            days(n),
            days(f.into())
        )),
        _ => None,
    }
}

/// MOD-05.9: an image through the Rust decoder, text as plain text, else
/// the note.
fn preview(data: &[u8]) -> AttachmentPreview {
    if let Some(png) = icons::decode(data, &icons::FullSize, &icons::Limits::DEFAULT) {
        return AttachmentPreview::Image { png };
    }
    if attachments::is_text(attachments::sniff(data)) {
        let cut = data.get(..PREVIEW_TEXT).unwrap_or(data);
        return AttachmentPreview::Text {
            text: String::from_utf8_lossy(cut).into_owned(),
        };
    }
    AttachmentPreview::Unsupported
}

#[uniffi::export]
impl Session {
    /// Takes vault `vault`'s notices once after an unlock (MOD-13.7): the
    /// expiry notice on the first unlock since the vault was opened, with
    /// S-START-11 and S-START-12 (MOD-09.7, APP-01.18), over the whole vault
    /// with `utc_offset` (seconds east of UTC) for the day count; and the
    /// recommended key change (MOD-13.10). Empty on every later call, and
    /// while the forced prompt waits (the notices come after it ends). No
    /// vault text.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn after_unlock(&self, vault: u64, utc_offset: i32) -> Result<AfterUnlock, AppError> {
        let Some(first) = self.take_fresh(vault)? else {
            return Ok(AfterUnlock::default());
        };
        let settings = NoticeSettings {
            on: self.settings.flag("expiry.notice_on_unlock".to_owned()),
            days: u32::try_from(self.settings.number("expiry.notice_days".to_owned())).unwrap_or(0),
        };
        let disk_notice = self.with_draft_state(vault, |_, s| Ok(s.notice.take()))?;
        self.with_vault(vault, |v| {
            let at = now();
            let notice = expiry::notice(
                v,
                settings,
                first,
                Instant::from(at),
                &Offset(utc_offset.into()),
            );
            let key_change = match reminder(&v.meta, at) {
                Reminder::Recommended { days: n, every } => Some(format!(
                    "The master key was last changed {} ago; a change every {} is recommended.",
                    days(n),
                    days(every.into())
                )),
                _ => None,
            };
            Ok(AfterUnlock {
                expiry_title: notice.as_ref().map(|n| {
                    if n.days == 0 {
                        "Expired entries".to_owned()
                    } else {
                        format!("Expired or due to expire in {}", days(n.days.into()))
                    }
                }),
                expiry_search: notice.map(|n| n.search),
                key_change,
                disk_notice,
            })
        })
    }

    /// MOD-13.8: the credentials sheet of the forced prompt closed. True
    /// when the vault no longer requires a change: it opens normally and
    /// the SSH keys its unlock held back are added (INT-06); false while
    /// the prompt stays (Cancel returns to it).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`.
    pub fn end_key_change(&self, vault: u64) -> Result<bool, AppError> {
        self.end_forced(vault)
    }

    /// APP-02.8 `r` (F-078): whole seconds left on App's clipboard
    /// countdown, rounded up; 0 when none runs. No value.
    #[must_use]
    pub fn clipboard_seconds_left(&self) -> u32 {
        u32::try_from(self.clipboard.seconds_left()).unwrap_or(u32::MAX)
    }

    /// MOD-05.9 Preview of attachment `name` of entry `entry`, inside App:
    /// a PNG or ICO image decoded and re-encoded in Rust (LD-65), text as
    /// plain text (L05-3 (b): no markup, no link), else a note. A crossing
    /// of LD-220: the Show value the user asked for.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`, `UnknownField`.
    pub fn preview_attachment(
        &self,
        vault: u64,
        entry: String,
        name: String,
    ) -> Result<AttachmentPreview, AppError> {
        self.with_vault(vault, |v| {
            let e = entry_of(v, &entry)?;
            let a = attachments::find(e, &name).ok_or(AppError::UnknownField)?;
            Ok(preview(a.data.expose()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_settings::{AppSetting, AppSettingValue};
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use crate::vault_settings::VaultSettings;
    use crate::views::{ListView, hex};
    use crate::wizard::Outcome;
    use app_model::{Entry, Group, Time};
    use std::path::Path;
    use std::sync::Arc;

    const DAY: i64 = 86_400;

    /// A fresh copy of the Personal demo vault (testdata/README.md) in the
    /// test's own folder, removed when the value drops (LD-240 (5)).
    fn copy(tag: &str) -> TempDir {
        let path = TempDir::new(&format!("window-{tag}")).file(&format!("{tag}.appvault"));
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.appvault"
            ),
            &path,
        )
        .unwrap();
        path
    }

    fn unlock(path: &Path) -> (Arc<Session>, u64) {
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(
            s.unlock(v, Some("demo-pass-7".into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        (s, v)
    }

    fn each(g: &mut Group, f: &mut impl FnMut(&mut Entry)) {
        g.entries.iter_mut().for_each(&mut *f);
        for sub in &mut g.groups {
            each(sub, f);
        }
    }

    /// Changes the vault file at `path` with `f`, saved.
    fn change(path: &Path, f: impl FnOnce(&mut app_model::Vault)) {
        let (s, v) = unlock(path);
        s.with_edit(v, |vault, _, _, _| {
            f(vault);
            Ok(())
        })
        .unwrap();
        assert!(s.save(v).unwrap().failure.is_none());
    }

    fn set(s: &Session, key: &str, value: AppSettingValue) {
        s.save_settings(vec![AppSetting {
            key: key.to_owned(),
            value,
        }])
        .unwrap();
    }

    /// F-077, APP-01.18 a to c, MOD-09.7: the notice on the first unlock
    /// only, over the whole vault; N = 0 lists the expired entries only.
    #[test]
    fn f_077_expiry_notice_after_the_first_unlock() {
        let path = copy("expiry");
        let at = now().0;
        let mut ids = Vec::new();
        change(&path, |v| {
            let mut n = 0i64;
            each(&mut v.root, &mut |e| {
                e.times.expires = false;
                // Old: 5 days ago; Soon: in 2 days; Later: in 40 days.
                if let Some(shift) = [-5, 2, 40].get(usize::try_from(n).unwrap_or(9)) {
                    e.times.expires = true;
                    e.times.expiry = Time(at + shift * DAY);
                    ids.push(hex(e.uuid));
                }
                n += 1;
            });
        });
        let (old, soon) = (ids[0].clone(), ids[1].clone());
        let (s, v) = unlock(&path);
        let after = s.after_unlock(v, 0).unwrap();
        assert_eq!(after.expiry_search.as_deref(), Some("is:expired-3"));
        assert_eq!(
            after.expiry_title.as_deref(),
            Some("Expired or due to expire in 3 days")
        );
        let mut hits = s.search(v, "is:expired-3".into()).unwrap().ids;
        hits.sort();
        let mut want = vec![old.clone(), soon];
        want.sort();
        assert_eq!(hits, want, "a: Old and Soon");
        assert_eq!(
            s.after_unlock(v, 0).unwrap(),
            AfterUnlock::default(),
            "once"
        );
        // b: lock, unlock: no notice.
        s.lock(v).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(s.after_unlock(v, 0).unwrap().expiry_search, None, "b");
        // c: S-START-12 = 0, first unlock: the expired entries only.
        let s = Session::new();
        set(
            &s,
            "expiry.notice_days",
            AppSettingValue::Number { value: 0 },
        );
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let after = s.after_unlock(v, 0).unwrap();
        assert_eq!(after.expiry_search.as_deref(), Some("is:expired-0"));
        assert_eq!(after.expiry_title.as_deref(), Some("Expired entries"));
        assert_eq!(s.search(v, "is:expired-0".into()).unwrap().ids, [old], "c");
        // S-START-11 off: none.
        let s = Session::new();
        set(
            &s,
            "expiry.notice_on_unlock",
            AppSettingValue::Flag { on: false },
        );
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(s.after_unlock(v, 0).unwrap(), AfterUnlock::default(), "off");
    }

    /// Makes testdata/option-a-work-key-change.appvault (testdata/README.md): the
    /// Work demo vault that asks for a key change at the next unlock.
    #[test]
    #[ignore = "writes testdata/option-a-work-key-change.appvault"]
    fn make_key_change_forced_vault() {
        let dir = std::env::temp_dir().join(format!("app-ffi-window-make-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Work.appvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-work.appvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-8".into()), None).unwrap();
        s.with_edit(v, |vault, _, _, _| {
            vault.meta.master_key_change_force_once = true;
            Ok(())
        })
        .unwrap();
        assert!(s.save(v).unwrap().failure.is_none());
        std::fs::copy(
            &path,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-work-key-change.appvault"
            ),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// F-074, MOD-13.8, T13 to T15: while a change is forced the vault
    /// counts as locked for Auto-Type and the SSH agents and the window gets
    /// the prompt; the notices wait. A changed key ends it; Lock ends it too.
    #[test]
    fn f_074_forced_key_change_counts_as_locked_until_changed() {
        let path = copy("forced");
        change(&path, |v| v.meta.master_key_change_force_once = true);
        let (s, v) = unlock(&path);
        let info = &s.vaults()[0];
        assert!(!info.locked);
        assert_eq!(
            info.key_change.as_deref(),
            Some("This vault requires a new master key: it asks for a change at this unlock.")
        );
        assert!(
            s.with_slots(|slots, _| slots[0].1.is_none()),
            "Auto-Type: locked"
        );
        assert_eq!(s.after_unlock(v, 0).unwrap(), AfterUnlock::default());
        assert!(!s.end_key_change(v).unwrap(), "no change yet");
        // Change now: the credentials sheet changes the password.
        let settings = VaultSettings::new(Arc::clone(&s), v);
        settings
            .set_password("orchid-meteor-pine-quartz-41".into())
            .unwrap();
        settings
            .set_repeat("orchid-meteor-pine-quartz-41".into())
            .unwrap();
        assert_eq!(settings.change_password(vec![]).unwrap(), Outcome::Done);
        assert!(s.end_key_change(v).unwrap(), "changed: opens");
        assert_eq!(s.vaults()[0].key_change, None);
        assert!(
            s.with_slots(|slots, _| slots[0].1.is_some()),
            "Auto-Type: open"
        );
        // T14: Lock ends the prompt; the next unlock shows it again.
        let (s, v) = unlock(&path);
        assert!(s.vaults()[0].key_change.is_some());
        s.lock(v).unwrap();
        assert!(s.vaults()[0].locked && s.vaults()[0].key_change.is_none());
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert!(s.vaults()[0].key_change.is_some(), "again");
        // MOD-13.6: the interval forces too, with its words.
        change(&path, |v| {
            v.meta.master_key_change_force_once = false;
            v.meta.master_key_change_force = 30;
            v.meta.master_key_changed = Time(now().0 - 45 * DAY);
        });
        let (s, _) = unlock(&path);
        assert_eq!(
            s.vaults()[0].key_change.as_deref(),
            Some(
                "This vault requires a new master key: it was last changed 45 days ago, and it requires a change every 30 days."
            )
        );
    }

    /// F-074, MOD-13.10, T17: the recommended notice after the vault opens,
    /// once per unlock, again after a lock and unlock; not forced.
    #[test]
    fn f_074_recommended_notice_once_per_unlock() {
        let path = copy("recommended");
        change(&path, |v| {
            v.meta.master_key_change_rec = 1;
            v.meta.master_key_changed = Time(now().0 - 10 * DAY);
        });
        let (s, v) = unlock(&path);
        assert_eq!(s.vaults()[0].key_change, None, "not forced");
        let words =
            "The master key was last changed 10 days ago; a change every 1 day is recommended.";
        assert_eq!(
            s.after_unlock(v, 0).unwrap().key_change.as_deref(),
            Some(words)
        );
        assert_eq!(s.after_unlock(v, 0).unwrap().key_change, None, "once");
        s.lock(v).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert_eq!(
            s.after_unlock(v, 0).unwrap().key_change.as_deref(),
            Some(words)
        );
    }

    /// F-078, APP-02.8: the session reports the countdown's seconds left
    /// after a copy; a lock clears it.
    #[test]
    fn f_078_session_reports_the_clipboard_countdown() {
        let path = copy("clipboard");
        let (s, v) = unlock(&path);
        assert_eq!(s.clipboard_seconds_left(), 0);
        let row = s.list(v, ListView::All).unwrap().rows.remove(0);
        s.copy_field(v, row.id, "UserName".into()).unwrap();
        let left = s.clipboard_seconds_left();
        assert!((9..=10).contains(&left), "{left}");
        s.lock(v).unwrap();
        assert_eq!(s.clipboard_seconds_left(), 0);
    }

    /// F-072, APP-06.18: a chosen key file's name comes back cleaned, so a
    /// U+202E in it never reverses the note.
    #[test]
    fn f_072_key_file_name_is_cleaned() {
        let dir = TempDir::new("window-key");
        let file = dir.join("evil\u{202E}gpj.appkey");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/key-xml-v1.appkey"
            ),
            &file,
        )
        .unwrap();
        let (_, name) = crate::session::read_key(Path::new(""), &file.to_string_lossy()).unwrap();
        assert_eq!(name, "evilgpj.appkey");
    }

    /// SD-13, MOD-05.9, L05-3, LD-65: images through the Rust decoder,
    /// HTML as plain text, other types a note.
    #[test]
    fn sd_13_preview_decodes_images_in_rust_and_shows_markup_as_plain_text() {
        use app_crypto::base64::{Form, decode};
        let png = decode(
            Form::Padded,
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
            .unwrap();
        let AttachmentPreview::Image { png: out } = preview(&png) else {
            panic!("not an image");
        };
        assert!(out.starts_with(b"\x89PNG\r\n\x1a\n"), "re-encoded as PNG");
        // A 400 × 100 PNG with a text chunk: its own size and shape, written
        // again by Rust (the chunk is gone), never the attachment's bytes.
        let wide = decode(
            Form::Padded,
            "iVBORw0KGgoAAAANSUhEUgAAAZAAAABkCAAAAACNoDmrAAAADHRFWHRDb21tZW50AGRlbW9ZXIpFAAAAoElEQVR42u3RAQ0AAAzCMKQjHRvP00lYU50qFgARECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAERECACAkRAgAgIEAEBIiACAkRAgAjI9wZ3RySTVJKqhwAAAABJRU5ErkJggg==")
            .unwrap();
        let AttachmentPreview::Image { png: out } = preview(&wide) else {
            panic!("not an image");
        };
        assert_eq!(
            icons::header_size(&out, icons::Format::Png),
            Some((400, 100))
        );
        assert!(!out.windows(4).any(|w| w == b"tEXt"), "re-encoded");
        let html = "<script>alert(1)</script><a href=\"https://evil.example\">x</a>";
        assert_eq!(
            preview(html.as_bytes()),
            AttachmentPreview::Text { text: html.into() },
            "the markup as text"
        );
        assert_eq!(
            preview(b"\xff\xd8\xff\xe0 jpeg"),
            AttachmentPreview::Unsupported
        );
        assert_eq!(preview(b"\x00\x01binary"), AttachmentPreview::Unsupported);
        let long = "a".repeat(PREVIEW_TEXT + 10);
        let AttachmentPreview::Text { text } = preview(long.as_bytes()) else {
            panic!("text");
        };
        assert_eq!(text.len(), PREVIEW_TEXT);
        // Over the session: an attachment of the Personal demo vault.
        let path = copy("preview");
        let (s, v) = unlock(&path);
        let entry = s
            .list(v, ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == "GitHub")
            .unwrap()
            .id;
        let detail = s.entry(v, entry.clone()).unwrap();
        let name = detail.attachments[0].name.clone();
        assert!(matches!(
            s.preview_attachment(v, entry.clone(), name).unwrap(),
            AttachmentPreview::Text { .. }
        ));
        assert_eq!(
            s.preview_attachment(v, entry, "none".into()),
            Err(AppError::UnknownField)
        );
    }
}
