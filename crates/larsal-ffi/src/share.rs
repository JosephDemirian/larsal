//! Shared groups (E11-S3, INT-08): the import and export passes of each
//! unlocked vault, their triggers, the approval records and the path guard,
//! over larsal-share.
//!
//! Guarantees:
//! - a share runs only when Larsal approved its mode and resolved path on this
//!   Mac (INT-08.31): a share item that arrived by a merge, an import or
//!   another app never imports, exports or is watched until then (AT-I04);
//! - a share whose resolved path is the file of any vault open in Larsal, a
//!   backup of one (F-269), or a key file this Mac knows, never runs
//!   (INT-08.34), and an export checks it again at its write, in the folder it
//!   really writes, so a folder swapped during the KDF gets nothing (F-162);
//! - an export replaces only what this share wrote or a container of it; any
//!   other file at its path is left alone (INT-08.34, `container::write_share`);
//! - every pass runs on a worker thread of its own, one per vault: the
//!   container's read and KDF run without the session lock, so a slow or
//!   hostile container never blocks the vault (INT-08.38); a save during a
//!   running export queues one more export;
//! - an import merges with larsal-core's shared-group import, inside the
//!   share group only (INT-08.32, LD-61); a lock or close drops a pass's
//!   result (the vault's lock count, as an unlock's); an import whose
//!   result a save would refuse under the reader's limits is refused
//!   (F-163);
//! - the import's merge runs on a copy, off the session lock; the lock is
//!   held only to swap the merged copy in, and only while the vault's
//!   change count is what it was at the copy: else the result is dropped
//!   and the share imports again, so the user's edits always win (F-165);
//! - the share password stays in `SecretString`; no result, error or
//!   banner line holds it (INT-08.39, AT-C06).
//!
//! Only Larsal's own saves export: the command line tool links none of this
//! (INT-08.40).

use crate::session::{LarsalError, Session};
use crate::share_edit::ShareMode;
use crate::views::{Rated, now, parse_id};
use larsal_core::storage::{self, DEFAULT_BACKUP_PATTERN};
use larsal_crypto::secret::SecretBytes;
use larsal_format::limits::Limits;
use larsal_model::Uuid;
use larsal_share::container;
use larsal_share::run::{self, Level, Line, Plan, Share};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

/// What waits to run for one vault.
#[derive(Default)]
struct Jobs {
    /// INT-08.15 step 1: every importing share (unlock, an allow setting
    /// turned on, the end of a pause).
    all: bool,
    /// Shares set up again (step 2) or just approved, by group.
    groups: BTreeSet<Uuid>,
    /// Watched paths that may have changed (step 3).
    paths: BTreeSet<PathBuf>,
    /// After a save (INT-08.17).
    export: bool,
}

impl Jobs {
    fn is_empty(&self) -> bool {
        !self.all && self.groups.is_empty() && self.paths.is_empty() && !self.export
    }
}

/// One vault's shares, kept in its session slot: dropped on lock and close.
#[derive(Default)]
pub(crate) struct State {
    jobs: Jobs,
    running: bool,
    /// INT-08.19: the merge dialog is open.
    paused: bool,
    /// INT-08.15 step 2: the settings each share group had last time.
    seen: HashMap<Uuid, SecretBytes>,
    /// INT-08.15: the SHA-256 of the first 5 KiB last seen per path.
    heads: HashMap<PathBuf, [u8; 32]>,
    /// Paths whose missing or unreadable file was told in this unlock;
    /// a good read takes the path out again.
    missing: HashSet<PathBuf>,
    /// What the passes since the last [`Session::take_share_news`] did.
    news: Option<ShareNews>,
    /// The group editor's Sharing page (share_edit.rs, INT-08.21): wiped
    /// with the rest of this state on lock and close.
    pub(crate) draft: Option<crate::share_edit::Draft>,
    /// Tests: runs once while an import's trial runs, off the lock.
    #[cfg(test)]
    pub(crate) trial: Option<Hook>,
    /// Tests: runs once between an export's look and its write, off the lock.
    #[cfg(test)]
    pub(crate) before_write: Option<Hook>,
}

#[cfg(test)]
type Hook = Box<dyn FnOnce(&Session) + Send>;

/// The kind of a share banner (INT-08.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ShareLevel {
    /// Success lines only.
    Success,
    /// A warning, no error.
    Warning,
    /// An error.
    Error,
}

/// One pass's banner (INT-08.20): one line each, successes first, then
/// warnings, then errors. Paths as stored and counts; no password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareBanner {
    /// Its kind.
    pub level: ShareLevel,
    /// Its lines (the MI08 texts).
    pub lines: Vec<String>,
    /// The path as stored that each line starts with, line by line, so the
    /// screen sets it in the mono font (E11-S5, the W-15 frames).
    pub paths: Vec<String>,
}

/// What share passes did since Swift last asked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareNews {
    /// An import changed the vault: the views read again, and the change
    /// is saved as any other (APP-05.2).
    pub changed: bool,
    /// The last banner of the passes since the last call; `None` when
    /// none had one.
    pub banner: Option<ShareBanner>,
}

/// What a pass found under the session lock.
struct Survey {
    epoch: u64,
    /// Every set-up share, with whether it is approved.
    shares: Vec<(Share, bool)>,
    /// Groups whose settings changed since last time (step 2).
    changed: Vec<Uuid>,
    /// Every open vault's file.
    open: Vec<PathBuf>,
    /// The key file each open vault was unlocked with.
    keys: Vec<PathBuf>,
}

/// INT-08.34: `path` names the file of an open vault, or a backup of one
/// by the pattern `backup` or the default, as APP-05.17 step 4 matches
/// them (F-269). A path that does not exist yet is compared through its
/// folder. Names compare as the file system compares them (E11-S6).
pub(crate) fn guarded(path: &Path, open: &[PathBuf], backup: &str) -> bool {
    let real = std::fs::canonicalize(path).ok().or_else(|| {
        let folder = std::fs::canonicalize(path.parent()?).ok()?;
        Some(folder.join(path.file_name()?))
    });
    let real = real.as_deref().unwrap_or(path);
    let home = home();
    open.iter().any(|p| {
        storage::same_entry(real, p)
            || [backup, DEFAULT_BACKUP_PATTERN]
                .iter()
                .any(|b| storage::is_backup(b, &storage::real_path(p), &home, real))
    })
}

/// The open vaults' files and their backups that exist now (F-269): what
/// an export may never replace (`container::write_file`'s `keep`).
fn kept(open: Vec<PathBuf>, backup: &str) -> Vec<PathBuf> {
    let home = home();
    let backups: Vec<PathBuf> = open
        .iter()
        .flat_map(|p| {
            let real = storage::real_path(p);
            let mut out = storage::old_copies(backup, &real, &home, None);
            out.extend(storage::old_copies(
                DEFAULT_BACKUP_PATTERN,
                &real,
                &home,
                None,
            ));
            out
        })
        .collect();
    [open, backups].concat()
}

/// MI08-17's second text.
const OPEN_VAULT: &str =
    "This file cannot be used for sharing: it is the file of a vault open in Larsal.";
/// MI08-27's editor text.
const KEY_FILE: &str = "This file cannot be used for sharing: it is a vault's key file.";
/// MI08-28.
const FILE_THERE: &str = "A file is already at this path. If it is not this share's file, Larsal leaves it alone and tells you after each save.";

/// A character that shows nothing, or shows as something it is not (RT-8):
/// controls (Cc), every format character (Cf), the other default-ignorable code
/// points, the spaces and separators that are not the plain space (Z*), blank
/// glyphs, private use and noncharacters. Unicode 16.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            // Cf.
            '\u{AD}' | '\u{600}'..='\u{605}' | '\u{61C}' | '\u{6DD}' | '\u{70F}'
            | '\u{890}'..='\u{891}' | '\u{8E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}'
            // Default-ignorable, not Cf.
            | '\u{34F}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
            | '\u{180B}'..='\u{180D}' | '\u{180F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFA0}' | '\u{FFF0}'..='\u{FFF8}'
            // Z*, but for the plain space.
            | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}'
            | '\u{202F}' | '\u{205F}' | '\u{3000}'
            // Blank glyphs.
            | '\u{2800}' | '\u{1D159}' | '\u{16FE4}' | '\u{FFFC}'
            // Private use and noncharacters.
            | '\u{E000}'..='\u{F8FF}' | '\u{FDD0}'..='\u{FDEF}' | '\u{F0000}'..='\u{10FFFF}')
        || (c as u32) & 0xFFFE == 0xFFFE
}

/// INT-08.31 (RT-8): a path as the Approve sheet and the group editor show it.
/// What [`hidden`] holds, and the backslash, is written out as `\\u{...}`, so a
/// typed `\\u{202e}` cannot read as a written-out one. Text only; the path
/// itself does not change.
#[uniffi::export]
#[must_use]
pub fn share_path_shown(path: String) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if hidden(c) || c == '\\' {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// `~/` of a backup pattern (APP-05.21).
fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from)
}

/// INT-08.34: `path` names one of the key files `keys`, by what file it is
/// or by a name the file system takes for the same one.
pub(crate) fn is_key_file(path: &Path, keys: &[PathBuf]) -> bool {
    keys.iter().any(|k| storage::same_entry(path, k))
}

/// The SHA-256 of the first 5 KiB of the file at `path` (INT-08.15);
/// `None` when it is not a regular file that can be read. Never waits on a
/// FIFO (F-101).
fn head_of(path: &Path) -> Option<[u8; 32]> {
    let mut head = Vec::with_capacity(run::HEAD);
    let file = larsal_platform::macos::open_regular(path).ok()?;
    let len = u64::try_from(run::HEAD).unwrap_or(u64::MAX);
    file.take(len).read_to_end(&mut head).ok()?;
    Some(run::head(&head))
}

fn level(l: Level) -> ShareLevel {
    match l {
        Level::Success => ShareLevel::Success,
        Level::Warning => ShareLevel::Warning,
        Level::Error => ShareLevel::Error,
    }
}

impl Session {
    /// Under the session lock: the vault's set-up shares and step 2's
    /// changed groups; `None` while it is locked or behind the forced key
    /// change. No file is touched here.
    fn survey(&self, id: u64) -> Result<Option<Survey>, LarsalError> {
        let approved = self.settings.share_approvals();
        self.with_share(id, |slot| {
            let vault = slot.vault?;
            let shares = run::shares(vault, Some(slot.path));
            let mut changed = Vec::new();
            let mut seen = HashMap::new();
            for s in &shares {
                let now = s.seen();
                if slot.share.seen.get(&s.group) != Some(&now) {
                    changed.push(s.group);
                }
                seen.insert(s.group, now);
            }
            slot.share.seen = seen;
            let shares = shares
                .into_iter()
                .map(|s| {
                    let ok = approved.contains(&s.approval(vault));
                    (s, ok)
                })
                .collect();
            Some(Survey {
                epoch: slot.epoch,
                shares,
                changed,
                open: slot.open,
                keys: slot.keys,
            })
        })
    }

    /// INT-08.34: `held`, the key files of this session's unlocks, and the
    /// remembered ones of every vault (APP-01.16). Reads Larsal settings, so
    /// off the session lock.
    pub(crate) fn key_files(&self, mut held: Vec<PathBuf>) -> Vec<PathBuf> {
        let known = self.settings.remembered_key_files();
        held.extend(
            known
                .iter()
                .map(|(vault, typed)| crate::session::key_path(Path::new(vault), typed)),
        );
        held
    }

    /// The plan of a survey: approved shares that are no vault's file and no
    /// key file (INT-08.31, INT-08.34), with the allow settings (INT-08.7).
    /// A key file's export is told (MI08-27). Checks the paths off the
    /// session lock.
    fn plan(&self, survey: Survey) -> (Plan, u64, Vec<Uuid>) {
        let (allow_import, allow_export, _) = self.settings.share_flags();
        let (open, backup) = (survey.open, self.backup_pattern());
        let keys = self.key_files(survey.keys);
        let mut refused = Vec::new();
        let runs = survey
            .shares
            .into_iter()
            .filter(|(s, ok)| *ok && !guarded(&s.path, &open, &backup))
            .map(|(s, _)| s)
            .filter(|s| {
                let key = is_key_file(&s.path, &keys);
                if key && allow_export && s.settings.exporting() {
                    refused.push(run::key_file(&s.settings.path));
                }
                !key
            })
            .collect();
        let mut plan = run::plan(runs, allow_import, allow_export);
        plan.export_lines.extend(refused);
        (plan, survey.epoch, survey.changed)
    }

    /// Adds work for vault `id` and starts its worker unless one runs.
    /// Nothing while the vault is locked or sharing is paused (INT-08.19:
    /// what comes meanwhile is dropped; the end of the pause imports all).
    fn queue(&self, id: u64, add: impl FnOnce(&mut Jobs)) {
        let start = self.with_share(id, |slot| {
            if slot.vault.is_none() || slot.share.paused {
                return None;
            }
            add(&mut slot.share.jobs);
            if slot.share.running || slot.share.jobs.is_empty() {
                return None;
            }
            slot.share.running = true;
            Some(slot.epoch)
        });
        let (Ok(Some(epoch)), Some(me)) = (start, self.me.upgrade()) else {
            return;
        };
        let worker = std::thread::Builder::new()
            .name("share".into())
            .spawn(move || me.work(id, epoch));
        if worker.is_err() {
            // No thread: nothing runs until the next trigger.
            let _ = self.with_share(id, |slot| slot.share.running = false);
        }
    }

    /// The worker of vault `id` for the unlock counted `epoch`: runs the
    /// waiting work until none is left; a lock or close ends it.
    fn work(&self, id: u64, epoch: u64) {
        loop {
            let next = self.with_share(id, |slot| {
                if slot.epoch != epoch {
                    return None;
                }
                if slot.share.paused || slot.share.jobs.is_empty() || slot.vault.is_none() {
                    slot.share.running = false;
                    return None;
                }
                Some(std::mem::take(&mut slot.share.jobs))
            });
            let Ok(Some(jobs)) = next else {
                return;
            };
            let (lines, changed) = self.pass(id, epoch, &jobs);
            let quiet = self.settings.share_flags().2;
            let banner = run::banner(&lines, quiet).map(|b| ShareBanner {
                level: level(b.level),
                lines: b.lines,
                paths: b.paths,
            });
            if banner.is_some() || changed {
                let _ = self.with_share(id, |slot| {
                    if slot.epoch == epoch {
                        let was = slot.share.news.take();
                        slot.share.news = Some(ShareNews {
                            changed: changed || was.as_ref().is_some_and(|n| n.changed),
                            banner: banner.or_else(|| was.and_then(|n| n.banner)),
                        });
                    }
                });
                crate::session::changed();
            }
        }
    }

    /// One pass: the imports `jobs` asks for (with step 2's), then, after a
    /// save, the exports. The lines of its banner and whether the vault
    /// changed.
    fn pass(&self, id: u64, epoch: u64, jobs: &Jobs) -> (Vec<Line>, bool) {
        let Ok(Some(survey)) = self.survey(id) else {
            return (Vec::new(), false);
        };
        let (plan, now_epoch, changed) = self.plan(survey);
        if now_epoch != epoch {
            return (Vec::new(), false);
        }
        let mut lines = Vec::new();
        let mut any = false;
        let asked =
            |s: &Share| jobs.all || jobs.groups.contains(&s.group) || changed.contains(&s.group);
        if jobs.all || !jobs.groups.is_empty() || !changed.is_empty() {
            lines.extend(plan.import_lines.iter().cloned());
        }
        for s in plan.imports.iter().filter_map(|&i| plan.shares.get(i)) {
            let on_look = jobs.paths.contains(&s.path);
            if asked(s) || on_look {
                any |= self.import(id, epoch, s, !asked(s), &mut lines);
            }
        }
        if jobs.export {
            lines.extend(plan.export_lines.iter().cloned());
            for &i in &plan.exports {
                let Some(s) = plan.shares.get(i) else {
                    continue;
                };
                // INT-08.37 (D-INT08-9): a Synchronize share imports first
                // when its file changed since the last import.
                if plan.imports.contains(&i) {
                    any |= self.import(id, epoch, s, true, &mut lines);
                }
                self.export(id, epoch, s, &mut lines);
            }
        }
        (lines, any)
    }

    /// INT-08.16: imports share `s` into vault `id`; with `if_changed`
    /// only when the first 5 KiB differ from the last seen. Whether the
    /// vault changed.
    fn import(
        &self,
        id: u64,
        epoch: u64,
        s: &Share,
        if_changed: bool,
        lines: &mut Vec<Line>,
    ) -> bool {
        let path = &s.path;
        let text = s.settings.path.as_str();
        if if_changed {
            let last = self
                .with_share(id, |slot| slot.share.heads.get(path).copied())
                .ok()
                .flatten();
            if last.is_some() && head_of(path) == last {
                return false;
            }
        }
        let bytes = match container::read_file(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                // A file that cannot be read is told once per unlock, not
                // at every tick; its first 5 KiB, when they can be read,
                // keep a later tick from reading it all again.
                let now = head_of(path);
                let first = self
                    .with_share(id, |slot| {
                        match now {
                            Some(h) => slot.share.heads.insert(path.clone(), h),
                            None => slot.share.heads.remove(path),
                        };
                        slot.share.missing.insert(path.clone())
                    })
                    .unwrap_or(false);
                if first {
                    lines.push(run::import_failed(text, &e));
                }
                return false;
            }
        };
        let head = run::head(&bytes);
        let mut host = self
            .host
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let opened = container::open(&bytes, &s.settings.password, &mut host, &Limits::DEFAULT);
        drop(bytes);
        // F-163, F-165: the merge runs on a copy, off the session lock, and
        // a save of its result must still pass the reader's limits; the
        // lock is taken again only to swap the merged copy in.
        let tried = match opened {
            Ok(o) => {
                let copy = self.with_share(id, |slot| {
                    let fresh = slot.epoch == epoch && !slot.share.paused;
                    let version = *slot.version;
                    slot.vault
                        .filter(|_| fresh)
                        .map(|v| (v.duplicate(), version))
                });
                let Ok(Some((copy, version))) = copy else {
                    // No copy (paused, locked or behind the forced key
                    // change at that moment): dropped and queued again.
                    self.queue(id, |j| {
                        j.groups.insert(s.group);
                    });
                    return false;
                };
                #[cfg(test)]
                if let Ok(Some(hook)) = self.with_share(id, |slot| slot.share.trial.take()) {
                    hook(self);
                }
                Ok(run::fits(copy, s.group, &o.vault, now(), &mut host).map(|t| (t, version)))
            }
            Err(e) => Err(e),
        };
        let seen = s.seen();
        let mut stale = None;
        let done = self.with_share(id, |slot| {
            if slot.epoch != epoch || slot.share.paused {
                return None;
            }
            slot.share.heads.insert(path.clone(), head);
            slot.share.missing.remove(path);
            let tried = match tried {
                Ok(tried) => tried,
                Err(e) => return Some(Err(e)),
            };
            let vault = slot.vault?;
            // The share was changed or removed meanwhile: dropped.
            let same = run::shares(vault, Some(slot.path))
                .iter()
                .any(|now| now.group == s.group && now.seen() == seen);
            if !same {
                return None;
            }
            let ((got, merged), version) = match tried {
                Ok(t) => t,
                Err(e) => return Some(Err(e)),
            };
            let Some(merged) = merged else {
                return Some(Ok((got, None)));
            };
            if *slot.version != version {
                // The vault changed while the trial ran: that change
                // wins, and the import runs again on the vault as it is.
                stale = Some(merged);
                return None;
            }
            let old = std::mem::replace(vault, merged);
            *slot.version = slot.version.wrapping_add(1);
            slot.edit.changes = slot.edit.changes.saturating_add(1);
            *slot.rated = Rated::default();
            Some(Ok((got, Some(old))))
        });
        // The merged copy that came too late is dropped off the lock.
        if stale.take().is_some() {
            self.queue(id, |j| {
                j.groups.insert(s.group);
            });
        }
        match done {
            // The vault it replaced is dropped here, off the lock.
            Ok(Some(Ok((got, _old)))) => {
                if got.changed {
                    lines.push(run::imported(text));
                }
                if got.outside > 0 {
                    lines.push(run::outside(text, got.outside));
                }
                got.changed
            }
            Ok(Some(Err(e))) => {
                lines.push(run::import_failed(text, &e));
                false
            }
            _ => false,
        }
    }

    /// INT-08.17: writes share `s`'s container from the vault as it is now;
    /// the head it wrote becomes the one last seen, so the share never
    /// imports its own export. INT-08.34 again at the write, in the folder
    /// it uses (F-162): the guard of the pass's start cannot see a folder
    /// swapped during the KDF.
    fn export(&self, id: u64, epoch: u64, s: &Share, lines: &mut Vec<Line>) {
        let text = s.settings.path.as_str();
        let built = self.with_share(id, |slot| {
            if slot.epoch != epoch || slot.share.paused {
                return None;
            }
            let vault = slot.vault?;
            let written = s.written(vault);
            let c = container::build(s.group, s.settings.keep_groups, vault, now());
            Some(c.map(|c| (c, slot.open, slot.keys, written)))
        });
        let (c, open, keys, written) = match built {
            Ok(Some(Ok(c))) => c,
            Ok(Some(Err(e))) => return lines.push(run::export_failed(text, &e)),
            _ => return,
        };
        let mut keep = kept(open, &self.backup_pattern());
        keep.extend(self.key_files(keys));
        let mut host = self
            .host
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let record = self.settings.share_written(&written);
        let looked = container::look(
            &s.path,
            &s.settings.password,
            &mut host,
            &Limits::DEFAULT,
            record.as_deref(),
        );
        let looked = match looked {
            Ok(looked) => looked,
            Err(e) => return lines.push(run::export_failed(text, &e)),
        };
        #[cfg(test)]
        if let Ok(Some(hook)) = self.with_share(id, |slot| slot.share.before_write.take()) {
            hook(self);
        }
        match container::write_share(
            &s.path,
            &c,
            &s.settings.password,
            &mut host,
            &Limits::DEFAULT,
            &keep,
            &looked,
        ) {
            Ok(head) => {
                self.settings.note_share_written(&written, &run::hex(&head));
                let _ = self.with_share(id, |slot| {
                    if slot.epoch == epoch {
                        slot.share.heads.insert(s.path.clone(), head);
                    }
                });
                lines.push(run::exported(text));
            }
            Err(e) => lines.push(run::export_failed(text, &e)),
        }
    }

    /// `save.backup.path` (APP-05.20); empty means the default.
    pub(crate) fn backup_pattern(&self) -> String {
        self.settings.text("backup.pattern".into())
    }

    /// INT-08.15 step 1 after an unlock (session.rs).
    pub(crate) fn share_unlocked(&self, id: u64) {
        let (import, _, _) = self.settings.share_flags();
        if import {
            self.queue(id, |j| j.all = true);
        }
    }

    /// INT-08.17 after a good save (saving.rs).
    pub(crate) fn share_saved(&self, id: u64) {
        let (_, export, _) = self.settings.share_flags();
        if export {
            self.queue(id, |j| j.export = true);
        }
    }

    /// INT-08.15 step 4 (larsal_settings.rs): an allow setting changed since
    /// `before`; with import on, every unlocked vault imports as at unlock.
    pub(crate) fn share_flags_changed(&self, before: (bool, bool, bool)) {
        let after = self.settings.share_flags();
        if (after.0, after.1) == (before.0, before.1) || !after.0 {
            return;
        }
        let ids: Vec<u64> = self.with_slots(|slots, _| {
            slots
                .iter()
                .filter(|s| s.1.is_some())
                .map(|s| s.0)
                .collect()
        });
        for id in ids {
            self.queue(id, |j| j.all = true);
        }
    }

    /// INT-08.31 (the group editor's accept, and behind the Approve sheet's
    /// [`Session::approve_share_shown`]): Larsal approves share group
    /// `group`'s mode and resolved path as they are now; then the share runs,
    /// and imports at once when it imports.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup` (no group, or no share
    /// that is set up there).
    pub(crate) fn approve_share(&self, vault: u64, group: String) -> Result<(), LarsalError> {
        let group = parse_id(&group, LarsalError::UnknownGroup)?;
        let key = self.with_open(vault, |v, path, _| {
            run::shares(v, Some(path))
                .into_iter()
                .find(|s| s.group == group)
                .map(|s| s.approval(v))
                .ok_or(LarsalError::UnknownGroup)
        })?;
        self.settings.approve_share(key);
        let (import, _, _) = self.settings.share_flags();
        if import {
            self.queue(vault, |j| {
                j.groups.insert(group);
            });
        }
        Ok(())
    }

    /// Tests: waits until vault `id`'s share work is done (at most 60 s).
    #[cfg(test)]
    pub(crate) fn share_wait(&self, id: u64) {
        for _ in 0..6000 {
            let busy = self
                .with_share(id, |slot| slot.share.running || !slot.share.jobs.is_empty())
                .unwrap_or(false);
            if !busy {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("share work did not end");
    }
}

#[uniffi::export]
impl Session {
    /// INT-08.15: the container files to watch now (one `DiskWatch` each,
    /// LD-216): the resolved paths of the shares that import, approved and
    /// not a vault's file; empty while locked, paused or with import off.
    /// A share whose settings changed since the last look is set up again
    /// and, when it imports, imported at once in the background (step 2).
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn share_paths(&self, vault: u64) -> Result<Vec<String>, LarsalError> {
        let paused = self.with_share(vault, |slot| slot.share.paused)?;
        let Some(survey) = self.survey(vault)? else {
            return Ok(Vec::new());
        };
        if paused {
            return Ok(Vec::new());
        }
        let (plan, _, changed) = self.plan(survey);
        let groups: Vec<Uuid> = changed
            .into_iter()
            .filter(|g| {
                plan.imports
                    .iter()
                    .any(|&i| plan.shares.get(i).is_some_and(|s| s.group == *g))
            })
            .collect();
        if !groups.is_empty() {
            self.queue(vault, |j| j.groups.extend(groups));
        }
        let paths: Vec<String> = plan
            .imports
            .iter()
            .filter_map(|&i| plan.shares.get(i))
            .map(|s| s.path.to_string_lossy().into_owned())
            .collect();
        Ok(paths)
    }

    /// INT-08.15 step 3: a watch says the file at `path` may have changed;
    /// in the background its first 5 KiB are compared and, when they
    /// differ, the shares that import it import it.
    ///
    /// # Errors
    /// `UnknownVault`; `TooLong` for a path over 4,096 bytes.
    pub fn share_look(&self, vault: u64, path: String) -> Result<(), LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        self.with_share(vault, |_| ())?;
        self.queue(vault, |j| {
            j.paths.insert(PathBuf::from(path));
        });
        Ok(())
    }

    /// INT-08.19: sharing of vault `vault` pauses while the merge dialog is
    /// open (no import, no export, no watch); when it closes, every
    /// importing share imports as at unlock.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn share_pause(&self, vault: u64, paused: bool) -> Result<(), LarsalError> {
        self.with_share(vault, |slot| {
            slot.share.paused = paused;
            slot.share.jobs = Jobs::default();
        })?;
        if !paused {
            self.share_unlocked(vault);
        }
        Ok(())
    }

    /// INT-08.31 (MI08-18's Approve): Larsal approves share group `group`'s
    /// mode and resolved path only when they are still the ones the sheet
    /// showed; then the share runs, and imports at once when it imports.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup` (no group, or no share that
    /// is set up there); `Refused` when the share changed under the sheet.
    pub fn approve_share_shown(
        &self,
        vault: u64,
        group: String,
        mode: ShareMode,
        full_path: String,
    ) -> Result<(), LarsalError> {
        let id = parse_id(&group, LarsalError::UnknownGroup)?;
        let same = self.with_open(vault, |v, path, _| {
            run::shares(v, Some(path))
                .into_iter()
                .find(|s| s.group == id)
                .map(|s| {
                    ShareMode::from(s.settings.mode()) == mode
                        && s.path.to_string_lossy() == full_path
                })
                .ok_or(LarsalError::UnknownGroup)
        })?;
        if !same {
            return Err(LarsalError::Refused(
                "This share changed while the sheet was open. Look at it again.".to_owned(),
            ));
        }
        self.approve_share(vault, group)
    }

    /// INT-08.31, INT-08.34: why the Approve sheet warns about share group
    /// `group` (the texts of MI08-17, MI08-27 and MI08-28): its path is a
    /// vault's file or a key file, or a file is there that this share did
    /// not write. Looks at the paths off the session lock.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownGroup`.
    pub fn share_block(&self, vault: u64, group: String) -> Result<Option<String>, LarsalError> {
        let id = parse_id(&group, LarsalError::UnknownGroup)?;
        let (path, exporting, written, open, keys) = self.with_share(vault, |slot| {
            let v = slot.vault.ok_or(LarsalError::Locked)?;
            let s = run::shares(v, Some(slot.path))
                .into_iter()
                .find(|s| s.group == id)
                .ok_or(LarsalError::UnknownGroup)?;
            let written = s.written(v);
            Ok((
                s.path,
                s.settings.exporting(),
                written,
                slot.open,
                slot.keys,
            ))
        })??;
        if guarded(&path, &open, &self.backup_pattern()) {
            return Ok(Some(OPEN_VAULT.to_owned()));
        }
        if is_key_file(&path, &self.key_files(keys)) {
            return Ok(Some(KEY_FILE.to_owned()));
        }
        let there = storage::stamp(&path).ok().flatten().is_some();
        let ours = self
            .settings
            .share_written(&written)
            .is_some_and(|head| head_of(&path).is_some_and(|h| run::hex(&h) == head));
        Ok((exporting && there && !ours).then(|| FILE_THERE.to_owned()))
    }

    /// What share passes did since the last call (INT-08.20); `None` when
    /// nothing. Swift reads the views again when `changed`.
    ///
    /// # Errors
    /// `UnknownVault`.
    pub fn take_share_news(&self, vault: u64) -> Result<Option<ShareNews>, LarsalError> {
        self.with_share(vault, |slot| slot.share.news.take())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::larsal_settings::{LarsalSetting, LarsalSettingValue};
    use crate::session::UnlockResult;
    use crate::test_dir::TempDir;
    use larsal_crypto::kdf::Host;
    use larsal_crypto::secret::SecretString;
    use larsal_format::share_item::{self, Settings};
    use larsal_model::{
        Argon2Kind, CustomDataItem, DeletedObject, Entry, Field, Group, Kdf, Time, Vault,
    };
    use larsal_share::Error;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// V's password (T56).
    pub(crate) const MAIN: &str = "demo-v";
    /// The card's share password.
    pub(crate) const SHARE: &str = "demo-share-1";
    /// T0 = 2026-01-01T00:00:00Z, T1 a day later, T2 = 2026-03-01 (INT-08
    /// notation), in seconds since 0001-01-01.
    const T0: Time = Time(63_902_822_400);
    const T1: Time = Time(63_902_908_800);
    const T2: Time = Time(63_907_920_000);

    pub(crate) fn id(n: u8) -> Uuid {
        Uuid([n; 16])
    }

    pub(crate) fn hex(u: Uuid) -> String {
        u.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub(crate) fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    pub(crate) fn set(e: &mut Entry, key: &str, value: &str, protected: bool) {
        e.set_field(
            key.to_owned(),
            Field {
                value: secret(value),
                protected,
            },
        );
    }

    pub(crate) fn entry(n: u8, title: &str, user: &str, password: &str) -> Entry {
        let mut e = Entry::new(id(n), T0);
        set(&mut e, "Title", title, false);
        set(&mut e, "UserName", user, false);
        set(&mut e, "Password", password, true);
        e
    }

    fn group_mut(g: &mut Group, n: u8) -> Option<&mut Group> {
        if g.uuid == id(n) {
            return Some(g);
        }
        g.groups.iter_mut().find_map(|c| group_mut(c, n))
    }

    pub(crate) fn team(v: &mut Vault) -> &mut Group {
        group_mut(&mut v.root, 0x20).expect("Team")
    }

    pub(crate) fn find(v: &Vault, n: u8) -> Option<&Entry> {
        v.root.all_entries().find(|e| e.uuid == id(n))
    }

    pub(crate) fn titles(g: &Group) -> Vec<String> {
        g.entries
            .iter()
            .map(|e| e.value("Title").to_owned())
            .collect()
    }

    /// A share on `path` with the card's share password.
    pub(crate) fn settings(import: bool, export: bool, path: &str) -> Settings {
        Settings {
            import,
            export,
            path: path.to_owned(),
            password: secret(SHARE),
            keep_groups: true,
            ..Settings::new()
        }
    }

    /// Puts `s` as the share item of `g`, in place of the one it had.
    pub(crate) fn set_share(g: &mut Group, mut s: Settings) {
        let key = String::from_utf8(share_item::KEY.to_vec()).unwrap();
        g.custom_data.items.retain(|i| i.key != key);
        let value = s.write().unwrap();
        g.custom_data.items.push(CustomDataItem {
            key,
            value,
            last_modified: None,
            unknown: Vec::new(),
        });
    }

    /// The share item of `g`, changed by `f` (another app's edit).
    pub(crate) fn edit_share(g: &mut Group, f: impl FnOnce(&mut Settings)) {
        let Some(share_item::Item::Settings(mut s)) = share_item::of(g) else {
            panic!("a share item");
        };
        f(&mut s);
        set_share(g, s);
    }

    /// V (INT-08 Test cases): Root(01) → Team(20) {Mail(0A) ann pw-1,
    /// Bank(0B) pw-b}, Team → Sub(21) → Wiki(0C) pw-w. A cheap AES-KDF.
    pub(crate) fn base() -> Vault {
        let mut sub = Group::new(id(0x21), "Sub".into(), T0);
        sub.entries.push(entry(0x0C, "Wiki", "", "pw-w"));
        let mut team = Group::new(id(0x20), "Team".into(), T0);
        team.entries.push(entry(0x0A, "Mail", "ann", "pw-1"));
        team.entries.push(entry(0x0B, "Bank", "", "pw-b"));
        team.groups.push(sub);
        let mut root = Group::new(id(0x01), "Root".into(), T0);
        root.groups.push(team);
        let mut v = Vault::new(root, T0);
        v.meta.name = "V".into();
        v.encryption.kdf = Kdf::AesKdf { rounds: 1_000 };
        v
    }

    /// V as a member wrote it: Mail's password `pw-2`, changed at T1.
    pub(crate) fn member() -> Vault {
        let mut m = base();
        let mail = team(&mut m).entries.first_mut().unwrap();
        set(mail, "Password", "pw-2", true);
        mail.times.last_modification = T1;
        m
    }

    fn host() -> Host {
        Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        }
    }

    /// Writes `vault` to `path` under `password` alone.
    pub(crate) fn write(path: &Path, vault: &Vault, password: &str) {
        container::write_file(
            path,
            vault,
            &secret(password),
            &mut host(),
            &Limits::DEFAULT,
            &[],
        )
        .unwrap();
    }

    /// The vault in the file at `path`.
    pub(crate) fn read(path: &Path, password: &str) -> Result<Vault, Error> {
        container::open_file(path, &secret(password), &mut host(), &Limits::DEFAULT)
            .map(|o| o.vault)
    }

    /// `of`'s Team as a container at `path` (another member's export).
    pub(crate) fn publish(path: &Path, of: &Vault) {
        publish_with(path, of, SHARE);
    }

    fn publish_with(path: &Path, of: &Vault, password: &str) {
        let c = container::build(id(0x20), true, of, T2).unwrap();
        write(path, &c, password);
    }

    /// A session with both allow settings on and `share.quiet` as given.
    pub(crate) fn session(quiet: bool) -> Arc<Session> {
        let s = Session::new();
        flags(&s, true, true, quiet);
        s
    }

    pub(crate) fn flags(s: &Session, import: bool, export: bool, quiet: bool) {
        let flag = |key: &str, on: bool| LarsalSetting {
            key: key.to_owned(),
            value: LarsalSettingValue::Flag { on },
        };
        s.save_settings(vec![
            flag("share.import", import),
            flag("share.export", export),
            flag("share.quiet", quiet),
        ])
        .unwrap();
    }

    /// Writes V (`vault`) to `file`, approves its shares as Larsal's group
    /// editor does (INT-08.31) and opens it in `s`, locked.
    pub(crate) fn approved(s: &Session, file: &Path, vault: &Vault) -> u64 {
        write(file, vault, MAIN);
        for share in run::shares(vault, Some(file)) {
            s.settings.approve_share(share.approval(vault));
        }
        s.open(file.to_string_lossy().into_owned()).unwrap()
    }

    /// Unlocks vault `v` and waits for its share passes.
    pub(crate) fn unlock(s: &Session, v: u64) {
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        s.share_wait(v);
    }

    /// Saves vault `v` and waits for its exports.
    pub(crate) fn save(s: &Session, v: u64) {
        let st = s.save(v).unwrap();
        assert_eq!(st.failure, None, "{st:?}");
        s.share_wait(v);
    }

    fn look(s: &Session, v: u64, path: &Path) {
        s.share_look(v, path.to_string_lossy().into_owned())
            .unwrap();
        s.share_wait(v);
    }

    pub(crate) fn model<R>(s: &Session, v: u64, f: impl FnOnce(&Vault) -> R) -> R {
        s.with_open(v, |vault, _, _| Ok(f(vault))).unwrap()
    }

    pub(crate) fn change(s: &Session, v: u64, f: impl FnOnce(&mut Vault)) {
        s.with_edit(v, |vault, _, _, _| {
            f(vault);
            Ok(())
        })
        .unwrap();
    }

    pub(crate) fn news(s: &Session, v: u64) -> Option<ShareNews> {
        s.take_share_news(v).unwrap()
    }

    /// The banner of the passes since the last look: its kind and lines.
    pub(crate) fn banner(s: &Session, v: u64) -> Option<(ShareLevel, Vec<String>)> {
        news(s, v)
            .and_then(|n| n.banner)
            .map(|b| (b.level, b.lines))
    }

    pub(crate) fn mail(s: &Session, v: u64) -> String {
        model(s, v, |m| {
            find(m, 0x0A).unwrap().value("Password").to_owned()
        })
    }

    /// V with Team sharing `team.larsalvault` (`import`, `export`) and a
    /// member's container there (Mail `pw-2`, T23): V's file, the
    /// container's and V.
    fn scene(dir: &Path, import: bool, export: bool) -> (PathBuf, PathBuf, Vault) {
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        publish(&path, &member());
        let mut vault = base();
        set_share(
            team(&mut vault),
            settings(import, export, "team.larsalvault"),
        );
        (file, path, vault)
    }

    /// T09: fresh Larsal settings; with them nothing runs, and turning import
    /// on imports at once (INT-08.15 step 4).
    #[test]
    fn t09_int08_7_sharing_starts_off_and_step_4_imports_when_turned_on() {
        let dir = TempDir::new("share-t09");
        let s = Session::new();
        assert_eq!(s.settings.share_flags(), (false, false, true));
        let (file, path, vault) = scene(&dir, true, false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-1");
        assert!(s.share_paths(v).unwrap().is_empty());
        assert_eq!(news(&s, v), None);
        flags(&s, true, false, true);
        s.share_wait(v);
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(
            s.share_paths(v).unwrap(),
            vec![path.to_string_lossy().into_owned()]
        );
    }

    #[test]
    fn t23_int08_15_unlock_imports_and_mi08_01_shows_only_when_quiet_is_off() {
        for quiet in [true, false] {
            let dir = TempDir::new(&format!("share-t23-{quiet}"));
            let (file, _, vault) = scene(&dir, true, false);
            let s = session(quiet);
            let v = approved(&s, &file, &vault);
            unlock(&s, v);
            model(&s, v, |m| {
                let mail = find(m, 0x0A).unwrap();
                assert_eq!(mail.value("Password"), "pw-2");
                assert!(mail.history.iter().any(|h| h.value("Password") == "pw-1"));
            });
            let n = news(&s, v).expect("the import is told");
            assert!(n.changed);
            let lines = n.banner.map(|b| (b.level, b.lines));
            let shown = (
                ShareLevel::Success,
                vec!["team.larsalvault: changes imported.".to_owned()],
            );
            assert_eq!(lines, (!quiet).then_some(shown), "quiet {quiet}");
            // The import is a change, saved as any other (APP-05.2).
            assert_eq!(s.save_status(v).unwrap().changes, 1);
        }
    }

    #[test]
    fn t24_int08_15_step_3_a_rewritten_container_imports_on_its_watch() {
        let dir = TempDir::new("share-t24");
        let (file, path, vault) = scene(&dir, true, false);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let _ = news(&s, v);
        let mut m = member();
        team(&mut m).entries.push(entry(0x40, "News", "", "pw-n"));
        publish(&path, &m);
        look(&s, v, &path);
        model(&s, v, |m| {
            assert!(titles(m.root.find_group(id(0x20)).unwrap()).contains(&"News".to_owned()))
        });
        assert!(news(&s, v).is_some_and(|n| n.changed));
    }

    /// Letters that gzip cannot shrink much.
    fn noise(len: usize) -> String {
        let mut x: u32 = 0x1234_5678;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                char::from(b'a' + u8::try_from(x % 26).unwrap())
            })
            .collect()
    }

    #[test]
    fn t25_int08_15_a_change_after_the_first_5_kib_starts_no_import() {
        let dir = TempDir::new("share-t25");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let mut vault = base();
        let mut big = entry(0x41, "Big", "", "");
        set(&mut big, "Notes", &noise(12_000), false);
        team(&mut vault).entries.push(big);
        publish(&path, &vault);
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(news(&s, v), None, "the same content: nothing to tell");
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 6_100, "{}", bytes.len());
        bytes[6_000] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        look(&s, v, &path);
        // The damaged file was never read: no MI08-02.
        assert_eq!(news(&s, v), None);
        // A change inside the first 5 KiB is read (and is damaged).
        bytes[200] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        look(&s, v, &path);
        let (level, lines) = banner(&s, v).expect("MI08-02");
        assert_eq!(level, ShareLevel::Error);
        assert!(
            lines[0].starts_with("team.larsalvault: import failed."),
            "{lines:?}"
        );
    }

    #[test]
    fn t26_int08_15_step_2_a_keep_groups_change_starts_no_import() {
        let dir = TempDir::new("share-t26");
        let (file, path, vault) = scene(&dir, true, false);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let _ = news(&s, v);
        // The container changes; no watch tells it.
        let mut m = member();
        team(&mut m).entries.push(entry(0x40, "News", "", "pw-n"));
        publish_with(&path, &m, "demo-share-2");
        change(&s, v, |m| {
            edit_share(team(m), |st| st.keep_groups = !st.keep_groups)
        });
        assert_eq!(s.share_paths(v).unwrap().len(), 1);
        s.share_wait(v);
        let has_news = |s: &Session| model(s, v, |m| find(m, 0x40).is_some());
        assert!(!has_news(&s), "a KeepGroups change started an import");
        assert_eq!(news(&s, v), None);
        // A new password is a share set up again: imported at once.
        change(&s, v, |m| {
            edit_share(team(m), |st| st.password = secret("demo-share-2"))
        });
        assert_eq!(s.share_paths(v).unwrap().len(), 1);
        s.share_wait(v);
        assert!(has_news(&s));
    }

    #[test]
    fn t27_int08_16_a_wrong_share_password_gives_mi08_02_and_team_unchanged() {
        let dir = TempDir::new("share-t27");
        let (file, path, vault) = scene(&dir, true, false);
        publish_with(&path, &member(), "other");
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let n = news(&s, v).unwrap();
        assert!(!n.changed);
        let b = n.banner.unwrap();
        assert_eq!(b.level, ShareLevel::Error);
        assert_eq!(
            b.lines,
            ["team.larsalvault: import failed. The share password is wrong."]
        );
        assert_eq!(mail(&s, v), "pw-1");
        assert_eq!(s.save_status(v).unwrap().changes, 0);
    }

    #[test]
    fn t28_int08_16_an_identical_container_changes_and_tells_nothing() {
        let dir = TempDir::new("share-t28");
        let (file, path, vault) = scene(&dir, true, false);
        publish(&path, &vault);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(news(&s, v), None);
        assert_eq!(s.save_status(v).unwrap().changes, 0);
        assert_eq!(mail(&s, v), "pw-1");
    }

    #[test]
    fn t29_int08_17_every_save_exports_and_no_export_is_imported_back() {
        let dir = TempDir::new("share-t29");
        let (file, path, vault) = scene(&dir, true, true);
        publish(&path, &vault);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let mut last = std::fs::read(&path).unwrap();
        for round in 0..3 {
            save(&s, v);
            let now = std::fs::read(&path).unwrap();
            assert_ne!(now, last, "save {round} did not write the container");
            assert!(read(&path, SHARE).is_ok());
            last = now;
            // The watch fires on Larsal's own write: nothing is imported.
            look(&s, v, &path);
            assert_eq!(news(&s, v), None);
            assert_eq!(s.save_status(v).unwrap().changes, 0);
        }
    }

    #[test]
    fn t30_int08_17_with_export_off_a_save_leaves_the_container_untouched() {
        let dir = TempDir::new("share-t30");
        let (file, path, vault) = scene(&dir, false, true);
        let before = std::fs::read(&path).unwrap();
        let s = session(true);
        flags(&s, true, false, true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        save(&s, v);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(news(&s, v), None);
    }

    /// V plus Other(22) at the root, with an entry of its own.
    fn with_other(vault: &mut Vault, s: Settings) {
        let mut other = Group::new(id(0x22), "Other".into(), T0);
        other.entries.push(entry(0x42, "Own", "", "pw-o"));
        set_share(&mut other, s);
        vault.root.groups.push(other);
    }

    #[test]
    fn t31_int08_18_two_exports_on_one_path_write_nothing_and_tell_once() {
        let dir = TempDir::new("share-t31");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
        with_other(&mut vault, settings(false, true, "team.larsalvault"));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        save(&s, v);
        assert!(!path.exists(), "a container was written");
        assert_eq!(
            banner(&s, v),
            Some((
                ShareLevel::Error,
                vec![
                    "team.larsalvault: exported by several groups (Team, Other), so nothing was exported. Give each group its own file."
                        .to_owned()
                ]
            ))
        );
    }

    #[test]
    fn t32_d_int08_7_two_imports_on_one_path_change_neither_group() {
        let dir = TempDir::new("share-t32");
        let (file, _, mut vault) = scene(&dir, true, false);
        with_other(&mut vault, settings(true, false, "team.larsalvault"));
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(
            banner(&s, v),
            Some((
                ShareLevel::Warning,
                vec![
                    "team.larsalvault: imported by several groups (Team, Other), so none of them is updated until only one imports it."
                        .to_owned()
                ]
            ))
        );
        assert_eq!(mail(&s, v), "pw-1");
        model(&s, v, |m| {
            assert_eq!(titles(m.root.find_group(id(0x22)).unwrap()), ["Own"]);
            assert_eq!(
                titles(m.root.find_group(id(0x20)).unwrap()),
                ["Mail", "Bank"]
            );
        });
        assert!(s.share_paths(v).unwrap().is_empty());
    }

    #[test]
    fn t33_int08_19_a_paused_vault_shares_nothing_until_the_pause_ends() {
        let dir = TempDir::new("share-t33");
        let (file, path, vault) = scene(&dir, true, true);
        publish(&path, &vault);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        s.share_pause(v, true).unwrap();
        assert!(
            s.share_paths(v).unwrap().is_empty(),
            "no watch while paused"
        );
        let mut m = base();
        team(&mut m).entries.push(entry(0x40, "News", "", "pw-n"));
        publish(&path, &m);
        let written = std::fs::read(&path).unwrap();
        look(&s, v, &path);
        save(&s, v);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            written,
            "exported while paused"
        );
        assert!(
            model(&s, v, |m| find(m, 0x40).is_none()),
            "imported while paused"
        );
        assert_eq!(news(&s, v), None);
        s.share_pause(v, false).unwrap();
        s.share_wait(v);
        assert!(model(&s, v, |m| find(m, 0x40).is_some()));
        assert_eq!(s.share_paths(v).unwrap().len(), 1);
    }

    #[test]
    fn t34_int08_20_one_banner_per_pass_and_quiet_keeps_only_the_failure() {
        for quiet in [true, false] {
            let dir = TempDir::new(&format!("share-t34-{quiet}"));
            let (file, path, mut vault) = scene(&dir, true, true);
            publish(&path, &vault);
            with_other(&mut vault, settings(false, true, "gone/other.larsalvault"));
            let s = session(quiet);
            let v = approved(&s, &file, &vault);
            unlock(&s, v);
            let _ = news(&s, v);
            // A member's export since the last import: this save's pass
            // imports it, exports Team and fails Other's export.
            publish(&path, &member());
            save(&s, v);
            let failed = "gone/other.larsalvault: export failed. The file could not be written: The file or its folder is not there.";
            let want = if quiet {
                vec![failed.to_owned()]
            } else {
                vec![
                    "team.larsalvault: changes imported.".to_owned(),
                    "team.larsalvault: exported.".to_owned(),
                    failed.to_owned(),
                ]
            };
            assert_eq!(
                banner(&s, v),
                Some((ShareLevel::Error, want)),
                "quiet {quiet}"
            );
            assert_eq!(mail(&s, v), "pw-2");
        }
    }

    /// AT-I04: a share item that came from outside Larsal's editor (by a
    /// merge, an import or another app) aims Team's export at a victim
    /// file. It never runs until approved, and a later change of its path
    /// needs a new approval.
    #[test]
    fn t52_at_i04_a_share_from_outside_never_runs_until_approved() {
        let dir = TempDir::new("share-t52");
        let (file, victim) = (dir.join("v2.larsalvault"), dir.join("victim.txt"));
        std::fs::write(&victim, "victim").unwrap();
        let mut vault = base();
        set_share(
            team(&mut vault),
            settings(true, true, &victim.to_string_lossy()),
        );
        write(&file, &vault, MAIN);
        let s = session(false);
        let v = s.open(file.to_string_lossy().into_owned()).unwrap();
        unlock(&s, v);
        assert!(
            s.share_paths(v).unwrap().is_empty(),
            "watched before approval"
        );
        save(&s, v);
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
        assert_eq!(news(&s, v), None);
        assert_eq!(
            s.approve_share(v, hex(id(0x21))),
            Err(LarsalError::UnknownGroup)
        );
        s.approve_share(v, hex(id(0x20))).unwrap();
        s.share_wait(v);
        let _ = news(&s, v);
        save(&s, v);
        // INT-08.34: the file is not this share's, so Approve does not cover it.
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
        let there = format!(
            "{}: export failed. Another file is already there, and Larsal did not write it for this share, so it was left alone. Choose another file or move that one.",
            victim.to_string_lossy()
        );
        assert_eq!(
            banner(&s, v).map(|b| (b.0, b.1.last().cloned())),
            Some((ShareLevel::Error, Some(there)))
        );
        std::fs::remove_file(&victim).unwrap();
        save(&s, v);
        assert!(read(&victim, SHARE).is_ok(), "the approved share exports");
        // The record lives in Larsal settings, outside the vault (INT-08.31).
        assert_eq!(s.settings.share_approvals().len(), 1);
        // Another app moves the path: paused again.
        let moved = dir.join("moved.txt");
        change(&s, v, |m| {
            edit_share(team(m), |st| st.path = moved.to_string_lossy().into_owned())
        });
        save(&s, v);
        assert!(!moved.exists());
        assert!(s.share_paths(v).unwrap().is_empty());
    }

    /// T53 (MOD-11 T42, LD-61): a container that names an entry outside
    /// the share never moves or overwrites it. Items skipped alone are no
    /// change, whatever `share.quiet` (INT-08.16 step 4, F-160 M39).
    #[test]
    fn t53_mod11_t42_an_import_never_touches_an_entry_outside_the_share() {
        for quiet in [true, false] {
            let dir = TempDir::new(&format!("share-t53-{quiet}"));
            let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
            let mut vault = base();
            let bank = team(&mut vault).entries.pop().unwrap();
            let mut home = Group::new(id(0x30), "Home".into(), T0);
            home.entries.push(bank);
            vault.root.groups.push(home);
            set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
            let mut m = base();
            let evil = team(&mut m).entries.last_mut().unwrap();
            set(evil, "Password", "evil", true);
            evil.times.last_modification = T2;
            evil.times.location_changed = T2;
            publish(&path, &m);
            let s = session(quiet);
            let v = approved(&s, &file, &vault);
            unlock(&s, v);
            model(&s, v, |m| {
                let home = m.root.find_group(id(0x30)).unwrap();
                assert_eq!(titles(home), ["Bank"]);
                assert_eq!(find(m, 0x0B).unwrap().value("Password"), "pw-b");
                assert_eq!(titles(m.root.find_group(id(0x20)).unwrap()), ["Mail"]);
            });
            let n = news(&s, v).expect("the skip is told");
            assert!(!n.changed, "quiet {quiet}: a skip marked the vault changed");
            assert_eq!(
                n.banner.map(|b| (b.level, b.lines)),
                Some((
                    ShareLevel::Warning,
                    vec!["team.larsalvault: 1 items were not imported because they belong outside this shared group.".to_owned()]
                )),
                "quiet {quiet}"
            );
            assert_eq!(s.save_status(v).unwrap().changes, 0);
        }
    }

    #[test]
    fn t54_int08_32_a_deletion_outside_the_share_is_skipped() {
        let dir = TempDir::new("share-t54");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let mut vault = base();
        vault
            .root
            .groups
            .push(Group::new(id(0x30), "Home".into(), T0));
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let mut m = base();
        m.deleted_objects.push(DeletedObject {
            uuid: id(0x30),
            deleted_at: T2,
            unknown: Vec::new(),
        });
        publish(&path, &m);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        model(&s, v, |m| {
            assert!(m.root.find_group(id(0x30)).is_some(), "Home erased")
        });
    }

    /// INT-08.34: a share on the vault's own file or on the file of any
    /// vault open in Larsal (any letter case) never runs, approved or not.
    #[test]
    fn t56_int08_34_a_share_on_an_open_vaults_file_never_runs() {
        let dir = TempDir::new("share-t56");
        let (file, w) = (dir.join("v.larsalvault"), dir.join("w.larsalvault"));
        let other = base();
        write(&w, &other, MAIN);
        let w_bytes = std::fs::read(&w).unwrap();
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, "v.larsalvault"));
        let mut sub = Group::new(id(0x23), "Sub2".into(), T0);
        set_share(&mut sub, settings(false, true, "W.LARSALVAULT"));
        vault.root.groups.push(sub);
        let mut imp = Group::new(id(0x24), "Imp".into(), T0);
        set_share(&mut imp, settings(true, false, "v.larsalvault"));
        vault.root.groups.push(imp);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        s.open(w.to_string_lossy().into_owned()).unwrap();
        unlock(&s, v);
        assert!(s.share_paths(v).unwrap().is_empty());
        save(&s, v);
        save(&s, v);
        assert_eq!(std::fs::read(&w).unwrap(), w_bytes, "W overwritten");
        let again = read(&file, MAIN).expect("V still opens with demo-v");
        assert_eq!(again.root.name, "Root");
        assert!(again.root.find_group(id(0x20)).is_some());
        assert_eq!(news(&s, v), None, "nothing ran");
        // RT-4: letter case where no file answers: the target is not there
        // yet, so only the compare of names can tell.
        let gone = dir.join("gone.larsalvault");
        assert!(guarded(
            &dir.join("GONE.LARSALVAULT"),
            std::slice::from_ref(&gone),
            ""
        ));
        assert!(!guarded(&dir.join("OTHER.LARSALVAULT"), &[gone], ""));
    }

    /// F-269 (INT-08.34, AT-I04): a share on V's own backup file (the
    /// default pattern; backups are on) never runs, and the editor shows
    /// MI08-17 before the backup exists; each save's backup stays V under
    /// demo-v. At the write, an export never replaces an existing backup.
    #[test]
    fn f269_int08_34_a_share_on_the_vaults_backup_never_runs() {
        let dir = TempDir::new("share-f269");
        let (file, backup) = (dir.join("v.larsalvault"), dir.join("v.old.larsalvault"));
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, "v.old.larsalvault"));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(
            s.share_edit(v, hex(id(0x20))).unwrap().warning,
            Some(crate::share_edit::ShareWarning::OpenVault),
            "MI08-17"
        );
        s.share_edit_cancel(v).unwrap();
        save(&s, v);
        save(&s, v);
        read(&backup, MAIN).expect("the backup opens with demo-v");
        assert!(read(&backup, SHARE).is_err(), "exported over the backup");
        assert_eq!(news(&s, v), None, "nothing ran");
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        let keep = kept(vec![storage::real_path(&file)], "");
        let at_write = container::write_file(
            &backup,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &keep,
        );
        assert!(
            matches!(
                at_write,
                Err(Error::Io(std::io::ErrorKind::PermissionDenied))
            ),
            "{at_write:?}"
        );
        read(&backup, MAIN).expect("the backup still opens with demo-v");
    }

    /// T60 (D-INT08-9): person B exported Pay since V's last import and no
    /// watch told V; V's save imports Pay before it writes.
    #[test]
    fn t60_d_int08_9_a_sync_export_first_imports_what_another_member_wrote() {
        let dir = TempDir::new("share-t60");
        let (file, path, vault) = scene(&dir, true, true);
        publish(&path, &vault);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let mut b = base();
        team(&mut b).entries.push(entry(0x43, "Pay", "", "pw-p"));
        publish(&path, &b);
        save(&s, v);
        assert!(
            model(&s, v, |m| find(m, 0x43).is_some()),
            "Pay not imported"
        );
        let c = read(&path, SHARE).unwrap();
        assert!(
            c.root.all_entries().any(|e| e.uuid == id(0x43)),
            "Pay lost from the container"
        );
    }

    /// The Checks' two vaults: A and B synchronize Team on one container;
    /// each save keeps the other's changes.
    #[test]
    fn d_int08_9_two_sync_vaults_on_one_container_keep_each_others_changes() {
        let dir = TempDir::new("share-two");
        let path = dir.join("shared.larsalvault");
        let mut vault = base();
        set_share(team(&mut vault), settings(true, true, "shared.larsalvault"));
        publish(&path, &vault);
        let (a, b) = (session(true), session(true));
        let va = approved(&a, &dir.join("a.larsalvault"), &vault);
        let vb = approved(&b, &dir.join("b.larsalvault"), &vault);
        unlock(&a, va);
        unlock(&b, vb);
        let add = |s: &Session, v: u64, n: u8, title: &str| {
            let now = now();
            change(s, v, |m| {
                let mut e = entry(n, title, "", "pw");
                e.times.last_modification = now;
                team(m).entries.push(e);
            });
        };
        add(&a, va, 0x44, "From A");
        save(&a, va);
        add(&b, vb, 0x45, "From B");
        save(&b, vb);
        save(&a, va);
        for (s, v) in [(&a, va), (&b, vb)] {
            model(s, v, |m| {
                assert!(find(m, 0x44).is_some() && find(m, 0x45).is_some())
            });
        }
        let c = read(&path, SHARE).unwrap();
        let ids: Vec<Uuid> = c.root.all_entries().map(|e| e.uuid).collect();
        assert!(
            ids.contains(&id(0x44)) && ids.contains(&id(0x45)),
            "{ids:?}"
        );
    }

    /// INT-08.38: a container whose KDF takes a long time never blocks
    /// the vault; the session answers at once while it runs.
    #[test]
    fn t61_int08_38_a_slow_container_never_blocks_the_vault() {
        let dir = TempDir::new("share-t61");
        let (file, path, vault) = scene(&dir, true, false);
        let mut slow = member();
        slow.encryption.kdf = Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 40,
            memory_kib: 65_536,
            lanes: 1,
        };
        publish(&path, &slow);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        let start = Instant::now();
        let busy = |s: &Session| s.with_share(v, |slot| slot.share.running).unwrap();
        let (mut calls, mut slowest) = (0, Duration::ZERO);
        while busy(&s) {
            let t = Instant::now();
            let _ = s.list(v, crate::views::ListView::All).unwrap();
            let _ = s.save_status(v).unwrap();
            slowest = slowest.max(t.elapsed());
            calls += 1;
            std::thread::sleep(Duration::from_millis(20));
        }
        let took = start.elapsed();
        assert!(
            took > Duration::from_millis(300),
            "the KDF took only {took:?}"
        );
        assert!(calls >= 5, "{calls} calls in {took:?}");
        assert!(
            slowest < Duration::from_millis(150),
            "a call waited {slowest:?}"
        );
        assert_eq!(mail(&s, v), "pw-2");
    }

    /// T62 (AT-C06, INT-08.39): during T23's import, T27's failure and
    /// T29's exports, no text that leaves the share code holds the share
    /// password.
    #[test]
    fn t62_at_c06_no_share_password_in_any_output() {
        let dir = TempDir::new("share-t62");
        let (file, path, vault) = scene(&dir, true, true);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        let mut out = Vec::new();
        unlock(&s, v);
        out.push(format!("{:?}", news(&s, v)));
        save(&s, v);
        out.push(format!("{:?}", news(&s, v)));
        publish_with(&path, &member(), "other");
        look(&s, v, &path);
        out.push(format!("{:?}", news(&s, v)));
        out.push(format!("{:?}", s.share_paths(v)));
        out.push(format!("{:?}", s.settings.share_approvals()));
        out.push(format!("{:?}", s.approve_share(v, hex(id(0x21)))));
        model(&s, v, |m| {
            let shares = run::shares(m, Some(&file));
            out.push(format!("{shares:?}"));
            out.push(format!("{:?}", run::plan(shares, true, true)));
            out.push(format!(
                "{:?}",
                share_item::of(m.root.find_group(id(0x20)).unwrap())
            ));
        });
        let all = out.join("\n");
        assert!(all.contains("team.larsalvault"), "{all}");
        assert!(!all.contains(SHARE) && !all.contains("other\""), "{all}");
    }

    /// T67 (LD-281 (1)): V's own KDF is in the ask band (parallelism 129).
    /// V's export asks nothing and keeps V's settings with a fresh salt; W's
    /// import of that container is refused at once, without a question.
    #[test]
    fn t67_ld281_1_an_ask_band_container_is_refused_at_import_without_a_question() {
        let dir = TempDir::new("share-t67");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let mut vault = base();
        vault.encryption.kdf = Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 1,
            memory_kib: 65_536,
            lanes: 129,
        };
        set_share(team(&mut vault), settings(false, true, "team.larsalvault"));
        let s = session(true);
        let v = approved(&s, &file, &vault);
        let asked = s.unlock(v, Some(MAIN.into()), None).unwrap();
        assert!(matches!(asked, UnlockResult::Ask { .. }), "{asked:?}");
        assert_eq!(s.approve_unlock(v).unwrap(), UnlockResult::Unlocked);
        save(&s, v);
        assert_eq!(news(&s, v), None, "the export asked or failed");
        let lim = Limits::DEFAULT;
        let params = |f: &Path| {
            let bytes = std::fs::read(f).unwrap();
            match larsal_format::header::read_header(&bytes, &lim)
                .unwrap()
                .kdf
            {
                larsal_crypto::kdf::KdfParams::Argon2 {
                    iterations,
                    memory_kib,
                    lanes,
                    salt,
                    ..
                } => ((iterations, memory_kib, lanes), salt),
                larsal_crypto::kdf::KdfParams::AesKdf { .. } => panic!("Argon2"),
            }
        };
        let ((vp, vs), (cp, cs)) = (params(&file), params(&path));
        assert_eq!(cp, (1, 65_536, 129));
        assert_eq!(vp, cp);
        assert_ne!(vs, cs, "the container's salt is V's");
        // W imports the same path: MI08-02 at once, no question.
        let w = session(true);
        let mut wv = base();
        set_share(team(&mut wv), settings(true, false, "team.larsalvault"));
        let wid = approved(&w, &dir.join("w.larsalvault"), &wv);
        let start = Instant::now();
        unlock(&w, wid);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            banner(&w, wid),
            Some((
                ShareLevel::Error,
                vec![
                    "team.larsalvault: import failed. Its key settings need more memory or time than Larsal uses without asking."
                        .to_owned()
                ]
            ))
        );
        assert_eq!(mail(&w, wid), "pw-1");
        assert_eq!(w.save_status(wid).unwrap().changes, 0);
    }

    /// T68 (MOD-08.32, LD-279 (2), F-142): after B imports A's planted
    /// entry, its reference resolves to empty for display and copy; Team's
    /// own Alias still gives Bank's password.
    #[test]
    fn t68_mod08_32_a_planted_reference_imported_reads_nothing_outside_the_share() {
        let dir = TempDir::new("share-t68");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let alias_of = |m: &mut Vault| {
            let mut alias = entry(0x0D, "Alias", "", "");
            set(
                &mut alias,
                "Password",
                &format!("{{REF:P@I:{}}}", "0B".repeat(16)),
                true,
            );
            team(m).entries.push(alias);
        };
        let mut a = base();
        alias_of(&mut a);
        let mut wiki = entry(0x44, "Team wiki", "", "{REF:P@U:ann@example.com}");
        set(&mut wiki, "URL", "https://evil.example/login", false);
        wiki.times.last_modification = T2;
        team(&mut a).entries.push(wiki);
        publish(&path, &a);
        let mut b = base();
        alias_of(&mut b);
        let mut home = Group::new(id(0x30), "Home".into(), T0);
        home.entries
            .push(entry(0x0F, "Gmail", "ann@example.com", "gmail-secret-demo"));
        b.root.groups.push(home);
        set_share(team(&mut b), settings(true, false, "team.larsalvault"));
        let s = session(true);
        let v = approved(&s, &file, &b);
        unlock(&s, v);
        assert!(
            model(&s, v, |m| find(m, 0x44).is_some()),
            "Team wiki imported"
        );
        let show = |n: u8| s.show_field(v, hex(id(n)), "Password".into()).unwrap();
        assert_eq!(show(0x44), "");
        assert_eq!(show(0x0D), "pw-b");
        assert_eq!(show(0x0F), "gmail-secret-demo");
        let detail = format!("{:?}", s.entry(v, hex(id(0x44))).unwrap());
        assert!(!detail.contains("gmail-secret-demo"));
        let hits = s.search(v, "gmail-secret-demo".into()).unwrap();
        assert!(!format!("{hits:?}").contains(&hex(id(0x44))));
    }

    /// INT-08.16: a missing container is told once per unlock, not on every
    /// watch.
    #[test]
    fn int08_16_a_missing_container_is_told_once_per_unlock() {
        let dir = TempDir::new("share-missing");
        let (file, path, vault) = scene(&dir, true, false);
        std::fs::remove_file(&path).unwrap();
        let s = session(true);
        let v = approved(&s, &file, &vault);
        let told = vec![
            "team.larsalvault: import failed. The file or its folder is not there.".to_owned(),
        ];
        unlock(&s, v);
        assert_eq!(banner(&s, v), Some((ShareLevel::Error, told.clone())));
        look(&s, v, &path);
        assert_eq!(news(&s, v), None);
        s.lock(v).unwrap();
        unlock(&s, v);
        assert_eq!(banner(&s, v), Some((ShareLevel::Error, told)));
    }

    /// The container of T61, whose KDF runs long enough for the vault to
    /// change while it is read: `member()`'s Team under a slow Argon2.
    fn publish_slow(path: &Path) {
        let mut slow = member();
        slow.encryption.kdf = Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 40,
            memory_kib: 65_536,
            lanes: 1,
        };
        publish(path, &slow);
    }

    /// Unlocks vault `v` and waits until its first pass has read the
    /// shares (the survey) and is reading the container.
    fn unlock_running(s: &Session, v: u64) {
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        let surveyed = |s: &Session| s.with_share(v, |slot| !slot.share.seen.is_empty()).unwrap();
        for _ in 0..500 {
            if surveyed(s) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            surveyed(s) && running(s, v),
            "the import ended before the test went on"
        );
    }

    fn running(s: &Session, v: u64) -> bool {
        s.with_share(v, |slot| slot.share.running).unwrap()
    }

    /// INT-08.38 (F-157 C1): a save while an import of a Synchronize share
    /// runs queues one more export, which writes the save's change.
    #[test]
    fn int08_38_a_save_while_a_pass_runs_queues_one_more_export() {
        let dir = TempDir::new("share-queued");
        let (file, path, vault) = scene(&dir, true, true);
        publish_slow(&path);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock_running(&s, v);
        change(&s, v, |m| {
            team(m).entries.push(entry(0x43, "Pay", "", "pw-p"))
        });
        let st = s.save(v).unwrap();
        assert_eq!(st.failure, None, "{st:?}");
        assert!(running(&s, v), "the save came after the pass");
        s.share_wait(v);
        let c = read(&path, SHARE).unwrap();
        assert!(
            c.root.all_entries().any(|e| e.uuid == id(0x43)),
            "the save's change was not exported"
        );
        assert_eq!(mail(&s, v), "pw-2");
    }

    /// INT-08's edge case "group deleted while an import is pending", and a
    /// share set up again meanwhile (F-157 C2): the read container is
    /// dropped, with no banner line, and Team stays as it is.
    #[test]
    fn int08_16_a_share_deleted_or_changed_during_its_import_is_dropped() {
        let cases: [fn(&mut Vault); 2] = [
            |m| m.root.groups.clear(),
            |m| edit_share(team(m), |st| st.password = secret("other")),
        ];
        for (n, case) in cases.into_iter().enumerate() {
            let dir = TempDir::new(&format!("share-dropped-{n}"));
            let (file, path, vault) = scene(&dir, true, false);
            publish_slow(&path);
            let s = session(false);
            let v = approved(&s, &file, &vault);
            unlock_running(&s, v);
            change(&s, v, case);
            assert!(running(&s, v), "case {n}: the change came after the read");
            s.share_wait(v);
            assert_eq!(news(&s, v), None, "case {n}");
            model(&s, v, |m| {
                let mail = find(m, 0x0A).map(|e| e.value("Password").to_owned());
                assert_eq!(mail, (n == 1).then(|| "pw-1".to_owned()), "case {n}");
            });
        }
    }

    /// INT-08.16 with INT-08.20 (F-157 C3): a good read takes the path out
    /// of the told ones, so a container that goes missing again in the
    /// same unlock is told again.
    #[test]
    fn int08_16_a_container_missing_again_after_a_good_read_is_told_again() {
        let dir = TempDir::new("share-missing-again");
        let (file, path, vault) = scene(&dir, true, false);
        std::fs::remove_file(&path).unwrap();
        let s = session(true);
        let v = approved(&s, &file, &vault);
        let told = vec![
            "team.larsalvault: import failed. The file or its folder is not there.".to_owned(),
        ];
        unlock(&s, v);
        assert_eq!(banner(&s, v), Some((ShareLevel::Error, told.clone())));
        publish(&path, &member());
        look(&s, v, &path);
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(banner(&s, v), None);
        std::fs::remove_file(&path).unwrap();
        look(&s, v, &path);
        assert_eq!(banner(&s, v), Some((ShareLevel::Error, told)));
    }

    /// INT-08.15 (LD-216): each approved importing share gives its own path
    /// to watch; an export-only share and one not approved give none.
    #[test]
    fn int08_15_each_approved_importing_share_is_one_path_to_watch() {
        let dir = TempDir::new("share-paths");
        let (file, path, mut vault) = scene(&dir, true, false);
        let mut home = Group::new(id(0x30), "Home".into(), T0);
        set_share(&mut home, settings(true, false, "home.larsalvault"));
        let mut out = Group::new(id(0x31), "Out".into(), T0);
        set_share(&mut out, settings(false, true, "out.larsalvault"));
        vault.root.groups.push(home);
        vault.root.groups.push(out);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        change(&s, v, |m| {
            let mut late = Group::new(id(0x32), "Late".into(), T0);
            set_share(&mut late, settings(true, false, "late.larsalvault"));
            m.root.groups.push(late);
        });
        let mut paths = s.share_paths(v).unwrap();
        paths.sort();
        let named = |p: &Path| p.to_string_lossy().into_owned();
        assert_eq!(
            paths,
            vec![named(&dir.join("home.larsalvault")), named(&path)]
        );
    }

    /// INT-08.19 (F-159 K3, K4): a pause that comes while a pass reads a
    /// container stops the pass: it neither merges what it read nor writes
    /// the container, and tells nothing.
    #[test]
    fn int08_19_a_pause_during_a_running_pass_merges_and_writes_nothing() {
        let dir = TempDir::new("share-pause-running");
        let (file, path, vault) = scene(&dir, true, true);
        publish(&path, &vault);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let _ = news(&s, v);
        publish_slow(&path);
        let written = std::fs::read(&path).unwrap();
        let st = s.save(v).unwrap();
        assert_eq!(st.failure, None, "{st:?}");
        let taken = |s: &Session| {
            s.with_share(v, |slot| slot.share.running && slot.share.jobs.is_empty())
                .unwrap()
        };
        for _ in 0..500 {
            if taken(&s) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(taken(&s), "the pass ended before the pause");
        s.share_pause(v, true).unwrap();
        s.share_wait(v);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            written,
            "exported while paused"
        );
        assert_eq!(mail(&s, v), "pw-1", "imported while paused");
        assert_eq!(news(&s, v), None);
    }

    /// INT-08.20 with APP-05.2 (F-159 K6): the news keeps an earlier pass's
    /// "changed" until Swift takes it, also when a later pass changed
    /// nothing; the banner is the later pass's.
    #[test]
    fn int08_20_a_later_pass_keeps_the_changed_news_of_an_earlier_one() {
        let dir = TempDir::new("share-news-kept");
        let (file, _, vault) = scene(&dir, true, true);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-2");
        save(&s, v);
        let n = news(&s, v).expect("news");
        assert!(n.changed, "the import's change was lost");
        assert_eq!(
            n.banner.map(|b| b.lines),
            Some(vec!["team.larsalvault: exported.".to_owned()])
        );
    }

    /// INT-08.17 with T29 (F-160 M25): the head Larsal's export wrote is the
    /// one last seen for its path, so the next watch never reads the
    /// share's own export again.
    #[test]
    fn int08_17_the_head_an_export_wrote_is_the_one_last_seen() {
        let dir = TempDir::new("share-export-head");
        let (file, path, vault) = scene(&dir, true, true);
        publish(&path, &vault);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        save(&s, v);
        let key = PathBuf::from(s.share_paths(v).unwrap().remove(0));
        let kept = s
            .with_share(v, |slot| slot.share.heads.get(&key).copied())
            .unwrap();
        assert_eq!(kept, head_of(&path));
    }

    /// INT-08.31 with API.md's `approve_share` row (F-160 M12): an
    /// importing share imports at once when Larsal approves it.
    #[test]
    fn int08_31_an_approved_importing_share_imports_at_once() {
        let dir = TempDir::new("share-approve");
        let (file, _, vault) = scene(&dir, true, false);
        write(&file, &vault, MAIN);
        let s = session(true);
        let v = s.open(file.to_string_lossy().into_owned()).unwrap();
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-1", "imported before approval");
        s.approve_share(v, hex(id(0x20))).unwrap();
        s.share_wait(v);
        assert_eq!(mail(&s, v), "pw-2");
    }

    /// LD-139 (F-160 M19): an import that changed the vault drops the
    /// ratings, so the Health Check runs again.
    #[test]
    fn ld139_an_import_drops_the_ratings() {
        let dir = TempDir::new("share-rated");
        let (file, path, vault) = scene(&dir, true, false);
        std::fs::remove_file(&path).unwrap();
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let _ = news(&s, v);
        while !s.rate(v, 100, 0).unwrap() {}
        assert!(s.sidebar(v).unwrap().attention.is_some());
        publish(&path, &member());
        look(&s, v, &path);
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(s.sidebar(v).unwrap().attention, None);
    }

    /// INT-08.20 (F-160 M9): a banner Swift has not taken yet stays when a
    /// later pass has none (quiet drops its success line).
    #[test]
    fn int08_20_a_banner_not_taken_yet_stays_after_a_pass_without_one() {
        let dir = TempDir::new("share-banner-kept");
        let (file, path, vault) = scene(&dir, true, false);
        publish_with(&path, &member(), "other");
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        publish(&path, &member());
        look(&s, v, &path);
        let n = news(&s, v).expect("news");
        assert!(n.changed);
        assert_eq!(
            n.banner.map(|b| b.lines),
            Some(vec![
                "team.larsalvault: import failed. The share password is wrong.".to_owned()
            ])
        );
    }

    /// MOD-11.14 (F-161): a container entry with Mail's Mod but other
    /// content goes into Mail's history; that import is a change, told
    /// with MI08-01 and saved (INT-08.16 step 4, APP-05.2).
    #[test]
    fn mod11_14_a_same_time_import_is_a_change_and_is_saved() {
        let dir = TempDir::new("share-same-time");
        let (file, path, vault) = scene(&dir, true, false);
        let mut m = base();
        set(
            team(&mut m).entries.first_mut().unwrap(),
            "Password",
            "pw-2",
            true,
        );
        publish(&path, &m);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-1");
        let n = news(&s, v).expect("the import is told");
        assert!(n.changed);
        assert_eq!(
            n.banner.map(|b| (b.level, b.lines)),
            Some((
                ShareLevel::Success,
                vec!["team.larsalvault: changes imported.".to_owned()]
            ))
        );
        assert_eq!(s.save_status(v).unwrap().changes, 1);
        save(&s, v);
        let saved = read(&file, MAIN).unwrap();
        let history: Vec<String> = find(&saved, 0x0A)
            .unwrap()
            .history
            .iter()
            .map(|h| h.value("Password").to_owned())
            .collect();
        assert_eq!(history, ["pw-2"]);
    }

    /// INT-08.12 step 4 (A1): with KeepGroups off, a save exports Team's
    /// own entries and no group below it (Sub and Wiki stay out).
    #[test]
    fn int08_12_a_keep_off_export_leaves_the_groups_below_out() {
        let dir = TempDir::new("share-keep-off");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let mut vault = base();
        let mut st = settings(false, true, "team.larsalvault");
        st.keep_groups = false;
        set_share(team(&mut vault), st);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        save(&s, v);
        let c = read(&path, SHARE).unwrap();
        assert_eq!(titles(&c.root), ["Mail", "Bank"]);
        assert!(c.root.groups.is_empty());
        assert!(find(&c, 0x0C).is_none());
    }

    /// INT-08.15 step 4, Larsal's rule (A3): export turned on while import is
    /// on imports every share again, as at unlock.
    #[test]
    fn int08_15_step_4_export_turned_on_while_import_is_on_imports_again() {
        let dir = TempDir::new("share-export-on");
        let (file, path, vault) = scene(&dir, true, false);
        let s = Session::new();
        flags(&s, true, false, true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-2");
        // The container changes; no watch tells it.
        let mut m = member();
        team(&mut m).entries.push(entry(0x40, "News", "", "pw-n"));
        publish(&path, &m);
        flags(&s, true, true, true);
        s.share_wait(v);
        assert!(model(&s, v, |m| find(m, 0x40).is_some()));
    }

    /// APP-06.16: a lock wipes the vault's share state (news, settings
    /// hashes, file hashes); the next unlock starts afresh.
    #[test]
    fn app06_16_a_lock_wipes_the_share_state() {
        let dir = TempDir::new("share-lock");
        let (file, _, vault) = scene(&dir, true, false);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let kept = |s: &Session| {
            s.with_share(v, |slot| {
                (
                    slot.share.news.is_some(),
                    !slot.share.seen.is_empty(),
                    !slot.share.heads.is_empty(),
                )
            })
            .unwrap()
        };
        assert_eq!(kept(&s), (true, true, true));
        s.lock(v).unwrap();
        // The settings hashes hold the share password: wiped with the rest.
        assert_eq!(kept(&s), (false, false, false));
        assert_eq!(s.take_share_news(v), Ok(None));
        assert!(s.share_paths(v).unwrap().is_empty());
        assert_eq!(s.approve_share(v, hex(id(0x20))), Err(LarsalError::Locked));
    }

    /// Ids for `n` new demo objects, from `tag`.
    fn ids(tag: u8, n: u32) -> impl Iterator<Item = Uuid> {
        (0..n).map(move |i| {
            let mut u = [tag; 16];
            u[..4].copy_from_slice(&i.to_le_bytes());
            Uuid(u)
        })
    }

    /// F-162 (INT-08.34, AT-I04), Checker 2's probe: V at `home/x.larsalvault`
    /// under a slow Argon2id, with Home → Gmail; Team exports to
    /// `shared/x.larsalvault`. Right after a good save, while the export's KDF
    /// runs, `shared` becomes a link to `home`. V's file still opens with
    /// `demo-v` and holds Gmail; a refused write tells MI08-03.
    #[test]
    fn f162_at_i04_a_share_folder_swapped_during_the_export_kdf_gets_no_write() {
        let dir = TempDir::new("share-f162");
        let (home, shared) = (dir.join("home"), dir.join("shared"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&shared).unwrap();
        let (file, to) = (home.join("x.larsalvault"), shared.join("x.larsalvault"));
        let mut vault = base();
        vault.encryption.kdf = Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 40,
            memory_kib: 65_536,
            lanes: 1,
        };
        let mut h = Group::new(id(0x25), "Home".into(), T0);
        h.entries
            .push(entry(0x0D, "Gmail", "", "gmail-secret-demo"));
        vault.root.groups.push(h);
        let text = to.to_string_lossy().into_owned();
        set_share(team(&mut vault), settings(false, true, &text));
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        change(&s, v, |m| {
            let gmail = group_mut(&mut m.root, 0x25).unwrap().entries.first_mut();
            set(gmail.unwrap(), "Password", "gmail-secret-demo-2", true);
        });
        // RT-4: the swap lands right after the look, before the KDF, every
        // run; no timing can let the write come first.
        let (from, old, to_home) = (shared.clone(), dir.join("shared-old"), home.clone());
        s.with_share(v, |slot| {
            slot.share.before_write = Some(Box::new(move |_: &Session| {
                std::fs::rename(&from, &old).unwrap();
                std::os::unix::fs::symlink(&to_home, &from).unwrap();
            }));
        })
        .unwrap();
        let st = s.save(v).unwrap();
        assert_eq!(st.failure, None, "{st:?}");
        s.share_wait(v);
        let again = read(&file, MAIN).expect("V still opens with demo-v");
        let gmail = again.root.all_entries().find(|e| e.uuid == id(0x0D));
        assert_eq!(gmail.unwrap().value("Password"), "gmail-secret-demo-2");
        let refused = format!(
            "{text}: export failed. The file could not be written: Larsal may not use the file or its folder."
        );
        match banner(&s, v) {
            Some(b) => assert_eq!(b, (ShareLevel::Error, vec![refused])),
            // The write came before the swap: into the folder as it was.
            None => assert!(read(&dir.join("shared-old/x.larsalvault"), SHARE).is_ok()),
        }
        let temp = std::fs::read_dir(&home)
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!temp, "a temp file left in V's folder");
    }

    /// F-163 (INT-08.36, FMT-08.12, AT-A08), Checker 2's probe: T23's
    /// scene with 1 deleted-object item in V and 1,000,000 (the reader's
    /// limit) in the member's container, for ids V does not hold. The
    /// merged vault would pass the limit, so the import is refused with
    /// MI08-02; V is unchanged and still saves and opens.
    ///
    /// Changed by R6 (INT-08.32, FMT-15.12): a share's items are rows, off the main
    /// list and at most the cap, so this container no longer passes the limit. The
    /// import goes through, the list stays 1 and V saves and opens. The refusal itself
    /// is proved by `f163_at_a08_one_item_past_the_custom_data_limit_is_refused`.
    #[test]
    fn f163_at_a08_a_full_list_in_a_container_is_rows_and_v_still_saves() {
        let dir = TempDir::new("share-f163");
        let (file, path, mut vault) = scene(&dir, true, false);
        let gone = |uuid| DeletedObject {
            uuid,
            deleted_at: T0,
            unknown: Vec::new(),
        };
        vault.deleted_objects.push(gone(id(0x60)));
        let mut m = member();
        m.deleted_objects = ids(0xD0, 1_000_000).map(gone).collect();
        publish(&path, &m);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(model(&s, v, |m| m.deleted_objects.len()), 1);
        assert_eq!(
            model(&s, v, |m| larsal_core::origin::read_rows(
                &m.meta.custom_data
            )
            .len()),
            larsal_core::origin::ROW_CAP
        );
        change(&s, v, |m| m.meta.name = "V2".into());
        save(&s, v);
        let again = read(&file, MAIN).expect("V still opens");
        assert_eq!(
            (again.meta.name.as_str(), again.deleted_objects.len()),
            ("V2", 1)
        );
    }

    /// F-163 under R6 (round 5, C1R4-03): a container entry at exactly the reader's
    /// custom data limit, new to V. Base takes this import, so it is not refused: the
    /// import's marker does not fit (one door), the entry comes in without it, and V
    /// saves and opens with the entry at the limit.
    #[test]
    fn f163_at_a08_an_entry_at_the_custom_data_limit_imports_without_a_marker() {
        let dir = TempDir::new("share-f163-item");
        let (file, path, vault) = scene(&dir, true, false);
        let mut m = member();
        let mut heavy = Entry::new(id(0x61), T0);
        for i in 0..larsal_format::limits::Limits::DEFAULT.custom_data_items {
            heavy.custom_data.items.push(CustomDataItem {
                key: format!("k{i}"),
                value: SecretString::new("v".to_owned()),
                last_modified: None,
                unknown: Vec::new(),
            });
        }
        team(&mut m).entries.push(heavy);
        publish(&path, &m);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(banner(&s, v), None);
        assert_eq!(mail(&s, v), "pw-2");
        let limit = larsal_format::limits::Limits::DEFAULT.custom_data_items;
        let heavy = |m: &Vault| {
            m.root.all_entries().find(|e| e.uuid == id(0x61)).map(|e| {
                (
                    e.custom_data.items.len(),
                    larsal_core::origin::mark_of(&e.custom_data),
                )
            })
        };
        assert_eq!(model(&s, v, heavy), Some((limit, None)));
        change(&s, v, |m| m.meta.name = "V2".into());
        save(&s, v);
        let again = read(&file, MAIN).expect("V still opens");
        assert_eq!(again.meta.name, "V2");
        assert_eq!(heavy(&again), Some((limit, None)));
    }

    /// F-164 (INT-08.38, AT-A08), Checker 2's probe 2 at unlock: Team of
    /// the container holds a new group named with 524,288 'A' and 4,000
    /// new entries. The import holds the session lock only briefly: no call
    /// of the screen waits 75 ms (about 5 ms here; 140 to 330 ms when each
    /// record held the whole path).
    #[test]
    fn f164_int08_38_a_long_group_name_times_many_entries_never_holds_the_lock() {
        let dir = TempDir::new("share-f164");
        let (file, path, vault) = scene(&dir, true, false);
        let mut m = member();
        let mut long = Group::new(id(0x30), "A".repeat(524_288), T0);
        long.entries = ids(0x77, 4_000).map(|u| Entry::new(u, T0)).collect();
        team(&mut m).groups.push(long);
        publish(&path, &m);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        let (mut calls, mut slowest) = (0, Duration::ZERO);
        loop {
            let t = Instant::now();
            let busy = running(&s, v);
            let _ = s.list(v, crate::views::ListView::All).unwrap();
            let _ = s.save_status(v).unwrap();
            slowest = slowest.max(t.elapsed());
            calls += 1;
            if !busy {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            slowest < Duration::from_millis(75),
            "a call waited {slowest:?} ({calls} calls)"
        );
        let held = model(&s, v, |m| {
            m.root.find_group(id(0x30)).map(|g| g.entries.len())
        });
        assert_eq!(held, Some(4_000));
    }

    /// The slowest `lock_epoch`, `list` and `save_status` call while vault
    /// `v`'s share work runs (and of the look at whether it runs, so a
    /// lock held between two rounds is seen too), and the number of rounds.
    /// At most 60 s, as [`Session::share_wait`].
    fn slowest_call(s: &Session, v: u64) -> (Duration, u32) {
        let start = Instant::now();
        let (mut rounds, mut slowest) = (0, Duration::ZERO);
        let mut timed = |f: &dyn Fn()| {
            let t = Instant::now();
            f();
            slowest = slowest.max(t.elapsed());
        };
        loop {
            let busy = std::cell::Cell::new(false);
            timed(&|| busy.set(running(s, v)));
            timed(&|| {
                s.lock_epoch(v).unwrap();
            });
            timed(&|| {
                s.list(v, crate::views::ListView::All).unwrap();
            });
            timed(&|| {
                s.save_status(v).unwrap();
            });
            rounds += 1;
            if !busy.get() {
                return (slowest, rounds);
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "share work did not end"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The member's V (Mail `pw-2`) with, in Team, a chain of 450 nested
    /// groups and `n` new entries at the bottom (F-165, F-167).
    fn deep_member(n: u32) -> Vault {
        let mut m = member();
        let mut chain: Vec<Uuid> = ids(0x78, 450).collect();
        let mut deep = Group::new(chain.pop().unwrap(), "Deep".into(), T0);
        deep.entries = ids(0x79, n).map(|u| Entry::new(u, T0)).collect();
        for u in chain.into_iter().rev() {
            let mut up = Group::new(u, "Deep".into(), T0);
            up.groups.push(deep);
            deep = up;
        }
        team(&mut m).groups.push(deep);
        m
    }

    /// F-165 (INT-08.38, AT-A08), Checker 2's probe: T23's scene, and in
    /// the member's Team a chain of 450 nested groups with 20,000 new
    /// entries at the bottom. The merge runs on a copy, off the session
    /// lock, so at the first unlock (which imports) and at the next (which
    /// changes nothing) no `lock_epoch`, `list` or `save_status` call
    /// waits a second (seconds when the merge ran under the lock; E11S6-V-02:
    /// 75 ms broke on a loaded Mac, with calls of about 5 ms in a quiet one).
    /// The result is the same.
    #[test]
    fn f165_int08_38_a_deep_chain_import_never_holds_the_lock_at_either_unlock() {
        let dir = TempDir::new("share-f165");
        let (file, path, vault) = scene(&dir, true, false);
        publish(&path, &deep_member(20_000));
        let s = session(false);
        let v = approved(&s, &file, &vault);
        let count = |s: &Session| model(s, v, |m| m.root.all_entries().count());
        for first in [true, false] {
            assert_eq!(
                s.unlock(v, Some(MAIN.into()), None).unwrap(),
                UnlockResult::Unlocked
            );
            let (slowest, rounds) = slowest_call(&s, v);
            assert!(
                slowest < Duration::from_secs(1),
                "unlock {first}: a call waited {slowest:?} ({rounds} rounds)"
            );
            assert_eq!(count(&s), 20_003);
            let imported = (
                ShareLevel::Success,
                vec!["team.larsalvault: changes imported.".to_owned()],
            );
            assert_eq!(banner(&s, v), first.then_some(imported));
            assert_eq!(s.save_status(v).unwrap().changes, u32::from(first));
            if first {
                save(&s, v);
            }
            s.lock(v).unwrap();
        }
    }

    /// INT-08.34: past the plan the write itself keeps a key file, even one
    /// that opens as this share's container, so the look passes.
    #[test]
    fn e11s6_rt1_the_write_itself_keeps_the_key_file() {
        let dir = TempDir::new("e11s6-keep-key");
        let (file, key) = (dir.join("v.larsalvault"), dir.join("k.larsalkey"));
        publish(&key, &member());
        let bytes = std::fs::read(&key).unwrap();
        let mut vault = base();
        set_share(team(&mut vault), settings(false, true, "k.larsalkey"));
        let s = session(false);
        s.save_settings(vec![crate::larsal_settings::LarsalSetting {
            key: "recent.remember_keys".into(),
            value: crate::larsal_settings::LarsalSettingValue::Flag { on: true },
        }])
        .unwrap();
        s.settings.note_keys(
            &dir.join("other.larsalvault"),
            Some("k.larsalkey".into()),
            None,
        );
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        let (share, epoch) = s
            .with_share(v, |slot| {
                let share = run::shares(slot.vault.unwrap(), Some(slot.path)).remove(0);
                (share, slot.epoch)
            })
            .unwrap();
        let mut lines = Vec::new();
        s.export(v, epoch, &share, &mut lines);
        assert_eq!(std::fs::read(&key).unwrap(), bytes);
        assert_eq!(
            run::banner(&lines, false).unwrap().lines,
            [
                "k.larsalkey: export failed. The file could not be written: Larsal may not use the file or its folder."
            ]
        );
    }

    /// F-165: a change the user makes while an import's trial runs wins:
    /// the merged copy is dropped and the share imports again, on the
    /// vault with that change.
    #[test]
    fn f165_int08_38_an_edit_during_the_trial_wins_and_the_share_imports_again() {
        let dir = TempDir::new("share-f165-edit");
        let (file, _, vault) = scene(&dir, true, false);
        let s = session(false);
        let v = approved(&s, &file, &vault);
        s.with_share(v, |slot| {
            slot.share.trial = Some(Box::new(move |s: &Session| {
                change(s, v, |m| m.meta.name = "V2".into());
            }));
        })
        .unwrap();
        unlock(&s, v);
        assert!(s.with_share(v, |slot| slot.share.trial.is_none()).unwrap());
        assert_eq!(model(&s, v, |m| m.meta.name.clone()), "V2");
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(
            banner(&s, v),
            Some((
                ShareLevel::Success,
                vec!["team.larsalvault: changes imported.".to_owned()]
            ))
        );
        assert_eq!(s.save_status(v).unwrap().changes, 1);
    }

    /// F-167 (INT-08.38), Checker 2's probe: T23's scene with a 450-group
    /// chain and 6,000 new entries in the member's Team (a trial of about
    /// 2 s here), and the editor open on Bank, its live code asked for as
    /// the Entry page does (here every 100 ms, more often than its once a
    /// second). A draft call only reads the vault, so it is not a change:
    /// the import lands while the calls go on (it never did when each call
    /// counted, and one core stayed busy).
    #[test]
    fn f167_int08_38_the_editors_live_code_never_holds_an_import_back() {
        let dir = TempDir::new("share-f167");
        let (file, path, vault) = scene(&dir, true, false);
        publish(&path, &deep_member(6_000));
        let s = session(true);
        let v = approved(&s, &file, &vault);
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        s.begin_edit(v, crate::views::hex(id(0x0B))).unwrap();
        let start = Instant::now();
        while running(&s, v) {
            s.draft_code(v).unwrap();
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the import never landed while the editor was open"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(mail(&s, v), "pw-2");
        assert_eq!(model(&s, v, |m| m.root.all_entries().count()), 6_003);
        assert_eq!(s.editor(v).unwrap().title, "Bank");
    }

    /// F-165: the merged copy that replaces V keeps V's own KDF settings,
    /// not the trial's one AES-KDF round, so V's next save is as strong.
    #[test]
    fn f165_the_swapped_in_copy_keeps_the_vaults_kdf() {
        let dir = TempDir::new("share-f165-kdf");
        let (file, _, vault) = scene(&dir, true, false);
        let s = session(true);
        let v = approved(&s, &file, &vault);
        unlock(&s, v);
        assert_eq!(mail(&s, v), "pw-2");
        let kdf = model(&s, v, |m| m.encryption.kdf);
        assert_eq!(kdf, Kdf::AesKdf { rounds: 1_000 });
    }

    /// LD-304 (5), AT-I04 (T52): a share item that arrives by APP-05.27's
    /// disk merge (another app saved the file with a Synchronize share on
    /// Team while this window had an unsaved change) is neither watched nor
    /// exported before Approve; the save after Approve writes the container.
    #[test]
    fn ld_304_5_at_i04_a_share_from_a_disk_merge_runs_only_after_approve() {
        use crate::saving::{DiskAsk, DiskChoice, DiskEvent};
        let dir = TempDir::new("share-ld304");
        let (file, path) = (dir.join("v2.larsalvault"), dir.join("team.larsalvault"));
        write(&file, &base(), MAIN);
        let s = session(false);
        let v = s.open(file.to_string_lossy().into_owned()).unwrap();
        unlock(&s, v);
        s.add_group(v, None, "Local".into(), 48, None).unwrap();
        let mut other = base();
        set_share(team(&mut other), settings(true, true, "team.larsalvault"));
        team(&mut other).times.last_modification = T2;
        write(&file, &other, MAIN);
        assert_eq!(
            s.check_disk(v).unwrap(),
            DiskEvent::Ask {
                ask: DiskAsk::Unsaved,
                changes: 1
            }
        );
        assert_eq!(
            s.resolve_disk(v, DiskChoice::Merge).unwrap(),
            DiskEvent::Reloaded
        );
        s.share_wait(v);
        model(&s, v, |m| {
            let team = m.root.find_group(id(0x20)).unwrap();
            assert!(
                share_item::of(team).is_some(),
                "the merge brought the share"
            );
            assert!(
                m.root.groups.iter().any(|g| g.name == "Local"),
                "and kept mine"
            );
        });
        assert!(
            s.share_paths(v).unwrap().is_empty(),
            "watched before Approve"
        );
        save(&s, v);
        assert!(!path.exists(), "exported before Approve");
        assert_eq!(news(&s, v), None);
        s.approve_share(v, hex(id(0x20))).unwrap();
        s.share_wait(v);
        let _ = news(&s, v);
        assert_eq!(
            s.share_paths(v).unwrap(),
            vec![path.to_string_lossy().into_owned()],
            "watched after Approve"
        );
        save(&s, v);
        let c = read(&path, SHARE).expect("the save after Approve writes the container");
        assert_eq!(c.root.uuid, id(0x20));
        assert_eq!(titles(&c.root), ["Mail", "Bank"]);
    }

    /// LD-297 (3) A2, AT-A08: a FIFO at an import share's container path
    /// is refused at once; the pass never waits on it.
    #[test]
    fn ld_297_3_at_a08_a_fifo_at_the_container_path_never_waits() {
        let dir = TempDir::new("share-fifo");
        let (file, path) = (dir.join("v.larsalvault"), dir.join("team.larsalvault"));
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let mut vault = base();
        set_share(team(&mut vault), settings(true, false, "team.larsalvault"));
        let s = session(true);
        let v = approved(&s, &file, &vault);
        assert_eq!(
            s.unlock(v, Some(MAIN.into()), None).unwrap(),
            UnlockResult::Unlocked
        );
        let start = Instant::now();
        while s.with_share(v, |slot| slot.share.running).unwrap() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the pass waits on the FIFO"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            banner(&s, v),
            Some((
                ShareLevel::Error,
                vec![
                    "team.larsalvault: import failed. The path is not a file Larsal can use."
                        .to_owned()
                ]
            ))
        );
        assert_eq!(mail(&s, v), "pw-1");
    }
}

#[cfg(test)]
mod backup_regressions {
    use super::tests::*;
    use super::*;
    use crate::share_edit::ShareMode;
    use larsal_model::Time;
    use larsal_share::Error;
    const T2: Time = Time(63_907_920_000);
    fn host() -> larsal_crypto::kdf::Host {
        larsal_crypto::kdf::Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: Some(larsal_crypto::kdf::SpeedRecord {
                count: 100_000_000,
                memory_kib: 0,
                lanes: 1,
                ms: 1000,
            }),
        }
    }
    use crate::larsal_settings::{LarsalSetting, LarsalSettingValue};
    use crate::test_dir::TempDir;
    fn backup_settings(s: &Session, enabled: bool, pattern: &str) {
        s.save_settings(vec![
            LarsalSetting {
                key: "backup.enabled".into(),
                value: LarsalSettingValue::Flag { on: enabled },
            },
            LarsalSetting {
                key: "backup.pattern".into(),
                value: LarsalSettingValue::Text {
                    text: pattern.into(),
                },
            },
        ])
        .unwrap();
    }
    #[test]
    fn t70_matrix_no_import_export_and_mi08_17() {
        let mut count = 0;
        for enabled in [false, true] {
            for existing in [false, true] {
                for configured in [false, true] {
                    for other in [false, true] {
                        count += 1;
                        let dir = TempDir::new(&format!("share-matrix-{count}"));
                        let file = dir.join("v.larsalvault");
                        let w = dir.join("other.larsalvault");
                        let stem = if other { "other" } else { "v" };
                        let pattern = "{FILE_NAME}-backup-{TIME:HHmmss}.larsalvault";
                        let name = if configured {
                            format!("{stem}-backup-any-text.larsalvault")
                        } else {
                            format!("{stem}.old.larsalvault")
                        }
                        .to_uppercase();
                        let dest = dir.join(&name);
                        let mut vault = base();
                        set_share(team(&mut vault), settings(true, true, &name));
                        let s = session(false);
                        backup_settings(&s, enabled, pattern);
                        if other {
                            write(&w, &base(), MAIN);
                            s.open(w.to_string_lossy().into_owned()).unwrap();
                        }
                        if existing {
                            write(&dest, &base(), MAIN);
                        }
                        let before = std::fs::read(&dest).ok();
                        let v = approved(&s, &file, &vault);
                        unlock(&s, v);
                        assert_eq!(mail(&s, v), "pw-1");
                        assert!(s.share_paths(v).unwrap().is_empty());
                        assert_eq!(
                            s.share_edit(v, hex(id(0x20))).unwrap().warning,
                            Some(crate::share_edit::ShareWarning::OpenVault),
                            "MI08-17 case {count}"
                        );
                        s.share_edit_cancel(v).unwrap();
                        save(&s, v);
                        assert_eq!(news(&s, v), None, "no pass case {count}");
                        assert_eq!(
                            std::fs::read(&dest).ok(),
                            before,
                            "destination case {count}"
                        );
                        if existing {
                            let open = if other {
                                vec![file.clone(), w.clone()]
                            } else {
                                vec![file.clone()]
                            };
                            let keep = kept(open, pattern);
                            let c = container::build(id(0x20), true, &vault, T2).unwrap();
                            let result = container::write_file(
                                &dest,
                                &c,
                                &secret(SHARE),
                                &mut host(),
                                &Limits::DEFAULT,
                                &keep,
                            );
                            assert!(
                                matches!(
                                    result,
                                    Err(Error::Io(std::io::ErrorKind::PermissionDenied))
                                ),
                                "write case {count}: {result:?}"
                            );
                            assert_eq!(
                                std::fs::read(&dest).ok(),
                                before,
                                "write preservation case {count}"
                            );
                        }
                        read(&file, MAIN).unwrap();
                    }
                }
            }
        }
        assert_eq!(count, 16);
        println!("T70: {count} matrix scenes, existing-backup writes refused");
    }
    #[test]
    fn f269_existing_casefold_backup_write_must_refuse() {
        let dir = TempDir::new("share-casefold");
        let file = dir.join("v.larsalvault");
        let backup = dir.join("V.OLD.LARSALVAULT");
        let vault = base();
        write(&file, &vault, MAIN);
        write(&backup, &vault, MAIN);
        let before = std::fs::read(&backup).unwrap();
        assert!(
            guarded(&backup, std::slice::from_ref(&file), ""),
            "early guard covers it"
        );
        let keep = kept(vec![file.clone()], "");
        println!(
            "casefold backup in keep={}",
            keep.iter()
                .any(|p| storage::file_id(p) == storage::file_id(&backup))
        );
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        let result = container::write_file(
            &backup,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &keep,
        );
        println!(
            "write={result:?}; backup opens main={} share={}",
            read(&backup, MAIN).is_ok(),
            read(&backup, SHARE).is_ok()
        );
        assert!(
            matches!(result, Err(Error::Io(std::io::ErrorKind::PermissionDenied))),
            "existing matching backup must be protected at write"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), before);
        read(&backup, MAIN).unwrap();
    }
    #[test]
    fn f269_backup_match_alias_and_controls() {
        let dir = TempDir::new("share-match");
        let real = dir.join("v.larsalvault");
        write(&real, &base(), MAIN);
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap();
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&*dir, &alias).unwrap();
        for name in [
            "v-backup-.larsalvault",
            "v-backup-nonnumeric.larsalvault",
            "V-BACKUP-123.LARSALVAULT",
        ] {
            assert!(
                storage::is_backup(
                    "{FILE_NAME}-backup-{TIME}.larsalvault",
                    &real,
                    &home,
                    &alias.join(name)
                ),
                "{name}"
            );
        }
        assert!(!storage::is_backup(
            "{FILE_NAME}-backup-{TIME}.larsalvault",
            &real,
            &home,
            &dir.join("other-backup-123.larsalvault")
        ));
        assert!(storage::is_backup(
            "~/demo/{FILE_NAME}.old.larsalvault",
            &real,
            &home,
            &home.join("demo/v.old.larsalvault")
        ));
    }

    #[test]
    fn f269_missing_literal_prefix_alias_guard_before_actual_save() {
        let dir = TempDir::new("share-missing-prefix-guard");
        let file = dir.join("v.larsalvault");
        let vault = base();
        write(&file, &vault, MAIN);
        std::os::unix::fs::symlink(&*dir, dir.join("alias")).unwrap();
        let pattern = "alias/new/{TIME:yyyy}/{FILE_NAME}.old.larsalvault";
        let t = larsal_model::times::Civil {
            year: 1999,
            month: 11,
            day: 4,
            hour: 12,
            minute: 34,
            second: 56,
        };
        let backup = storage::backup_path(pattern, &file, t, 0, &dir);
        let canonical = dir.join("new/1999/v.old.larsalvault");
        let before_alias = guarded(&backup, std::slice::from_ref(&file), pattern);
        let before_canonical = guarded(&canonical, std::slice::from_ref(&file), pattern);
        let bytes = std::fs::read(&file).unwrap();
        let mut q = storage::SaveRequest::plain(&file, &bytes, None, &dir);
        q.backup = Some(storage::Backup {
            pattern,
            local: t,
            millis: 0,
            home: &dir,
        });
        assert_eq!(storage::save(&q).unwrap().backup, Some(Ok(backup.clone())));
        assert_eq!(std::fs::read(&backup).unwrap(), bytes);
        read(&backup, MAIN).unwrap();
        assert_eq!(storage::file_id(&backup), storage::file_id(&canonical));
        let after = guarded(&canonical, std::slice::from_ref(&file), pattern);
        println!(
            "missing fixed prefix guard: alias={before_alias}, canonical={before_canonical}, after actual save={after}, bytes preserved=true, main reopen=true"
        );
        assert!(after);
        assert!(
            before_alias && before_canonical,
            "INT08.34 requires the permitted backup name to be guarded before its missing folders are created"
        );
    }

    #[test]
    fn t69_each_invalid_item_stays_shared_without_running() {
        for raw in [true, false] {
            let dir = TempDir::new(if raw {
                "share-raw-state"
            } else {
                "share-path-state"
            });
            let file = dir.join("v.larsalvault");
            let victim = dir.join("victim.larsalvault");
            std::fs::write(&victim, b"demo canary").unwrap();
            let mut vault = base();
            let path = if raw {
                "victim.larsalvault".to_owned()
            } else {
                format!("{}a", "é".repeat(2048))
            };
            set_share(team(&mut vault), settings(true, true, &path));
            if raw {
                let item = team(&mut vault).custom_data.items.last_mut().unwrap();
                let mut value = item.value.expose().to_owned();
                value.extend(std::iter::repeat_n(
                    '!',
                    larsal_format::share_item::MAX_VALUE + 1 - value.len(),
                ));
                item.value = larsal_crypto::secret::SecretString::new(value);
            }
            let s = session(false);
            let v = approved(&s, &file, &vault);
            unlock(&s, v);
            let label = s.share_label(v, hex(id(0x20))).unwrap().unwrap();
            assert_eq!(label.state, crate::share_edit::ShareState::Off);
            assert_eq!(label.mode, ShareMode::Inactive);
            assert!(label.path.is_empty() && label.full_path.is_empty());
            assert!(!s.share_marks(v).unwrap()[0].active);
            let rows = s.share_rows(v).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].mode, ShareMode::Inactive);
            assert!(rows[0].path.is_empty() && !rows[0].active);
            let page = s.share_edit(v, hex(id(0x20))).unwrap();
            assert!(page.item);
            assert_eq!(page.mode, ShareMode::Inactive);
            assert!(page.path.is_empty());
            s.share_edit_cancel(v).unwrap();
            assert!(s.share_paths(v).unwrap().is_empty());
            save(&s, v);
            assert_eq!(news(&s, v), None);
            assert_eq!(std::fs::read(&victim).unwrap(), b"demo canary");
        }
    }

    #[test]
    fn f269_folder_swap_reaches_casefold_backup() {
        let dir = TempDir::new("share-backup-swap");
        let home = dir.join("home");
        let shared = dir.join("shared");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&shared).unwrap();
        let file = home.join("v.larsalvault");
        let backup = home.join("V.OLD.LARSALVAULT");
        let target = shared.join("V.OLD.LARSALVAULT");
        let vault = base();
        write(&file, &vault, MAIN);
        write(&backup, &vault, MAIN);
        let before = std::fs::read(&backup).unwrap();
        assert!(
            !guarded(&target, std::slice::from_ref(&file), ""),
            "legitimate share at preflight"
        );
        let keep = kept(vec![file.clone()], "");
        std::fs::rename(&shared, dir.join("shared-before")).unwrap();
        std::os::unix::fs::symlink(&home, &shared).unwrap();
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        let result = container::write_file(
            &target,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &keep,
        );
        println!(
            "post-preflight folder swap: write={result:?}, main={} share={}",
            read(&backup, MAIN).is_ok(),
            read(&backup, SHARE).is_ok()
        );
        assert!(
            matches!(result, Err(Error::Io(std::io::ErrorKind::PermissionDenied))),
            "folder-swap write must preserve the existing backup"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), before);
        read(&backup, MAIN).unwrap();
    }

    fn c2r3_directory_case(tag: &str, pattern: &str, year: i64) {
        let dir = TempDir::new(tag);
        let file = dir.join("v.larsalvault");
        let vault = base();
        write(&file, &vault, MAIN);
        let t = larsal_model::times::Civil {
            year,
            month: 11,
            day: 4,
            hour: 12,
            minute: 34,
            second: 56,
        };
        let backup = storage::backup_path(pattern, &file, t, 0, &dir);
        let original = std::fs::read(&file).unwrap();
        let mut request = storage::SaveRequest::plain(&file, &original, None, &dir);
        request.backup = Some(storage::Backup {
            pattern,
            local: t,
            millis: 0,
            home: &dir,
        });
        let saved = storage::save(&request).unwrap();
        assert_eq!(
            saved.backup,
            Some(Ok(backup.clone())),
            "the actual save accepts and creates this backup pattern"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), original);
        read(&backup, MAIN).unwrap();
        let before = std::fs::read(&backup).unwrap();
        let guard = guarded(&backup, std::slice::from_ref(&file), pattern);
        let keep = kept(vec![file.clone()], pattern);
        let listed = keep
            .iter()
            .any(|p| storage::file_id(p) == storage::file_id(&backup));
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        let result = container::write_file(
            &backup,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &keep,
        );
        let preserved = std::fs::read(&backup).unwrap() == before;
        let main = read(&backup, MAIN).is_ok();
        let shared = read(&backup, SHARE).is_ok();
        println!(
            "pattern={pattern} generated={backup:?} guarded={guard} listed={listed} writer={result:?} preserved={preserved} main={main} share={shared}"
        );
        assert!(
            guard && listed && preserved && main && !shared,
            "APP05 permitted backup path must remain protected"
        );
        assert!(matches!(
            result,
            Err(Error::Io(std::io::ErrorKind::PermissionDenied))
        ));
    }
    #[test]
    fn c2r3_fixed_directory_positive_control() {
        c2r3_directory_case(
            "c2r3-fixed-directory",
            "backups/fixed/{FILE_NAME}.old.larsalvault",
            2026,
        );
    }
    #[test]
    fn c2r3_time_directory_existing_backup_must_be_protected() {
        c2r3_directory_case(
            "c2r3-time-directory",
            "backups/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
            2026,
        );
    }
    #[test]
    fn c2r3_slash_time_format_existing_backup_must_be_protected() {
        c2r3_directory_case(
            "c2r3-slash-directory",
            "backups/{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
            2026,
        );
    }
    #[test]
    fn c2r3_time_directory_absent_destination_must_be_guarded() {
        let dir = TempDir::new("c2r3-time-absent");
        let file = dir.join("v.larsalvault");
        write(&file, &base(), MAIN);
        let backup_dir = dir.join("backups/2026");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let target = backup_dir.join("v.old.larsalvault");
        let got = guarded(
            &target,
            std::slice::from_ref(&file),
            "backups/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
        );
        println!("absent time-directory path guarded={got}");
        assert!(
            got,
            "INT08.34 must guard permitted backup names before creation"
        );
    }
    #[test]
    fn c2r3_unrelated_filename_in_backup_directory_can_write() {
        let dir = TempDir::new("c2r3-backup-negative");
        let file = dir.join("v.larsalvault");
        let vault = base();
        write(&file, &vault, MAIN);
        std::fs::create_dir_all(dir.join("backups/fixed")).unwrap();
        let dest = dir.join("backups/fixed/team.larsalvault");
        let pattern = "backups/fixed/{FILE_NAME}.old.larsalvault";
        assert!(!guarded(&dest, std::slice::from_ref(&file), pattern));
        let keep = kept(vec![file.clone()], pattern);
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        container::write_file(
            &dest,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &keep,
        )
        .unwrap();
        read(&dest, SHARE).unwrap();
        read(&file, MAIN).unwrap();
    }

    #[test]
    fn f269_older_multi_component_directory_backup_refuses_write() {
        c2r3_directory_case(
            "f269-old-multi-directory",
            "backups/{TIME:yyyy/MM/dd}/{FILE_NAME}-{TIME}.old.larsalvault",
            1999,
        );
    }

    #[test]
    fn f269_directory_t70_no_import_export_and_mi08_17() {
        let mut count = 0;
        for (pattern, folder) in [
            (
                "backups/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
                "backups/1999",
            ),
            (
                "backups/{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault",
                "backups/1999/01",
            ),
        ] {
            for enabled in [false, true] {
                for existing in [false, true] {
                    count += 1;
                    let dir = TempDir::new("share-directory-matrix");
                    let file = dir.join("v.larsalvault");
                    let relative = format!("{folder}/V.OLD.LARSALVAULT");
                    let dest = dir.join(&relative);
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let mut vault = base();
                    set_share(team(&mut vault), settings(true, true, &relative));
                    if existing {
                        write(&dest, &base(), MAIN);
                    }
                    let before = std::fs::read(&dest).ok();
                    let s = session(false);
                    backup_settings(&s, enabled, pattern);
                    let v = approved(&s, &file, &vault);
                    unlock(&s, v);
                    assert_eq!(mail(&s, v), "pw-1");
                    assert!(s.share_paths(v).unwrap().is_empty());
                    assert_eq!(
                        s.share_edit(v, hex(id(0x20))).unwrap().warning,
                        Some(crate::share_edit::ShareWarning::OpenVault)
                    );
                    s.share_edit_cancel(v).unwrap();
                    save(&s, v);
                    assert_eq!(news(&s, v), None);
                    assert_eq!(std::fs::read(&dest).ok(), before);
                    if existing {
                        assert!(
                            kept(vec![file.clone()], pattern)
                                .iter()
                                .any(|p| storage::file_id(p) == storage::file_id(&dest))
                        );
                        read(&dest, MAIN).unwrap();
                    }
                    read(&file, MAIN).unwrap();
                }
            }
        }
        assert_eq!(count, 8);
        println!("T70: {count} older-directory scenes");
    }

    #[test]
    fn f269_same_backup_name_in_unrelated_folder_can_write() {
        let dir = TempDir::new("share-unrelated-directory");
        let file = dir.join("v.larsalvault");
        let vault = base();
        write(&file, &vault, MAIN);
        let dest = dir.join("unrelated/1999/01/v.old.larsalvault");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let pattern = "backups/{TIME:yyyy/MM}/{FILE_NAME}.old.larsalvault";
        assert!(!guarded(&dest, std::slice::from_ref(&file), pattern));
        let c = container::build(id(0x20), true, &vault, T2).unwrap();
        container::write_file(
            &dest,
            &c,
            &secret(SHARE),
            &mut host(),
            &Limits::DEFAULT,
            &kept(vec![file.clone()], pattern),
        )
        .unwrap();
        read(&dest, SHARE).unwrap();
        read(&file, MAIN).unwrap();
    }
    #[test]
    fn f269_parent_components_alias_guard_and_editor_before_actual_save() {
        let mut missed = Vec::new();
        for (n, (pattern, suffix)) in [
            (
                "alias/new/{TIME:yyyy}/../fixed/{FILE_NAME}.old.larsalvault",
                "new/fixed/v.old.larsalvault",
            ),
            (
                "alias/new/{TIME:yyyy/../MM}/{FILE_NAME}.old.larsalvault",
                "new/11/v.old.larsalvault",
            ),
            (
                "alias/new/{TIME:'..'}/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
                "1999/v.old.larsalvault",
            ),
            (
                "alias/new/{TIME:'.'}{TIME:'.'}/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
                "1999/v.old.larsalvault",
            ),
            (
                "alias/new/{TIME:yyyy/MM}/../fixed/{FILE_NAME}.old.larsalvault",
                "new/1999/fixed/v.old.larsalvault",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = TempDir::new(&format!("f269-fix5-parent-components-{n}"));
            let file = dir.join("v.larsalvault");
            std::os::unix::fs::symlink(&*dir, dir.join("alias")).unwrap();
            let mut vault = base();
            set_share(team(&mut vault), settings(true, true, suffix));
            let s = session(false);
            backup_settings(&s, false, pattern);
            let v = approved(&s, &file, &vault);
            unlock(&s, v);
            let t = larsal_model::times::Civil {
                year: 1999,
                month: 11,
                day: 4,
                hour: 12,
                minute: 34,
                second: 56,
            };
            let generated = storage::backup_path(pattern, &file, t, 0, &dir);
            let canonical = dir.join(suffix);
            let before_literal = guarded(&generated, std::slice::from_ref(&file), pattern);
            let before_canonical = guarded(&canonical, std::slice::from_ref(&file), pattern);
            let warning = s.share_edit(v, hex(id(0x20))).unwrap().warning;
            let watched = s.share_paths(v).unwrap();
            println!(
                "parent scene {n}: before literal={before_literal}, canonical={before_canonical}, editor={warning:?}, watched={watched:?}"
            );
            s.share_edit_cancel(v).unwrap();
            assert!(!guarded(
                &dir.join(format!("other/{suffix}")),
                std::slice::from_ref(&file),
                pattern
            ));
            let bytes = std::fs::read(&file).unwrap();
            let mut q = storage::SaveRequest::plain(&file, &bytes, None, &dir);
            q.backup = Some(storage::Backup {
                pattern,
                local: t,
                millis: 0,
                home: &dir,
            });
            assert_eq!(
                storage::save(&q).unwrap().backup,
                Some(Ok(generated.clone()))
            );
            assert_eq!(std::fs::read(&generated).unwrap(), bytes);
            read(&generated, MAIN).unwrap();
            assert_eq!(std::fs::canonicalize(&generated).unwrap(), canonical);
            assert_eq!(storage::file_id(&generated), storage::file_id(&canonical));
            assert!(guarded(&canonical, std::slice::from_ref(&file), pattern));
            let keep = kept(vec![file.clone()], pattern);
            assert!(
                keep.iter()
                    .any(|p| storage::file_id(p) == storage::file_id(&canonical))
            );
            let c = container::build(id(0x20), true, &vault, T2).unwrap();
            let result = container::write_file(
                &canonical,
                &c,
                &secret(SHARE),
                &mut host(),
                &Limits::DEFAULT,
                &keep,
            );
            assert!(matches!(
                result,
                Err(Error::Io(std::io::ErrorKind::PermissionDenied))
            ));
            assert_eq!(std::fs::read(&canonical).unwrap(), bytes);
            read(&canonical, MAIN).unwrap();
            read(&file, MAIN).unwrap();
            println!(
                "parent scene {n}: actual save=true, canonical inode=true, encrypted bytes=true, original password reopen=true, after guard=true, final writer refused=true"
            );
            if !(before_literal
                && before_canonical
                && warning == Some(crate::share_edit::ShareWarning::OpenVault)
                && watched.is_empty())
            {
                missed.push(n);
            }
        }
        assert!(
            missed.is_empty(),
            "INT08.34 and MI08-17 miss actual permitted canonical names before folder creation: {missed:?}"
        );
    }

    #[test]
    fn f269_missing_parent_normalization_unrelated_actual_share() {
        for (n, (pattern, correct, unrelated)) in [
            (
                "alias/../new/{TIME:yyyy}/{FILE_NAME}.old.larsalvault",
                "nested/new/1999/v.old.larsalvault",
                "new/1999/v.old.larsalvault",
            ),
            (
                "alias/new/{TIME:yyyy}/../fixed/{FILE_NAME}.old.larsalvault",
                "nested/real/new/fixed/v.old.larsalvault",
                "new/fixed/v.old.larsalvault",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = TempDir::new(&format!("f269-fix5-normalization-negative-{n}"));
            std::fs::create_dir_all(dir.join("nested/real")).unwrap();
            std::os::unix::fs::symlink(dir.join("nested/real"), dir.join("alias")).unwrap();
            let file = dir.join("v.larsalvault");
            let vault = base();
            write(&file, &vault, MAIN);
            let target = dir.join(unrelated);
            assert!(!target.parent().unwrap().exists());
            assert!(!guarded(&target, std::slice::from_ref(&file), pattern));
            let t = larsal_model::times::Civil {
                year: 1999,
                month: 11,
                day: 4,
                hour: 12,
                minute: 34,
                second: 56,
            };
            let backup = storage::backup_path(pattern, &file, t, 0, &dir);
            let bytes = std::fs::read(&file).unwrap();
            let mut q = storage::SaveRequest::plain(&file, &bytes, None, &dir);
            q.backup = Some(storage::Backup {
                pattern,
                local: t,
                millis: 0,
                home: &dir,
            });
            assert_eq!(storage::save(&q).unwrap().backup, Some(Ok(backup.clone())));
            assert_eq!(std::fs::canonicalize(&backup).unwrap(), dir.join(correct));
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            assert!(!guarded(&target, std::slice::from_ref(&file), pattern));
            let keep = kept(vec![file.clone()], pattern);
            assert!(
                keep.iter()
                    .any(|p| storage::file_id(p) == storage::file_id(&backup))
            );
            let c = container::build(id(0x20), true, &vault, T2).unwrap();
            container::write_file(
                &target,
                &c,
                &secret(SHARE),
                &mut host(),
                &Limits::DEFAULT,
                &keep,
            )
            .unwrap();
            read(&target, SHARE).unwrap();
            assert_eq!(std::fs::read(&backup).unwrap(), bytes);
            read(&backup, MAIN).unwrap();
            read(&file, MAIN).unwrap();
            println!(
                "normalization negative {n}: unrelated absent parent guard=false, actual backup in distinct canonical folder, unrelated write allowed, backup encrypted bytes preserved and reopen=true"
            );
        }
    }
}
