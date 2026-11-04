//! Import, export and the safety rules (INT-08.15 to INT-08.20, INT-08.31,
//! INT-08.32, INT-08.34, INT-08.37): which shares of a vault may run, the
//! import merge inside the share group, and the lines of a pass's banner.
//! When and on which thread a pass runs is app-ffi's (INT-08.38).
//!
//! Guarantees: an import merges with app-core's shared-group import as it
//! is, so it moves, changes and erases only inside the share group (LD-61,
//! LD-130); [`fits`] runs it on a copy and tells whether the result still
//! saves under the reader's limits (F-163, F-165); a line holds the path
//! as stored, counts, group names and a reason in plain words, never a
//! password or other vault value (INT-08.39).

use crate::settings::{self, Item, Mode, Settings};
use crate::{Error, NotShare};
use app_core::merge::{ChangeKind, Kind, Options, merge};
use app_core::recycle;
use app_crypto::kdf::{CostReport, Host};
use app_crypto::secret::SecretString;
use app_format::Saved;
use app_format::limits::Limits;
use app_model::{Kdf, Time, Uuid, Vault};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The bytes of a container whose SHA-256 tells a change (INT-08.15).
pub const HEAD: usize = 5 * 1024;

/// SHA-256 of the first [`HEAD`] bytes: a rewrite of a vault always changes
/// them (CRY-03), so this catches every save (INT-08.15).
#[must_use]
pub fn head(bytes: &[u8]) -> [u8; 32] {
    let hash = app_crypto::hash::sha256(&[bytes.get(..HEAD).unwrap_or(bytes)]);
    hash.expose().try_into().unwrap_or([0; 32])
}

/// A share that is set up: a readable item, not Inactive, a path, a vault
/// with a file, not in the recycle bin.
pub struct Share {
    /// The share group.
    pub group: Uuid,
    /// The group's name, for MI08-05 and MI08-06.
    pub name: String,
    /// The settings; the path as stored.
    pub settings: Settings,
    /// The resolved path (INT-08.5).
    pub path: PathBuf,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("group", &self.group)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Share {
    /// INT-08.31: the approval record of this share in `vault`: the vault
    /// id (the root group's id), the group id and the SHA-256 of the mode
    /// and the resolved path, in hex. A change of mode or path needs a new
    /// approval.
    #[must_use]
    pub fn approval(&self, vault: &Vault) -> String {
        let mode = match self.settings.mode() {
            Mode::Inactive => "inactive",
            Mode::Import => "import",
            Mode::Export => "export",
            Mode::Synchronize => "synchronize",
        };
        let path = self.path.to_string_lossy();
        let hash = app_crypto::hash::sha256(&[mode.as_bytes(), b"\n", path.as_bytes()]);
        format!(
            "{}:{}:{}",
            hex(&vault.root.uuid.0),
            hex(&self.group.0),
            hex(hash.expose())
        )
    }

    /// INT-08.15 step 2: what a change of the settings is told by (mode,
    /// path, password and `Group` id; not `KeepGroups`), as a hash that
    /// holds the password, so it is a secret.
    #[must_use]
    pub fn seen(&self) -> app_crypto::secret::SecretBytes {
        let s = &self.settings;
        let mode = [u8::from(s.import), u8::from(s.export)];
        let path = u64::try_from(s.path.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        app_crypto::hash::sha256(&[
            &mode,
            &s.group.0,
            &path,
            s.path.as_bytes(),
            s.password.expose().as_bytes(),
        ])
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every set-up share of `vault`, whose file is `file`, in group tree order
/// (INT-08.15 step 1). An invalid item (INT-08.4), an Inactive share, one
/// without a path, a share in the recycle bin (INT-08.35) and every share
/// of a vault with no file (INT-08.5) are left out.
#[must_use]
pub fn shares(vault: &Vault, file: Option<&Path>) -> Vec<Share> {
    let Some(file) = file else {
        return Vec::new();
    };
    vault
        .root
        .subtree()
        .into_iter()
        .filter_map(|g| {
            let Some(Item::Settings(s)) = settings::of(g) else {
                return None;
            };
            if !s.valid() || recycle::group_in_bin(vault, g.uuid) {
                return None;
            }
            let path = settings::resolve(&s.path, Some(file))?;
            Some(Share {
                group: g.uuid,
                name: g.name.clone(),
                settings: s,
                path,
            })
        })
        .collect()
}

/// What a pass may run, after the path conflicts of INT-08.18.
#[derive(Debug, Default)]
pub struct Plan {
    /// The shares, in group tree order.
    pub shares: Vec<Share>,
    /// Indexes into `shares` of the imports to run, in tree order.
    pub imports: Vec<usize>,
    /// Indexes of the exports to run, in path text order; none when two
    /// exporting shares name one path (one conflict blocks every export).
    pub exports: Vec<usize>,
    /// MI08-05, one per path that several shares import (D-INT08-7: none
    /// of them is imported).
    pub import_lines: Vec<Line>,
    /// MI08-06, one per path that several shares export.
    pub export_lines: Vec<Line>,
}

/// The plan for `shares` (the ones the caller lets run: approved, INT-08.31,
/// and not a vault's file, INT-08.34), with import and export allowed or not
/// (INT-08.7). Conflicts compare the path text as stored (INT-08.5).
#[must_use]
pub fn plan(shares: Vec<Share>, allow_import: bool, allow_export: bool) -> Plan {
    let mut plan = Plan::default();
    let importing: Vec<usize> = (0..shares.len())
        .filter(|&i| allow_import && shares.get(i).is_some_and(|s| s.settings.importing()))
        .collect();
    let exporting: Vec<usize> = (0..shares.len())
        .filter(|&i| allow_export && shares.get(i).is_some_and(|s| s.settings.exporting()))
        .collect();
    let text = |i: usize| shares.get(i).map_or("", |s| s.settings.path.as_str());
    let names = |of: &[usize], path: &str| -> Vec<String> {
        of.iter()
            .filter(|&&i| text(i) == path)
            .filter_map(|&i| shares.get(i).map(|s| s.name.clone()))
            .collect()
    };
    let mut done: Vec<&str> = Vec::new();
    for &i in &importing {
        let path = text(i);
        let same = names(&importing, path);
        if same.len() > 1 {
            if !done.contains(&path) {
                done.push(path);
                plan.import_lines.push(several_import(path, &same));
            }
        } else {
            plan.imports.push(i);
        }
    }
    let mut paths: Vec<&str> = exporting.iter().map(|&i| text(i)).collect();
    paths.sort_unstable();
    paths.dedup();
    for path in paths {
        let same = names(&exporting, path);
        if same.len() > 1 {
            plan.export_lines.push(several_export(path, &same));
        }
    }
    if plan.export_lines.is_empty() {
        plan.exports = exporting;
        plan.exports.sort_by(|&a, &b| text(a).cmp(text(b)));
    }
    plan.shares = shares;
    plan
}

/// What an import merge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Imported {
    /// The vault changed (MI08-01); with no change nothing is reported and
    /// the vault is not marked changed (INT-08.16 step 4).
    pub changed: bool,
    /// Container objects whose id is outside the share group, skipped with
    /// a Conflict record (MI08-19, INT-08.32).
    pub outside: usize,
}

/// INT-08.16 step 3: merges `container` (opened by
/// [`crate::container::open`], so without nested share items, INT-08.33)
/// into share group `group` of `vault`: app-core's shared-group import, as
/// it is (synchronize mode, ids only inside the group, no vault custom
/// data; MOD-11.1, MOD-11.15, LD-61, LD-130).
///
/// # Errors
/// [`Error::NoGroup`] when the group is gone; [`Error::RandomSource`].
pub fn merge_into(
    vault: &mut Vault,
    group: Uuid,
    container: &Vault,
    now: Time,
) -> Result<Imported, Error> {
    let o = Options {
        target_start: Some(group),
        ..Options::new(Kind::SharedImport)
    };
    let merged = merge(vault, container, &o, now).map_err(|e| match e {
        app_core::Error::RandomSource => Error::RandomSource,
        _ => Error::NoGroup,
    })?;
    let outside = merged
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Conflict && c.details.iter().any(|d| d == OUTSIDE))
        .count();
    Ok(Imported {
        changed: merged
            .changes
            .iter()
            .any(|c| c.kind != ChangeKind::Conflict || c.details.iter().any(|d| d == SAME_TIME)),
        outside,
    })
}

/// F-163 (FMT-08.12, AT-A08): [`merge_into`] of `container` into `group`
/// of `copy`, a copy of the vault, then whether the result still saves.
/// The result goes through the save's own check (app-format builds the
/// file and reads its document back under [`Limits::DEFAULT`]) under a
/// fresh random key with one AES-KDF round, so there is no key work of
/// note; nothing is written. What the merge did, and the merged copy when
/// it changed something (F-165: the caller swaps it in, so the merge never
/// runs under the session lock); a merge that changes nothing passes.
///
/// # Errors
/// [`Error::Vault`] with the save's reason (`TooLarge` names the limit);
/// those of [`merge_into`].
pub fn fits(
    mut copy: Vault,
    group: Uuid,
    container: &Vault,
    now: Time,
    host: &mut Host,
) -> Result<(Imported, Option<Vault>), Error> {
    let got = merge_into(&mut copy, group, container, now)?;
    if !got.changed {
        return Ok((got, None));
    }
    let kdf = copy.encryption.kdf;
    copy.encryption.kdf = Kdf::AesKdf { rounds: 1 };
    let random = app_crypto::random::bytes(32).map_err(|_| Error::RandomSource)?;
    let mut text = String::with_capacity(64);
    for b in random.expose() {
        let _ = write!(text, "{b:02x}");
    }
    let password = SecretString::new(text);
    let key = crate::container::credentials(&password);
    let limits = Limits::DEFAULT;
    let mut save = |approval: Option<&CostReport>| {
        app_format::save(&copy, &key, None, host, &limits, approval).map_err(Error::Vault)
    };
    if let Saved::Ask(report) = save(None)? {
        save(Some(&report))?;
    }
    copy.encryption.kdf = kdf;
    Ok((got, Some(copy)))
}

/// app-core's detail of a Conflict record for an id outside the shared
/// group (MOD-11, LD-61).
const OUTSIDE: &str = "outside the shared group";

/// MOD-11.14: the source's version went into the history.
const SAME_TIME: &str = "same time, different content";

/// The kind of a banner line and of the banner (INT-08.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// A success line.
    Success,
    /// A warning line.
    Warning,
    /// An error line.
    Error,
}

/// One line of a pass (the Messages table of INT-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Its kind.
    pub level: Level,
    /// App's text; starts with the path as stored.
    pub text: String,
    /// That path as stored, which the screen sets in the mono font.
    pub path: String,
}

fn line(level: Level, path: &str, text: String) -> Line {
    Line {
        level,
        text,
        path: path.to_owned(),
    }
}

/// MI08-01.
#[must_use]
pub fn imported(path: &str) -> Line {
    line(Level::Success, path, format!("{path}: changes imported."))
}

/// MI08-02, or MI08-04 when the file is not a share file.
#[must_use]
pub fn import_failed(path: &str, e: &Error) -> Line {
    let text = match e {
        Error::NotShare(why) => {
            let why = match why {
                NotShare::UnknownKind => "unknown file kind",
                NotShare::NoVault => "the archive holds no vault",
                NotShare::TwoVaults => "the archive holds two vaults",
            };
            format!("{path}: import failed. It is not a share file ({why}).")
        }
        e => format!("{path}: import failed. {}", reason(e)),
    };
    line(Level::Error, path, text)
}

/// MI08-03 success.
#[must_use]
pub fn exported(path: &str) -> Line {
    line(Level::Success, path, format!("{path}: exported."))
}

/// MI08-03 failure; a failed write gives MI08-07 as its reason.
#[must_use]
pub fn export_failed(path: &str, e: &Error) -> Line {
    let why = match e {
        Error::Io(kind) => format!("The file could not be written: {}", system(*kind)),
        e => reason(e),
    };
    line(Level::Error, path, format!("{path}: export failed. {why}"))
}

/// MI08-05.
#[must_use]
pub fn several_import(path: &str, groups: &[String]) -> Line {
    let groups = groups.join(", ");
    line(
        Level::Warning,
        path,
        format!(
            "{path}: imported by several groups ({groups}), so none of them is updated until only one imports it."
        ),
    )
}

/// MI08-06.
#[must_use]
pub fn several_export(path: &str, groups: &[String]) -> Line {
    let groups = groups.join(", ");
    line(
        Level::Error,
        path,
        format!(
            "{path}: exported by several groups ({groups}), so nothing was exported. Give each group its own file."
        ),
    )
}

/// MI08-19.
#[must_use]
pub fn outside(path: &str, count: usize) -> Line {
    line(
        Level::Warning,
        path,
        format!(
            "{path}: {count} items were not imported because they belong outside this shared group."
        ),
    )
}

/// The reason of MI08-02 and MI08-03 in plain words: no path, no value.
fn reason(e: &Error) -> String {
    use app_format::Error as F;
    use app_format::limits::Limit;
    match e {
        Error::Vault(F::WrongKey) => "The share password is wrong.".into(),
        Error::Vault(F::TooLarge(Limit::KdfCost)) => {
            "Its key settings need more memory or time than App uses without asking.".into()
        }
        Error::Vault(F::TooLarge(_)) => "It is larger than App reads.".into(),
        Error::Vault(F::Corrupt) => "It is damaged.".into(),
        Error::Vault(F::Unsupported | F::OldFormat) => "It uses a format App cannot read.".into(),
        Error::Vault(F::Io(kind)) | Error::Io(kind) => system(*kind),
        Error::Vault(_) | Error::NotShare(_) => "It is not a vault App can read.".into(),
        Error::NoGroup => "The shared group is no longer in the vault.".into(),
        Error::Recycled => "The shared group is in the recycle bin.".into(),
        Error::RandomSource => "The random source failed.".into(),
    }
}

/// The system's reason in plain words.
fn system(kind: std::io::ErrorKind) -> String {
    use std::io::ErrorKind as K;
    match kind {
        K::NotFound => "The file or its folder is not there.".into(),
        K::PermissionDenied => "App may not use the file or its folder.".into(),
        K::StorageFull => "There is no space left on the disk.".into(),
        K::ReadOnlyFilesystem => "The disk is read-only.".into(),
        K::InvalidInput => "The path is not a file App can use.".into(),
        K::FileTooLarge => "It is larger than App reads.".into(),
        other => {
            let text = other.to_string();
            let mut chars = text.chars();
            chars.next().map_or_else(String::new, |first| {
                format!("{}{}.", first.to_uppercase(), chars.as_str())
            })
        }
    }
}

/// The banner of one pass (INT-08.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    /// Error if any line is one, else warning if any, else success.
    pub level: Level,
    /// The lines: successes first, then warnings, then errors.
    pub lines: Vec<String>,
    /// The path as stored that each of `lines` starts with.
    pub paths: Vec<String>,
}

/// One banner for all `lines` of a pass; success lines are left out when
/// `quiet` (`share.quiet_success`); `None` when nothing is left.
#[must_use]
pub fn banner(lines: &[Line], quiet: bool) -> Option<Banner> {
    let mut kept: Vec<&Line> = lines
        .iter()
        .filter(|l| !(quiet && l.level == Level::Success))
        .collect();
    kept.sort_by_key(|l| l.level);
    let level = kept.last()?.level;
    Some(Banner {
        level,
        lines: kept.iter().map(|l| l.text.clone()).collect(),
        paths: kept.iter().map(|l| l.path.clone()).collect(),
    })
}
