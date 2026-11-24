//! Vault settings (MOD-12) and master key change reminders (MOD-13), story
//! E4-S14: the values behind the vault settings screen, applied all
//! together or not at all, and the reminder status after an unlock.
//!
//! Guarantees:
//! - [`apply`] runs every check and needs every confirmation first; a
//!   refusal changes nothing (D-12-1). A control left untouched (`None`)
//!   keeps the stored value exactly, even one outside the screen's range
//!   (D-12-2, MOD-13.12).
//! - `SettingsChanged` moves only when a value of the settings group
//!   changed (MOD-12.9, LD-33); the name, description and default user
//!   name times move only when their value changes (MOD-12.3).
//! - Nothing here lowers the cipher, the KDF cost or a protection flag
//!   without the user's confirmation of the MOD-12.12 warnings; the
//!   password is always protected (MOD-12.16, MOD-12.17, AT-A09).
//! - No error or record holds a value from the vault.

use crate::merge::last_modified_text;
use crate::{Error, edit, history, recycle, tree};
use larsal_crypto::kdf::{self, Argon2Type, Ceilings, Clock, CostReport, Host, KdfParams, Verdict};
use larsal_crypto::secret::SecretString;
use larsal_model::custom_data::CustomDataItem;
use larsal_model::{
    Argon2Kind, Cipher, Compression, CustomData, Entry, Field, Group, Kdf, Meta, PublicItem, Time,
    Uuid, Vault,
};

/// The highest history item limit the screen takes (MOD-12.5, MOD-03.10).
pub const MAX_HISTORY_ITEMS: i32 = 100_000;
/// The highest history size limit, in MiB (MOD-12.5).
pub const MAX_HISTORY_MIB: i32 = 2_047;
/// The day range of the key change controls (MOD-13.12, D-13-7).
pub const MAX_KEY_DAYS: i32 = 3_650;
/// Argon2 iterations above this warn (MOD-12.12).
pub const SLOW_ITERATIONS: u64 = 10_000;
/// AES-KDF rounds below this warn (MOD-12.12, CRY-02.24).
pub const WEAK_ROUNDS: u64 = 100_000;
/// Argon2 memory below this needs a confirm (MOD-12.12, D-12-6).
pub const SAFE_MEMORY_KIB: u64 = 19_456;
/// Argon2 iterations below this need a confirm (MOD-12.12, D-12-6).
pub const SAFE_ITERATIONS: u64 = 2;
/// The highest autosave delay in minutes (MOD-12.8).
pub const MAX_AUTOSAVE: u32 = 420_000_000;
/// FEA-05's quality levels: Bad 0, Poor 1, Weak 2, Good 3, Excellent 4.
pub const GOOD: u8 = 3;

/// The autosave delay item (MOD-12.8), as bytes (name rule).
const AUTOSAVE_KEY: [u8; 21] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x61, 0x75, 0x74, 0x6F, 0x73, 0x61, 0x76, 0x65, 0x44, 0x65, 0x6C,
    0x61, 0x79, 0x4D, 0x69, 0x6E,
];
/// The unlock time item of simple mode (MOD-12.11), as bytes.
const UNLOCK_TIME_KEY: [u8; 31] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4F, 0x4E, 0x5F,
    0x54, 0x49, 0x4D, 0x45, 0x5F, 0x50, 0x52, 0x45, 0x46, 0x45, 0x52, 0x45, 0x4E, 0x43, 0x45,
];
/// The browser association prefix (MOD-12.18), as bytes.
const BROWSER_PREFIX: [u8; 13] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
];
/// The per-entry site-access item (MOD-12.18), as bytes.
const SITE_ACCESS: [u8; 26] = [
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73, 0x65,
    0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
];
/// The public display item prefix (MOD-12.4, FMT-03.23), as bytes.
const PUBLIC_PREFIX: [u8; 12] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
];
const LAST_MODIFIED: &str = "_LAST_MODIFIED";
const CREATED: &str = "_CREATED_";
/// INT-02.9: Larsal's own last use item per association name.
const LAST_USED: &str = "_LAST_USED_";

fn key(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

/// The five protection switches; the password one is always on
/// (MOD-12.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    /// `ProtectTitle`.
    pub title: bool,
    /// `ProtectUserName`.
    pub user_name: bool,
    /// `ProtectURL`.
    pub url: bool,
    /// `ProtectNotes`.
    pub notes: bool,
}

/// A warning the user must confirm before [`apply`] goes on (MOD-12.10,
/// MOD-12.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// Argon2 iterations above 10,000: opening may take very long.
    SlowArgon2,
    /// AES-KDF rounds below 100,000: weak against guessing.
    WeakAesKdf,
    /// Argon2 below 19 MiB or 2 iterations (D-12-6).
    BelowSafeMinimum,
    /// `vault.msg.no_password`: a key without password.
    NoPassword,
    /// `vault.msg.password_weak`: quality below Good.
    WeakPassword,
}

/// Why [`apply`] did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A warning needs the user's confirmation first.
    Confirm(Confirm),
    /// The KDF cost is in the ask band (CRY-02.14): show the report and
    /// pass it back as `cost_approval`.
    Cost(CostReport),
    /// A control holds a value outside its range; the Larsal id names it.
    OutOfRange(&'static str),
    /// `vault.msg.password_mismatch`.
    PasswordMismatch,
    /// `vault.msg.password_below_minimum`.
    BelowMinimum,
    /// `vault.msg.no_key_part`.
    NoKeyPart,
    /// `vault.msg.kdf_unchanged`: settings the KDF refuses, or too costly
    /// for this Mac.
    KdfUnchanged,
    /// A step failed (the tree changed under the call); nothing applied.
    Failed(Error),
}

/// The password part on the credentials page (MOD-12.10).
pub enum PasswordPart {
    /// Not opened for editing: the vault's current state stays.
    Untouched,
    /// Removed, or opened and left empty.
    Removed,
    /// A new password typed twice, with its FEA-05 quality (0 to 4).
    New {
        /// The first box.
        typed: SecretString,
        /// The repeat box.
        repeat: SecretString,
        /// FEA-05 level of `typed`.
        quality: u8,
    },
}

/// The credentials page (MOD-12.10): the parts the key will have.
pub struct KeyChange {
    /// The password part.
    pub password: PasswordPart,
    /// Whether the vault has a password now (for `Untouched`).
    pub had_password: bool,
    /// A key file part after the change.
    pub key_file: bool,
    /// A hardware key part after the change.
    pub hardware: bool,
    /// The app setting for the minimum vault password quality, 0 to 4.
    pub min_quality: u8,
}

/// The encryption page in advanced mode (MOD-12.12): cipher and KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionEdit {
    /// `vault.cipher`.
    pub cipher: Cipher,
    /// `vault.kdf` with its iterations, memory and lanes.
    pub kdf: Kdf,
    /// Simple mode's chosen unlock time in ms (stored in the unlock time
    /// item); `None` for advanced mode, which removes the item.
    pub unlock_time_ms: Option<u32>,
}

/// Every control of the screen; `None` is a control the user did not
/// touch (D-12-2).
#[derive(Default)]
pub struct Changes {
    /// `vault.name`.
    pub name: Option<String>,
    /// `vault.description`.
    pub description: Option<String>,
    /// `vault.default_username`.
    pub default_user_name: Option<String>,
    /// `vault.history_items`: −1 off, else 0 to 100,000.
    pub history_items: Option<i32>,
    /// `vault.history_size` in MiB: −1 off, else 1 to 2,047.
    pub history_mib: Option<i32>,
    /// `vault.recycle_bin`.
    pub recycle_bin: Option<bool>,
    /// The answer when turning a non-empty bin off: delete it (MOD-04.12).
    pub delete_old_bin: bool,
    /// `vault.compression`.
    pub compression: Option<Compression>,
    /// `vault.autosave_delay` in minutes; 0 is off.
    pub autosave_minutes: Option<u32>,
    /// `vault.public_name`; `Some(None)` clears it.
    pub public_name: Option<Option<String>>,
    /// `vault.public_color` as `#rrggbb`; `Some(None)` clears it.
    pub public_color: Option<Option<String>>,
    /// `vault.public_icon`; `Some(None)` clears it.
    pub public_icon: Option<Option<i32>>,
    /// The encryption page.
    pub encryption: Option<EncryptionEdit>,
    /// The field protection page.
    pub protection: Option<Protection>,
    /// `keychange.recommend`: −1 off, else 1 to 3,650.
    pub key_change_rec: Option<i32>,
    /// `keychange.force`: −1 off, else 1 to 3,650.
    pub key_change_force: Option<i32>,
    /// `keychange.force_once`.
    pub force_once: Option<bool>,
    /// The credentials page.
    pub key: Option<KeyChange>,
    /// Warnings the user confirmed.
    pub confirmed: Vec<Confirm>,
    /// The cost report the user approved (CRY-02.14).
    pub cost_approval: Option<CostReport>,
}

/// What [`apply`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// Some value changed: the vault is marked changed (APP-05).
    pub changed: bool,
    /// `SettingsChanged` moved.
    pub settings_changed: bool,
    /// An encryption control was touched: derive the key now, on a worker
    /// thread (MOD-12.14).
    pub derive_now: bool,
    /// The key changed: the caller replaces the credentials, removes this
    /// vault's quick unlock data and, after the save, shows the old-copies
    /// notice (MOD-12.10 steps 8 and 9).
    pub key_changed: bool,
    /// Histories were cut to new limits (MOD-12.5).
    pub pruned: bool,
}

/// The template the KDF crate checks and benchmarks (no salt matters).
fn params_of(k: &Kdf) -> KdfParams {
    match *k {
        Kdf::AesKdf { rounds } => KdfParams::AesKdf {
            rounds,
            seed: vec![0; 32],
        },
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        } => KdfParams::Argon2 {
            kind: match kind {
                Argon2Kind::D => Argon2Type::D,
                Argon2Kind::Id => Argon2Type::Id,
            },
            version: 0x13,
            iterations,
            memory_kib,
            lanes,
            salt: vec![0; 32],
        },
    }
}

/// Simple mode (MOD-12.11): the KDF kind, memory and lanes kept, the
/// iterations (or rounds) set by the benchmark for `target_ms`, measured
/// with `clock` (CRY-02.28). The measured run goes into `host`, so a save
/// with it right after estimates from this run and does not measure again
/// (F-075: a load swing between two measurements put the cost in the ask
/// band).
///
/// # Errors
/// [`Refusal::KdfUnchanged`] when the KDF crate refuses the settings or the
/// target time.
pub fn tune(kdf: &Kdf, target_ms: u32, host: &mut Host, clock: Clock) -> Result<Kdf, Refusal> {
    let b = kdf::benchmark(&params_of(kdf), u64::from(target_ms), host, clock)
        .map_err(|_| Refusal::KdfUnchanged)?;
    match kdf {
        Kdf::AesKdf { .. } => host.aes_record = Some(b.record),
        Kdf::Argon2 { .. } => host.argon2_record = Some(b.record),
    }
    Ok(match (*kdf, b.params) {
        (Kdf::AesKdf { .. }, KdfParams::AesKdf { rounds, .. }) => Kdf::AesKdf { rounds },
        (
            Kdf::Argon2 {
                kind,
                memory_kib,
                lanes,
                ..
            },
            KdfParams::Argon2 { iterations, .. },
        ) => Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        },
        _ => return Err(Refusal::KdfUnchanged),
    })
}

fn range(value: Option<i32>, lo: i32, hi: i32, id: &'static str) -> Result<(), Refusal> {
    match value {
        Some(v) if v != -1 && !(lo..=hi).contains(&v) => Err(Refusal::OutOfRange(id)),
        _ => Ok(()),
    }
}

/// Every check of every page, in page order (D-12-1).
fn check(v: &Vault, c: &Changes, host: &mut Host, ceilings: &Ceilings) -> Result<(), Refusal> {
    let confirmed = |w: Confirm| c.confirmed.contains(&w);
    let need = |w: Confirm| {
        if confirmed(w) {
            Ok(())
        } else {
            Err(Refusal::Confirm(w))
        }
    };
    range(c.history_items, 0, MAX_HISTORY_ITEMS, "vault.history_items")?;
    range(c.history_mib, 1, MAX_HISTORY_MIB, "vault.history_size")?;
    if c.autosave_minutes.is_some_and(|m| m > MAX_AUTOSAVE) {
        return Err(Refusal::OutOfRange("vault.autosave_delay"));
    }
    range(c.key_change_rec, 1, MAX_KEY_DAYS, "keychange.recommend")?;
    range(c.key_change_force, 1, MAX_KEY_DAYS, "keychange.force")?;
    if let Some(Some(color)) = &c.public_color {
        let ok = color.len() == 7
            && color.starts_with('#')
            && color.bytes().skip(1).all(|b| b.is_ascii_hexdigit());
        if !ok {
            return Err(Refusal::OutOfRange("vault.public_color"));
        }
    }
    if let Some(k) = &c.key {
        check_key(k, &confirmed)?;
    }
    if let Some(e) = c.encryption
        && (e.cipher, e.kdf) != (v.encryption.cipher, v.encryption.kdf)
    {
        match e.kdf {
            Kdf::Argon2 {
                iterations,
                memory_kib,
                ..
            } => {
                // APP-07.9: the safe minimum asks before the slow warning.
                if memory_kib < SAFE_MEMORY_KIB || iterations < SAFE_ITERATIONS {
                    need(Confirm::BelowSafeMinimum)?;
                }
                if iterations > SLOW_ITERATIONS {
                    need(Confirm::SlowArgon2)?;
                }
            }
            Kdf::AesKdf { rounds } => {
                if rounds < WEAK_ROUNDS {
                    need(Confirm::WeakAesKdf)?;
                }
            }
        }
        let params = params_of(&e.kdf);
        match kdf::assess(&params, host, ceilings, c.cost_approval.as_ref()) {
            Ok(Verdict::Run(_)) => {}
            Ok(Verdict::Ask(report)) => return Err(Refusal::Cost(report)),
            Err(_) => return Err(Refusal::KdfUnchanged),
        }
    }
    Ok(())
}

/// MOD-12.10 steps 1 to 7 (steps 5 and 6, key file and hardware key, are
/// checked by the caller as they load).
fn check_key(k: &KeyChange, confirmed: &dyn Fn(Confirm) -> bool) -> Result<(), Refusal> {
    let password = match &k.password {
        PasswordPart::Untouched => k.had_password,
        PasswordPart::Removed => false,
        PasswordPart::New { typed, .. } => !typed.is_empty(),
    };
    if !password && !confirmed(Confirm::NoPassword) {
        return Err(Refusal::Confirm(Confirm::NoPassword));
    }
    if let PasswordPart::New {
        typed,
        repeat,
        quality,
    } = &k.password
        && !typed.is_empty()
    {
        if !larsal_crypto::secret::ct_eq(typed.expose().as_bytes(), repeat.expose().as_bytes()) {
            return Err(Refusal::PasswordMismatch);
        }
        if *quality < k.min_quality {
            return Err(Refusal::BelowMinimum);
        }
        if *quality < GOOD && !confirmed(Confirm::WeakPassword) {
            return Err(Refusal::Confirm(Confirm::WeakPassword));
        }
    }
    if !password && !k.key_file && !k.hardware {
        return Err(Refusal::NoKeyPart);
    }
    Ok(())
}

/// Applies the screen (MOD-12.2 Larsal, D-12-1): every check first, then every
/// change together; `now` for every time that moves.
///
/// # Errors
/// [`Refusal`] from the first check that fails; nothing changes then.
pub fn apply(
    v: &mut Vault,
    c: &Changes,
    host: &mut Host,
    ceilings: &Ceilings,
    now: Time,
) -> Result<Applied, Refusal> {
    check(v, c, host, ceilings)?;
    // Changes go to a copy that replaces the vault only when every step
    // worked, so a step that fails changes nothing (D-12-1).
    let mut draft = v.duplicate();
    let out = apply_to(&mut draft, c, now)?;
    *v = draft;
    Ok(out)
}

fn apply_to(v: &mut Vault, c: &Changes, now: Time) -> Result<Applied, Refusal> {
    let mut out = Applied::default();
    let mut settings = false;
    let m = &mut v.meta;
    // MOD-12.3: each time moves only when its value changes.
    for (value, current, time) in [
        (&c.name, &mut m.name, &mut m.name_changed),
        (
            &c.description,
            &mut m.description,
            &mut m.description_changed,
        ),
        (
            &c.default_user_name,
            &mut m.default_user_name,
            &mut m.default_user_name_changed,
        ),
    ] {
        if let Some(new) = value
            && new != current
        {
            new.clone_into(current);
            *time = now;
            out.changed = true;
        }
    }
    // MOD-13.12: the day values belong to the settings group.
    if let Some(d) = c.key_change_rec
        && d != m.master_key_change_rec
    {
        m.master_key_change_rec = d;
        settings = true;
    }
    if let Some(d) = c.key_change_force
        && d != m.master_key_change_force
    {
        m.master_key_change_force = d;
        settings = true;
    }
    if let Some(p) = c.protection {
        settings |= set_protection(v, p);
    }
    // MOD-12.5: history limits; a change cuts every history at once.
    let items = c.history_items.unwrap_or(v.meta.history_max_items);
    let size = c.history_mib.map_or(v.meta.history_max_size, |mib| {
        if mib == -1 {
            -1
        } else {
            mib.saturating_mul(1_048_576)
        }
    });
    if history::apply_limits(v, items, size) {
        settings = true;
        out.pruned = true;
    }
    if let Some(on) = c.recycle_bin {
        settings |=
            recycle::set_bin_enabled(v, on, c.delete_old_bin, now).map_err(Refusal::Failed)?;
    }
    if let Some(z) = c.compression
        && z != v.encryption.compression
    {
        v.encryption.compression = z;
        settings = true;
    }
    if let Some(e) = c.encryption {
        out.derive_now = true;
        if (e.cipher, e.kdf) != (v.encryption.cipher, v.encryption.kdf) {
            v.encryption.cipher = e.cipher;
            v.encryption.kdf = e.kdf;
            settings = true;
        }
        let item = e.unlock_time_ms.map(|ms| ms.to_string());
        out.changed |= set_item(
            &mut v.meta.custom_data,
            key(&UNLOCK_TIME_KEY),
            item.as_deref(),
            now,
        );
    }
    if let Some(minutes) = c.autosave_minutes {
        let value = (minutes > 0).then(|| minutes.to_string());
        out.changed |= set_item(
            &mut v.meta.custom_data,
            key(&AUTOSAVE_KEY),
            value.as_deref(),
            now,
        );
    }
    settings |= set_public(v, c);
    if let Some(once) = c.force_once
        && once != v.meta.master_key_change_force_once
    {
        v.meta.master_key_change_force_once = once;
        out.changed = true;
    }
    if c.key.is_some() {
        key_changed(&mut v.meta, now);
        out.key_changed = true;
        out.changed = true;
    }
    if settings {
        // MOD-12.9: only a settings-group value moves this time.
        v.meta.settings_changed = now;
        out.settings_changed = true;
        out.changed = true;
    }
    Ok(out)
}

/// MOD-12.10 step 8, MOD-13.11: a confirmed key change moves
/// `MasterKeyChanged` to now (also for the same password typed again) and
/// clears the force-once flag. Changing only the KDF is not a key change.
pub fn key_changed(m: &mut Meta, now: Time) {
    m.master_key_changed = now;
    m.master_key_change_force_once = false;
}

/// MOD-12.16: the page's switches; the password always on. Turning one off
/// clears that standard field's own flag in every entry and history item,
/// with no time change. Returns whether a flag changed.
fn set_protection(v: &mut Vault, p: Protection) -> bool {
    let mp = &mut v.meta.memory_protection;
    let before = (mp.title, mp.user_name, mp.password, mp.url, mp.notes);
    let off: Vec<&str> = [
        ("Title", mp.title && !p.title),
        ("UserName", mp.user_name && !p.user_name),
        ("URL", mp.url && !p.url),
        ("Notes", mp.notes && !p.notes),
    ]
    .iter()
    .filter(|(_, off)| *off)
    .map(|(n, _)| *n)
    .collect();
    (mp.title, mp.user_name, mp.password, mp.url, mp.notes) =
        (p.title, p.user_name, true, p.url, p.notes);
    let after = (mp.title, mp.user_name, mp.password, mp.url, mp.notes);
    if !off.is_empty() {
        for_every_entry(&mut v.root, &mut |e| {
            for n in &off {
                if let Some(f) = e.field(n).filter(|f| f.protected).map(Field::duplicate) {
                    e.set_field(
                        (*n).to_owned(),
                        Field {
                            protected: false,
                            ..f
                        },
                    );
                }
            }
        });
    }
    before != after
}

/// Every live entry and its history items.
fn for_every_entry(root: &mut Group, f: &mut dyn FnMut(&mut Entry)) {
    let mut stack = vec![root];
    while let Some(g) = stack.pop() {
        for e in &mut g.entries {
            f(e);
            e.history.iter_mut().for_each(&mut *f);
        }
        stack.extend(g.groups.iter_mut());
    }
}

/// MOD-12.17: every `Password` field's own protected flag set, in every
/// entry and history item (on read, creation, import and merge).
pub fn protect_all_passwords(v: &mut Vault) {
    for_every_entry(&mut v.root, &mut |e| {
        if let Some(f) = e
            .field("Password")
            .filter(|f| !f.protected)
            .map(Field::duplicate)
        {
            e.set_field(
                "Password".to_owned(),
                Field {
                    protected: true,
                    ..f
                },
            );
        }
    });
}

/// MOD-12.4: the public display items (FMT-03.23): set, cleared or left.
fn set_public(v: &mut Vault, c: &Changes) -> bool {
    let mut changed = false;
    let mut put = |suffix: &[u8], value: Option<Option<(u8, Vec<u8>)>>| {
        let Some(value) = value else { return };
        let mut name = PUBLIC_PREFIX.to_vec();
        name.extend_from_slice(suffix);
        let at = v.public_custom_data.iter().position(|i| i.name == name);
        let current = at
            .and_then(|i| v.public_custom_data.get(i))
            .map(|i| (i.kind, i.value.clone()));
        if current == value {
            return;
        }
        if let Some(i) = at {
            v.public_custom_data.remove(i);
        }
        if let Some((kind, value)) = value {
            v.public_custom_data.push(PublicItem { kind, name, value });
        }
        changed = true;
    };
    put(
        b"NAME",
        c.public_name
            .clone()
            .map(|o| o.map(|s| (0x18, s.into_bytes()))),
    );
    put(
        b"COLOR",
        c.public_color.clone().map(|o| {
            o.map(|s| {
                (
                    0x18,
                    s.chars()
                        .map(|c| c.to_ascii_lowercase())
                        .collect::<String>()
                        .into_bytes(),
                )
            })
        }),
    );
    put(
        b"ICON",
        c.public_icon
            .map(|o| o.map(|i| (0x0C, i.to_le_bytes().to_vec()))),
    );
    changed
}

/// Sets (`Some`) or removes (`None`) a vault custom data item, refreshing
/// the container's `_LAST_MODIFIED` (FMT-14.18 c); when nothing else is
/// left, the stamp goes too. Returns whether anything changed.
pub(crate) fn set_item(cd: &mut CustomData, k: &str, value: Option<&str>, now: Time) -> bool {
    let at = cd.items.iter().position(|i| i.key == k);
    match (at, value) {
        (None, None) => return false,
        (Some(i), Some(v)) if cd.items.get(i).is_some_and(|x| x.value == v) => return false,
        (Some(i), Some(v)) => {
            if let Some(x) = cd.items.get_mut(i) {
                v.clone_into(&mut x.value);
                x.last_modified = Some(now);
            }
        }
        (Some(i), None) => {
            cd.items.remove(i);
        }
        (None, Some(v)) => cd.items.push(CustomDataItem {
            key: k.to_owned(),
            value: v.to_owned(),
            last_modified: Some(now),
            unknown: Vec::new(),
        }),
    }
    stamp(cd, now);
    true
}

fn stamp(cd: &mut CustomData, now: Time) {
    if cd.items.iter().all(|i| i.key == LAST_MODIFIED) {
        cd.items.clear();
        return;
    }
    let text = last_modified_text(now);
    match cd.items.iter_mut().find(|i| i.key == LAST_MODIFIED) {
        Some(i) => i.value = text,
        None => cd.items.push(CustomDataItem {
            key: LAST_MODIFIED.to_owned(),
            value: text,
            last_modified: None,
            unknown: Vec::new(),
        }),
    }
}

/// The autosave delay in minutes (MOD-12.8); 0 when off or unreadable.
#[must_use]
pub fn autosave_minutes(v: &Vault) -> u32 {
    v.meta
        .custom_data
        .get(key(&AUTOSAVE_KEY))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Simple mode's unlock time, shown as max(100, value) (MOD-12.11);
/// `None` without the item: the page opens in advanced mode.
#[must_use]
pub fn unlock_time_ms(v: &Vault) -> Option<u32> {
    v.meta
        .custom_data
        .get(key(&UNLOCK_TIME_KEY))
        .map(|s| s.parse::<u32>().unwrap_or(0).max(100))
}

// ---------------------------------------------------------------------------
// Browser integration actions (MOD-12.18): they act at once.

/// One stored browser association: name (the key without the prefix), the
/// public key value and the created item, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// The name.
    pub name: String,
    /// The public key (not a secret).
    pub value: String,
    /// The `_CREATED_` item's value.
    pub created: Option<String>,
}

fn association_name(k: &str) -> Option<&str> {
    k.as_bytes()
        .starts_with(&BROWSER_PREFIX)
        .then(|| k.get(BROWSER_PREFIX.len()..))
        .flatten()
}

/// The stored associations, in stored order.
#[must_use]
pub fn associations(v: &Vault) -> Vec<Association> {
    let cd = &v.meta.custom_data;
    cd.items
        .iter()
        .filter_map(|i| {
            association_name(&i.key).map(|n| Association {
                name: n.to_owned(),
                value: i.value.clone(),
                created: cd.get(&format!("{CREATED}{n}")).map(str::to_owned),
            })
        })
        .collect()
}

/// Renames an association: its key item and its `_CREATED_` item.
pub fn rename_association(v: &mut Vault, old: &str, new: &str, now: Time) -> bool {
    let (from, to) = (
        format!("{}{old}", key(&BROWSER_PREFIX)),
        format!("{}{new}", key(&BROWSER_PREFIX)),
    );
    let cd = &mut v.meta.custom_data;
    if old == new || cd.get(&from).is_none() || cd.get(&to).is_some() {
        return false;
    }
    for (a, b) in [
        (from, to),
        (format!("{CREATED}{old}"), format!("{CREATED}{new}")),
    ] {
        if let Some(i) = cd.items.iter_mut().find(|i| i.key == a) {
            i.key = b;
            i.last_modified = Some(now);
        }
    }
    stamp(cd, now);
    true
}

/// Sets the value of the named association (Larsal: that row's own item).
pub fn set_association_value(v: &mut Vault, name: &str, value: &str, now: Time) -> bool {
    let k = format!("{}{name}", key(&BROWSER_PREFIX));
    v.meta.custom_data.get(&k).is_some() && set_item(&mut v.meta.custom_data, &k, Some(value), now)
}

/// INT-02.1, INT-02.6: a new association `name` holding the key `value`,
/// and its `_CREATED_` item holding `created`. False, and nothing written,
/// when the name is taken: Larsal never overwrites an association (INT-02.2).
pub fn add_association(v: &mut Vault, name: &str, value: &str, created: &str, now: Time) -> bool {
    let k = format!("{}{name}", key(&BROWSER_PREFIX));
    let cd = &mut v.meta.custom_data;
    if cd.get(&k).is_some() {
        return false;
    }
    set_item(cd, &k, Some(value), now);
    set_item(cd, &format!("{CREATED}{name}"), Some(created), now);
    true
}

/// `vault.act.remove_association`: removes each named association's key
/// item, its `_CREATED_` item and its `_LAST_USED_` item (INT-02.8).
/// Returns how many associations went.
pub fn remove_associations(v: &mut Vault, names: &[&str], now: Time) -> usize {
    let mut n = 0usize;
    for name in names {
        let k = format!("{}{name}", key(&BROWSER_PREFIX));
        if set_item(&mut v.meta.custom_data, &k, None, now) {
            n = n.saturating_add(1);
            for side in [CREATED, LAST_USED] {
                set_item(&mut v.meta.custom_data, &format!("{side}{name}"), None, now);
            }
        }
    }
    n
}

/// `vault.act.disconnect_all`: every association and, in Larsal, its
/// `_CREATED_` item (D-12-7). Returns how many associations went.
pub fn disconnect_all(v: &mut Vault, now: Time) -> usize {
    let names: Vec<String> = associations(v).into_iter().map(|a| a.name).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    remove_associations(v, &refs, now)
}

/// How many live entries hold the site-access item (the vault settings'
/// "Stored permissions" row, MOD-12.18).
#[must_use]
pub fn site_access_count(v: &Vault) -> usize {
    let k = key(&SITE_ACCESS);
    v.root
        .all_entries()
        .filter(|e| e.custom_data.get(k).is_some())
        .count()
}

/// `vault.act.forget_site_access`: removes the site-access item from each
/// live entry as a normal edit (a history item, Mod moves). Returns how
/// many entries changed.
pub fn forget_site_access(v: &mut Vault, now: Time) -> usize {
    let k = key(&SITE_ACCESS);
    let ids: Vec<Uuid> = v
        .root
        .all_entries()
        .filter(|e| e.custom_data.get(k).is_some())
        .map(|e| e.uuid)
        .collect();
    ids.into_iter()
        .filter(|id| {
            edit::edit_entry(v, *id, now, |e| {
                e.custom_data.items.retain(|i| i.key != k);
                if e.custom_data.items.iter().all(|i| i.key == LAST_MODIFIED) {
                    e.custom_data.items.clear();
                } else {
                    stamp(&mut e.custom_data, now);
                }
            })
            .unwrap_or(false)
        })
        .count()
}

/// `vault.act.new_root_id`: a new random id for the root group; no deleted
/// object (MOD-12.18).
///
/// # Errors
/// `RandomSource` when no fresh id can be drawn.
pub fn new_root_id(v: &mut Vault) -> Result<Uuid, Error> {
    let taken: std::collections::HashSet<Uuid> = v.root.subtree().iter().map(|g| g.uuid).collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    v.root.uuid = id;
    Ok(id)
}

// ---------------------------------------------------------------------------
// New vault defaults (MOD-12.22).

/// A new vault (MOD-12.22): name `name`, root `Root` with a random id,
/// AES-256, Argon2id 64 MiB with lanes min(4, cores) and 2 iterations until
/// [`tune`] sets them for one second, gzip, recycle bin on and no bin
/// group, 10 history items and 6 MiB, only the password protected, key
/// change days off, maintenance 365 days, every time `now`.
///
/// # Errors
/// `RandomSource` when no id can be drawn.
pub fn new_vault(name: &str, now: Time, cores: u64) -> Result<Vault, Error> {
    let id = larsal_crypto::random::uuid_v4().map_err(|_| Error::RandomSource)?;
    let mut v = Vault::new(Group::new(Uuid(id), "Root".to_owned(), now), now);
    name.clone_into(&mut v.meta.name);
    v.encryption.kdf = Kdf::Argon2 {
        kind: Argon2Kind::Id,
        iterations: SAFE_ITERATIONS,
        memory_kib: 65_536,
        lanes: cores.clamp(1, 4),
    };
    Ok(v)
}

// ---------------------------------------------------------------------------
// Master key change reminders (MOD-13).

/// The status after an unlock (MOD-13.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reminder {
    /// Nothing to show.
    None,
    /// `keychange.msg.recommended`: elapsed days and the interval.
    Recommended {
        /// Whole days since `MasterKeyChanged` (MOD-13.4).
        days: i64,
        /// `MasterKeyChangeRec`.
        every: i32,
    },
    /// `keychange.msg.forced`: elapsed days and the interval, or `None`
    /// for the force-once request.
    Forced {
        /// Whole days since `MasterKeyChanged`.
        days: i64,
        /// `MasterKeyChangeForce`, or `None` for force-once.
        every: Option<i32>,
    },
}

/// MOD-13.4 to MOD-13.6: whole 24-hour periods since `MasterKeyChanged`
/// in UTC; a day value counts only when it is 1 or more; forced wins.
#[must_use]
pub fn reminder(m: &Meta, now: Time) -> Reminder {
    let days = now
        .0
        .saturating_sub(m.master_key_changed.0)
        .div_euclid(86_400);
    let due = |every: i32| every >= 1 && days >= i64::from(every);
    if m.master_key_change_force_once {
        Reminder::Forced { days, every: None }
    } else if due(m.master_key_change_force) {
        Reminder::Forced {
            days,
            every: Some(m.master_key_change_force),
        }
    } else if due(m.master_key_change_rec) {
        Reminder::Recommended {
            days,
            every: m.master_key_change_rec,
        }
    } else {
        Reminder::None
    }
}

/// MOD-13.16: the command line tool's one line on standard error, without
/// any vault text; `None` when nothing is due. INT-10 owns the wording.
#[must_use]
pub fn cli_notice(r: &Reminder) -> Option<String> {
    match *r {
        Reminder::None => None,
        Reminder::Forced { days, every: Some(f) } => Some(format!(
            "Note: this vault requires a master key change (last changed {days} days ago, required every {f} days); use the vault edit command"
        )),
        Reminder::Forced { every: None, .. } => Some(
            "Note: this vault requires a master key change (requested once); use the vault edit command".to_owned(),
        ),
        Reminder::Recommended { days, every } => Some(format!(
            "Note: a master key change is recommended (last changed {days} days ago, recommended every {every} days)"
        )),
    }
}
