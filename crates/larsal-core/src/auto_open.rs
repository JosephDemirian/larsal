//! Auto-open (APP-06.25, APP-06.26, SR-10, LD-97; F-079): the vaults a
//! vault's `AutoOpen` group asks Larsal to open after it unlocks, each with the
//! path, key file and password its entry gives. Opening them is larsal-ffi's.
//!
//! Guarantees: resolved passwords stay in `SecretString`; no file is read
//! here; an `AutoOpen` group that is, or lies in, a shared group gives
//! nothing (LD-97).

use crate::refs;
use crate::url::{VAULT_LINK, vault_link_path};
use core::cell::Cell;
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Group, Time, Vault};

/// The group's name, exact case (APP-06.25).
pub const GROUP: &str = "AutoOpen";

/// The custom data key that makes a group a share (INT-08.1), stored
/// encoded (name rule).
const SHARE_KEY: &[u8] = &[
    0x4B, 0x65, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x2F, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E,
    0x63, 0x65,
];

/// One vault to open (APP-06.25 steps 4 and 5).
pub struct Target {
    /// The vault's path: the vault link prefix removed, a `file://` URL as
    /// a local path, a relative path taken from the unlocked vault's folder.
    pub path: String,
    /// The key file's path by the same rules; `None` for no key file.
    pub key_file: Option<String>,
    /// The user name holds a protected value ([`resolve_field`]): the key
    /// file is used but never remembered or named (rule 4, SR-12).
    pub key_secret: bool,
    /// The resolved password; `None` when it is empty (no password part).
    pub password: Option<SecretString>,
}

fn shared(g: &Group) -> bool {
    g.custom_data
        .items
        .iter()
        .any(|i| i.key.as_bytes() == SHARE_KEY)
}

/// The device rule of step 2 for an `IfDevice` value on the Mac named
/// `host`: items split at commas and trimmed, compared without letter case;
/// `!name` matching ends with "do not open", `!other` means "open", a plain
/// matching name means "open"; the start is "do not open".
#[must_use]
pub fn device_allows(list: &str, host: &str) -> bool {
    let mut open = false;
    for item in list.split(',').map(str::trim) {
        match item.strip_prefix('!') {
            Some(name) if name.eq_ignore_ascii_case(host) => return false,
            Some(_) => open = true,
            None if item.eq_ignore_ascii_case(host) => open = true,
            None => {}
        }
    }
    open
}

/// Field `name` of `e` resolved in full as Copy resolves it (MOD-08.25)
/// and for display (MOD-08.23), and whether a protected value is inside the
/// full one (rule 4, LD-232 (2)): the field is protected (its own flag or
/// the vault's, LD-207), or a placeholder brought one in (the display
/// resolution put in the mask, [`refs::Resolved::masked`]; F-129: never a
/// text compare, which a transform can fool). A protected field shows as
/// the mask whole. One clock for both, so a date or one-time code cannot
/// differ.
#[must_use]
pub fn resolve_field(
    vault: &Vault,
    vault_dir: &str,
    e: &Entry,
    name: &str,
    now: Time,
) -> (SecretString, SecretString, bool) {
    let field = e.field(name);
    let raw = field.map_or("", |f| f.value.expose());
    let run = |display| {
        let meter = Cell::new(refs::COPY_BUDGET);
        let ctx = refs::Context {
            display,
            ..refs::copy_context(vault, vault_dir, now, &meter)
        };
        refs::resolve(raw, e, &ctx)
    };
    let full = run(false).text;
    if field.is_some_and(|f| f.protected || vault.meta.memory_protection.for_field(name)) {
        return (full, SecretString::new(refs::MASK.to_owned()), true);
    }
    let shown = run(true);
    (full, shown.text, shown.masked)
}

/// Steps 1 to 5 of APP-06.25 for `vault`, whose file lies in `vault_dir`,
/// on the Mac named `host` at time `now`: the entries directly in the first
/// `AutoOpen` group under the root, in group order, with a URL and a user
/// name or password, that the device rule allows, resolved as Copy resolves
/// (MOD-08). Whether each path exists is the caller's step.
#[must_use]
pub fn targets(vault: &Vault, vault_dir: &str, host: &str, now: Time) -> Vec<Target> {
    let group = vault.root.groups.iter().find(|g| g.name == GROUP);
    let Some(group) = group.filter(|g| !shared(g) && !shared(&vault.root)) else {
        return Vec::new();
    };
    let resolve = |e: &Entry, name: &str| resolve_field(vault, vault_dir, e, name, now);
    let empty = |e: &Entry, name: &str| e.field(name).is_none_or(|f| f.value.is_empty());
    group
        .entries
        .iter()
        .filter(|e| !empty(e, "URL") && !(empty(e, "UserName") && empty(e, "Password")))
        .filter(|e| {
            e.field("IfDevice")
                .is_none_or(|f| device_allows(f.value.expose(), host))
        })
        .map(|e| {
            let (url, ..) = resolve(e, "URL");
            let url = url.expose();
            let path = match url.as_bytes().strip_prefix(VAULT_LINK) {
                Some(_) => url.get(VAULT_LINK.len()..).unwrap_or(""),
                None => url,
            };
            let (key, _, key_secret) = resolve(e, "UserName");
            let (password, ..) = resolve(e, "Password");
            Target {
                path: vault_link_path(path, vault_dir),
                key_file: (!key.is_empty()).then(|| vault_link_path(key.expose(), vault_dir)),
                key_secret,
                password: (!password.is_empty()).then_some(password),
            }
        })
        .collect()
}
