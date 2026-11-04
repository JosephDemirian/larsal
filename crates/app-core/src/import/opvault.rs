//! OPVault import (FEA-08 section D): a folder of JavaScript-wrapped JSON
//! files with opdata01 blobs, keys from PBKDF2-HMAC-SHA512.
//!
//! Guarantees:
//! - opdata01 (FEA-08.34): the header, then the exact total size from the
//!   plaintext length (checked arithmetic, before any allocation), then the
//!   HMAC in constant time, and only then the decryption. The reference
//!   allocates from the length before any check.
//! - Item keys (FEA-08.36) and each item's check value (LD-45) are verified
//!   in constant time; a failure inside one item skips it and lists it in
//!   the import report; a folder that fails stops the import.
//! - The password-derived keys, the master and overview keys, the item keys
//!   and every decrypted JSON live in `SecretBytes` and are wiped when the
//!   reader returns. Crypto only through app-crypto; the PBKDF2 cost range
//!   of FEA-08.68 is checked before the derivation.
//! - Every file read is bounded: `profile.js`, `folders.js` and band files
//!   at 256 MiB, attachment files at the one-attachment limit (FEA-08.67).

use super::json::{self, Json};
use super::{Builder, Context, Draft, ImportError, Imported, Limit, MAX_FILE, R, SkipReason};
use crate::text::Text;
use app_crypto::cipher::{Cipher, Decryptor};
use app_crypto::kdf::{self, Prf};
use app_crypto::secret::{SecretBytes, SecretString};
use app_crypto::{hash, mac};
use app_model::entry::STANDARD_FIELDS;
use app_model::times::Civil;
use app_model::{Time, Uuid};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The 18 category groups, in code order (FEA-08.39).
pub const CATEGORIES: [(&str, &str); 18] = [
    ("001", "Login"),
    ("002", "Credit Card"),
    ("003", "Secure Note"),
    ("004", "Identity"),
    ("005", "Password"),
    ("099", "Tombstone"),
    ("100", "Software License"),
    ("101", "Bank Account"),
    ("102", "Database"),
    ("103", "Driver License"),
    ("104", "Outdoor License"),
    ("105", "Membership"),
    ("106", "Passport"),
    ("107", "Rewards"),
    ("108", "SSN"),
    ("109", "Router"),
    ("110", "Server"),
    ("111", "Email"),
];

/// The note of a smart folder without a predicate (FEA-08.38).
pub const NO_PREDICATE: &str = "This smart folder has no predicate.";

/// The files of an OPVault's `default` folder (FEA-08.33). [`DiskFolder`]
/// reads a real one; tests and fuzzing give files in memory.
pub trait Folder {
    /// The file `name` of `default`, `Ok(None)` when it is missing. Refuses
    /// a file over `max` bytes before reading it, naming `over`.
    ///
    /// # Errors
    /// [`ImportError::TooLarge`], or [`ImportError::Open`] with the
    /// system's reason.
    fn file(&self, name: &str, max: u64, over: Limit) -> Result<Option<SecretBytes>, ImportError>;

    /// The names of the files in `default`.
    ///
    /// # Errors
    /// [`ImportError::Open`] with the system's reason.
    fn names(&self) -> Result<Vec<String>, ImportError>;
}

/// The chosen `.opvault` folder on disk.
#[derive(Debug)]
pub struct DiskFolder {
    default: PathBuf,
}

impl DiskFolder {
    /// Opens the folder at `path`.
    ///
    /// # Errors
    /// `MSG-OPV-LAYOUT` when it or its `default` folder is missing.
    pub fn open(path: &Path) -> Result<Self, ImportError> {
        let default = path.join("default");
        if !default.is_dir() {
            return Err(ImportError::OpvLayout);
        }
        Ok(Self { default })
    }
}

impl Folder for DiskFolder {
    fn file(&self, name: &str, max: u64, over: Limit) -> Result<Option<SecretBytes>, ImportError> {
        match crate::storage::read_limited(&self.default.join(name), max) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
                Err(ImportError::TooLarge(over))
            }
            Err(e) => Err(ImportError::Open(e.kind())),
        }
    }

    fn names(&self) -> Result<Vec<String>, ImportError> {
        let dir = std::fs::read_dir(&self.default).map_err(|e| ImportError::Open(e.kind()))?;
        Ok(dir
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect())
    }
}

/// An encryption key and a MAC key.
struct Keys {
    enc: SecretBytes,
    mac: SecretBytes,
}

impl Keys {
    /// The first 32 bytes encrypt, the last 32 authenticate.
    fn split(b: &SecretBytes) -> Option<Keys> {
        let half = |r: core::ops::Range<usize>| {
            let mut k = SecretBytes::zeroed(32);
            k.expose_mut().copy_from_slice(b.expose().get(r)?);
            Some(k)
        };
        Some(Keys {
            enc: half(0..32)?,
            mac: half(32..64)?,
        })
    }
}

/// Why an opdata01 blob failed.
#[derive(Debug, PartialEq, Eq)]
enum Opd {
    /// Header or size wrong, or the decryption failed.
    Damaged,
    /// The HMAC did not match.
    BadMac,
}

/// FEA-08.34: checks in order (header, exact size, HMAC), then decrypts and
/// drops the P random bytes.
fn opdata(blob: &[u8], keys: &Keys) -> Result<SecretBytes, Opd> {
    if blob.len() < 64 || !blob.starts_with(b"opdata01") {
        return Err(Opd::Damaged);
    }
    let l: [u8; 8] = blob
        .get(8..16)
        .and_then(|s| s.try_into().ok())
        .ok_or(Opd::Damaged)?;
    let l = u64::from_le_bytes(l);
    let p = 16u64.saturating_sub(l % 16);
    let total = l
        .checked_add(p)
        .and_then(|v| v.checked_add(8 + 8 + 16 + 32))
        .ok_or(Opd::Damaged)?;
    if total != u64::try_from(blob.len()).map_err(|_| Opd::Damaged)? {
        return Err(Opd::Damaged);
    }
    let mac_at = blob.len().checked_sub(32).ok_or(Opd::Damaged)?;
    let (signed, tag) = (
        blob.get(..mac_at).ok_or(Opd::Damaged)?,
        blob.get(mac_at..).ok_or(Opd::Damaged)?,
    );
    if !mac::verify_hmac_sha256(keys.mac.expose(), &[signed], tag) {
        return Err(Opd::BadMac);
    }
    let iv = blob.get(16..32).ok_or(Opd::Damaged)?;
    let plain =
        cbc_nopad(&keys.enc, iv, blob.get(32..mac_at).ok_or(Opd::Damaged)?).ok_or(Opd::Damaged)?;
    let (p, l) = (
        usize::try_from(p).map_err(|_| Opd::Damaged)?,
        usize::try_from(l).map_err(|_| Opd::Damaged)?,
    );
    let mut out = SecretBytes::zeroed(l);
    out.expose_mut().copy_from_slice(
        plain
            .expose()
            .get(p..p.checked_add(l).ok_or(Opd::Damaged)?)
            .ok_or(Opd::Damaged)?,
    );
    Ok(out)
}

/// AES-256-CBC without padding of whole blocks.
fn cbc_nopad(key: &SecretBytes, iv: &[u8], ct: &[u8]) -> Option<SecretBytes> {
    if ct.is_empty() || !ct.len().is_multiple_of(16) {
        return None;
    }
    let mut dec = Decryptor::new(Cipher::Aes256Cbc, key, iv).ok()?;
    let head = dec.update(ct).ok()?;
    let tail = dec.finish_unpadded().ok()?;
    let mut out = SecretBytes::zeroed(head.len().checked_add(tail.len())?);
    let (a, b) = out.expose_mut().split_at_mut(head.len());
    a.copy_from_slice(head.expose());
    b.copy_from_slice(tail.expose());
    Some(out)
}

/// Strips the JavaScript wrapper after trimming trailing white space
/// (FEA-08.33, L08-7f).
fn unwrap_js<'a>(b: &'a [u8], prefix: &str, suffix: &str) -> Option<&'a [u8]> {
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(0, |i| i.saturating_add(1));
    b.get(..end)?
        .strip_prefix(prefix.as_bytes())?
        .strip_suffix(suffix.as_bytes())
}

/// A 32- or 36-character id as 16 bytes (FEA-08.37).
fn uuid(text: &str) -> Option<Uuid> {
    let hex: String = match text.len() {
        32 => text.to_owned(),
        36 if [8, 13, 18, 23]
            .iter()
            .all(|&i| text.as_bytes().get(i) == Some(&b'-')) =>
        {
            text.chars().filter(|&c| c != '-').collect()
        }
        _ => return None,
    };
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = hex.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(Uuid(out))
}

fn secs(v: &Json) -> Option<Time> {
    v.int().and_then(Time::from_unix)
}

/// Reads an OPVault folder. `folder_name` is the chosen folder's name
/// (the root group's name without every `.opvault`, FEA-08.40).
/// `password` `None` stops after the layout checks, before any
/// derivation, with `MSG-WRONG-PASSWORD`.
///
/// # Errors
/// `MSG-OPV-LAYOUT`, `MSG-OPV-DAMAGED`, `MSG-WRONG-PASSWORD`,
/// `MSG-KDF-COST`, `MSG-TOO-LARGE`, `MSG-IMP-OPEN`; `Cancelled`.
pub fn read(
    folder: &dyn Folder,
    folder_name: &str,
    password: Option<&SecretString>,
    ctx: &Context<'_>,
) -> Result<Imported, ImportError> {
    let profile_file = folder
        .file("profile.js", MAX_FILE, Limit::File)?
        .ok_or(ImportError::OpvLayout)?;
    let profile = unwrap_js(profile_file.expose(), "var profile=", ";")
        .and_then(|b| json::parse(b).ok())
        .filter(Json::is_object)
        .ok_or(ImportError::OpvLayout)?;
    let blob = |k: &str| super::b64(profile.get(k).str()).ok_or(ImportError::OpvDamaged);
    let (salt, master_blob, overview_blob) =
        (blob("salt")?, blob("masterKey")?, blob("overviewKey")?);
    let iterations = profile
        .get("iterations")
        .int()
        .and_then(|i| u64::try_from(i).ok())
        .unwrap_or(0);
    let password = password.ok_or(ImportError::WrongPassword)?;
    ctx.check_cancel()?;
    // FEA-08.35: the password's full UTF-8 bytes.
    let pw = SecretBytes::new(password.expose().as_bytes().to_vec());
    let derived = kdf::pbkdf2(Prf::Sha512, &pw, &salt, iterations, 64).map_err(|e| match e {
        app_crypto::Error::KdfCost => ImportError::KdfCost,
        _ => ImportError::OpvDamaged,
    })?;
    drop(pw);
    ctx.check_cancel()?;
    let derived = Keys::split(&derived).ok_or(ImportError::OpvDamaged)?;
    let master = match opdata(&master_blob, &derived) {
        Ok(k) => k,
        Err(Opd::BadMac) => return Err(ImportError::WrongPassword),
        Err(Opd::Damaged) => return Err(ImportError::OpvDamaged),
    };
    let master = Keys::split(&hash::sha512(&[master.expose()])).ok_or(ImportError::OpvDamaged)?;
    let overview = opdata(&overview_blob, &derived).map_err(|_| ImportError::OpvDamaged)?;
    let overview =
        Keys::split(&hash::sha512(&[overview.expose()])).ok_or(ImportError::OpvDamaged)?;
    drop(derived);

    let root_name = folder_name.replace(".opvault", "");
    let mut b = Builder::new(ctx, &root_name)?;
    if let Some(id) = uuid(profile.get("uuid").str()) {
        b.root_id(id);
    }
    if let Some(root) = b.group_mut(0) {
        if let Some(t) = secs(profile.get("createdAt")) {
            root.times.creation = t;
        }
        if let Some(t) = secs(profile.get("updatedAt")) {
            root.times.last_modification = t;
        }
    }
    folders(&mut b, folder, &overview)?;
    let mut categories = Vec::with_capacity(CATEGORIES.len());
    for (code, name) in CATEGORIES {
        categories.push((code, b.new_child(0, name, None)?));
    }
    let names = attachment_index(&folder.names()?);
    let keys = (&master, &overview);
    for digit in "0123456789ABCDEF".chars() {
        let Some(band) = folder.file(&format!("band_{digit}.js"), MAX_FILE, Limit::File)? else {
            continue;
        };
        let items = unwrap_js(band.expose(), "ld(", ");")
            .and_then(|b| json::parse(b).ok())
            .filter(Json::is_object)
            .ok_or(ImportError::OpvDamaged)?;
        for (_, item) in items.members() {
            let label: String = item.get("uuid").str().chars().take(64).collect();
            match one_item(&mut b, folder, &names, item, keys, &categories) {
                Ok(()) => {}
                Err(Fail::Skip(reason)) => b.skip(&label, reason),
                Err(Fail::Stop(e)) => return Err(e),
            }
        }
    }
    b.drop_empty_top_groups();
    Ok(b.finish())
}

/// FEA-08.38: every folder becomes a group (and is dropped at the end
/// when empty, as items never go into folders). A folder that fails stops
/// the import.
fn folders(b: &mut Builder<'_>, folder: &dyn Folder, overview: &Keys) -> R<()> {
    let Some(file) = folder.file("folders.js", MAX_FILE, Limit::File)? else {
        return Ok(());
    };
    let list = unwrap_js(file.expose(), "loadFolders(", ");")
        .and_then(|b| json::parse(b).ok())
        .filter(Json::is_object)
        .ok_or(ImportError::OpvDamaged)?;
    for (_, f) in list.members() {
        let blob = super::b64(f.get("overview").str()).ok_or(ImportError::OpvDamaged)?;
        let plain = opdata(&blob, overview).map_err(|_| ImportError::OpvDamaged)?;
        let o = json::parse(plain.expose()).map_err(|_| ImportError::OpvDamaged)?;
        let g = b.new_child(0, o.get("title").str(), uuid(f.get("uuid").str()))?;
        let notes = if !f.get("smart").is_true() {
            String::new()
        } else {
            match super::b64(f.get("predicate_b64").str()) {
                Some(p) if f.get("predicate_b64").str() != "" => {
                    p.iter().map(|x| format!("{x:02x}")).collect()
                }
                _ => NO_PREDICATE.to_owned(),
            }
        };
        if let Some(group) = b.group_mut(g) {
            group.notes = notes;
            if let Some(t) = secs(f.get("created")) {
                group.times.creation = t;
            }
            if let Some(t) = secs(f.get("updated")) {
                group.times.last_modification = t;
            }
        }
    }
    Ok(())
}

/// How one item ended badly.
enum Fail {
    /// Skip it and list it (FEA-08.37).
    Skip(SkipReason),
    /// Stop the import (a limit, Cancel, the random source).
    Stop(ImportError),
}

impl From<ImportError> for Fail {
    fn from(e: ImportError) -> Self {
        Fail::Stop(e)
    }
}

const DAMAGED: Fail = Fail::Skip(SkipReason::Damaged);

/// LD-45: the item's `hmac`, HMAC-SHA256 with the overview MAC key over
/// every other member in sorted key order, each as its key followed by its
/// value as text (a string as is, a whole number in decimal, `true` 1,
/// `false` 0). Any other value type fails the check.
fn item_check(item: &Json, overview: &Keys) -> bool {
    let Some(tag) = super::b64(item.get("hmac").str()) else {
        return false;
    };
    let mut members: Vec<&(String, Json)> =
        item.members().iter().filter(|(k, _)| k != "hmac").collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut msg: Vec<u8> = Vec::new();
    for (k, v) in members {
        msg.extend(k.as_bytes());
        match v {
            Json::Str(s) => msg.extend(s.expose().as_bytes()),
            Json::Bool(t) => msg.push(if *t { b'1' } else { b'0' }),
            Json::Number(_) => match v.int() {
                Some(n) => msg.extend(n.to_string().as_bytes()),
                None => return false,
            },
            _ => return false,
        }
    }
    mac::verify_hmac_sha256(overview.mac.expose(), &[&msg], &tag)
}

/// FEA-08.36, FEA-08.37, FEA-08.39, FEA-08.42: one item.
fn one_item(
    b: &mut Builder<'_>,
    folder: &dyn Folder,
    names: &Names,
    item: &Json,
    (master, overview): (&Keys, &Keys),
    categories: &[(&str, usize)],
) -> Result<(), Fail> {
    let id = uuid(item.get("uuid").str()).ok_or(DAMAGED)?;
    if [item.get("d"), item.get("k"), item.get("hmac")]
        .iter()
        .any(|v| v.str().is_empty())
    {
        return Err(DAMAGED);
    }
    if !item_check(item, overview) {
        return Err(Fail::Skip(SkipReason::CheckFailed));
    }
    let k = super::b64(item.get("k").str()).ok_or(DAMAGED)?;
    if k.len() != 112 {
        return Err(DAMAGED);
    }
    let (signed, tag) = k.split_at(80);
    if !mac::verify_hmac_sha256(master.mac.expose(), &[signed], tag) {
        return Err(DAMAGED);
    }
    let raw = cbc_nopad(
        &master.enc,
        k.get(..16).ok_or(DAMAGED)?,
        k.get(16..80).ok_or(DAMAGED)?,
    )
    .ok_or(DAMAGED)?;
    let item_keys = Keys::split(&raw).ok_or(DAMAGED)?;
    let o = match item.get("o").str() {
        "" => None,
        text => {
            let blob = super::b64(text).ok_or(DAMAGED)?;
            let plain = opdata(&blob, overview).map_err(|_| DAMAGED)?;
            Some(json::parse(plain.expose()).map_err(|_| DAMAGED)?)
        }
    };
    let d_blob = super::b64(item.get("d").str()).ok_or(DAMAGED)?;
    let d_plain = opdata(&d_blob, &item_keys).map_err(|_| DAMAGED)?;
    let details = json::parse(d_plain.expose()).map_err(|_| DAMAGED)?;
    drop(d_plain);

    let mut d = b.draft_with(Some(id))?;
    let null = Json::Null;
    let o = o.as_ref().unwrap_or(&null);
    d.set("Title", o.get("title").text(), false)?;
    d.set("URL", o.get("url").text(), false)?;
    for u in o.get("URLs").items() {
        let url = u.get("u").text();
        if !url.is_empty() && url.expose() != d.value("URL") {
            d.extra_url(url)?;
        }
    }
    for t in o.get("tags").items() {
        if let Json::Str(tag) = t {
            d.tag(tag.expose());
        }
    }
    d.set("Notes", details.get("notesPlain").text(), false)?;
    d.set("Password", details.get("password").text(), true)?;
    for f in details.get("fields").items() {
        match f.get("designation").str() {
            "password" => d.set("Password", f.get("value").text(), true)?,
            "username" => d.set("UserName", f.get("value").text(), false)?,
            _ => {}
        }
    }
    for section in details.get("sections").items() {
        for f in section.get("fields").items() {
            section_field(&mut d, section.get("title").str(), f)?;
        }
    }
    if let Some(t) = secs(item.get("created")) {
        d.entry_mut().times.creation = t;
    }
    if let Some(t) = secs(item.get("updated")) {
        d.entry_mut().times.last_modification = t;
    }
    attachments(&mut d, b, folder, names, id, &item_keys, overview)?;
    let trashed = item.get("trashed").is_true();
    let group = if trashed {
        0
    } else {
        let code = item.get("category").str();
        categories
            .iter()
            .find(|(c, _)| *c == code)
            .map_or(0, |(_, g)| *g)
    };
    let id = b.add(group, d)?;
    if trashed {
        b.trash(id);
    }
    Ok(())
}

/// FEA-08.41: one section field.
fn section_field(d: &mut Draft, section: &str, f: &Json) -> R<()> {
    let v = f.get("v");
    if matches!(v, Json::Null) {
        return Ok(());
    }
    let (n, t, k) = (f.get("n").str(), f.get("t").str(), f.get("k").str());
    if n.starts_with("TOTP_") {
        return totp_field(d, v);
    }
    let name = if section.is_empty() || n.starts_with("address") {
        let has = |hay: &str, needle: &str| {
            crate::edit::find_ascii_ci(hay.as_bytes(), needle.as_bytes()).is_some()
        };
        if has(n, "password") || has(t, "password") {
            "Password".to_owned()
        } else if has(n, "username") || has(t, "username") {
            "UserName".to_owned()
        } else if has(n, "url")
            || has(t, "url")
            || has(n, "hostname")
            || has(t, "server")
            || has(n, "website")
        {
            "URL".to_owned()
        } else {
            t.to_owned()
        }
    } else {
        format!("{section}_{t}")
    };
    if name
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("expir"))
    {
        if let Some(when) = date(k, v) {
            let times = &mut d.entry_mut().times;
            times.expires = true;
            times.expiry = when;
        }
        return Ok(());
    }
    match k {
        "date" | "monthYear" => {
            if let Some(c) = date(k, v).and_then(Time::to_civil) {
                let text = format!("{:04}-{:02}-{:02}", c.year, c.month, c.day);
                let value = Text::from(&text).into_secret();
                // A standard name ends up a suffixed custom field (FEA-08.41).
                if STANDARD_FIELDS.contains(&name.as_str()) {
                    d.custom(&name, value, false)?;
                } else {
                    d.set(&name, value, false)?;
                }
            }
        }
        "address" => {
            let mut keys: Vec<&(String, Json)> = v.members().iter().collect();
            keys.sort_by(|a, b| app_model::entry::cmp_utf16(&a.0, &b.0));
            for (key, value) in keys {
                d.set(&format!("{name}_{key}"), value.text(), false)?;
            }
        }
        _ => {
            let value = if let Json::Str(s) = v {
                Text::from(s.expose()).into_secret()
            } else {
                SecretString::new(String::new())
            };
            d.custom(&name, value, matches!(k, "password" | "concealed"))?;
        }
    }
    Ok(())
}

/// The TOTP rows of FEA-08.41.
fn totp_field(d: &mut Draft, v: &Json) -> R<()> {
    let text = v.str();
    if d.has_totp() {
        let n = d.numbered("otp");
        return d.set(&n, Text::from(text).into_secret(), true);
    }
    let settings = if text.starts_with("otpauth://") {
        let mut uri = Text::from(text);
        let query = text.split_once('?').map_or("", |(_, q)| q);
        let has = |name: &str| query.split('&').any(|p| p.split('=').next() == Some(name));
        for (name, value) in [("digits", "digits=6"), ("period", "period=30")] {
            if !has(name) {
                uri.push(if uri.as_str().contains('?') { '&' } else { '?' });
                uri.push_str(value);
            }
        }
        crate::totp::from_text(uri.as_str(), "").filter(crate::totp::Settings::has_secret)
    } else {
        crate::totp::from_text("", text)
    };
    match settings {
        Some(s) => d.store_totp(&s),
        None => Ok(()),
    }
}

/// FEA-08.41 dates: `monthYear` is `YYYYMM`, the 1st at 00:00 UTC;
/// otherwise seconds UTC, a number or a text holding one.
fn date(k: &str, v: &Json) -> Option<Time> {
    let n = v.int().or_else(|| v.str().trim().parse::<i64>().ok())?;
    if k == "monthYear" {
        let month = u32::try_from(n.checked_rem(100)?).ok()?;
        return Time::from_civil(Civil {
            year: n.checked_div(100)?,
            month,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        });
    }
    Time::from_unix(n)
}

/// The attachment files by their `<UUID>_` prefix (33 characters), built
/// once, so an item finds its files without a scan of every name.
type Names = HashMap<String, Vec<String>>;

fn attachment_index(names: &[String]) -> Names {
    let mut index: Names = HashMap::new();
    for n in names.iter().filter(|n| n.ends_with(".attachment")) {
        if let Some(prefix) = n.get(..33).filter(|p| p.ends_with('_')) {
            index.entry(prefix.to_owned()).or_default().push(n.clone());
        }
    }
    index
}

/// FEA-08.42: the entry's attachment files. Each file is read only up to
/// the room the result's byte budget has left: past the one-attachment
/// limit, or unreadable, it is skipped into the report (LD-146 (6)); past
/// the attachments or total budget the import stops (FEA-08.67).
fn attachments(
    d: &mut Draft,
    b: &mut Builder<'_>,
    folder: &dyn Folder,
    names: &Names,
    id: Uuid,
    item_keys: &Keys,
    overview: &Keys,
) -> Result<(), Fail> {
    let prefix: String = id.0.iter().map(|x| format!("{x:02X}")).collect::<String>() + "_";
    for name in names.get(&prefix).map_or(&[][..], Vec::as_slice) {
        let (room, over) = b.room(d);
        let bytes = match folder.file(name, u64::try_from(room).unwrap_or(u64::MAX), over) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(ImportError::TooLarge(l @ (Limit::AllAttachments | Limit::Total))) => {
                return Err(Fail::Stop(ImportError::TooLarge(l)));
            }
            Err(_) => {
                b.skip(name, SkipReason::Attachment);
                continue;
            }
        };
        match attachment(bytes.expose(), item_keys, overview) {
            Some(Some((file_name, content))) => {
                let fallback = name.split('.').next().unwrap_or("");
                d.attach(file_name.as_deref().unwrap_or(fallback), content)?;
            }
            Some(None) => {} // trashed
            None => b.skip(name, SkipReason::Attachment),
        }
    }
    Ok(())
}

/// One attachment file: `None` when it fails, `Some(None)` when trashed,
/// else its name (when the metadata gives one) and content.
#[allow(clippy::type_complexity)]
fn attachment(
    b: &[u8],
    item_keys: &Keys,
    overview: &Keys,
) -> Option<Option<(Option<String>, SecretBytes)>> {
    if !b.starts_with(b"OPCLDAT") || !matches!(b.get(7), Some(1 | 2)) {
        return None;
    }
    let meta_len = usize::from(u16::from_le_bytes(b.get(8..10)?.try_into().ok()?));
    let icon_len = usize::try_from(u32::from_le_bytes(b.get(12..16)?.try_into().ok()?)).ok()?;
    let meta_end = 16usize.checked_add(meta_len)?;
    let icon_end = meta_end.checked_add(icon_len)?;
    let meta = json::parse(b.get(16..meta_end)?).ok()?;
    if meta.get("trashed").is_true() {
        return Some(None);
    }
    if icon_len > 0 {
        opdata(b.get(meta_end..icon_end)?, item_keys).ok()?;
    }
    let content = opdata(b.get(icon_end..)?, item_keys).ok()?;
    let name = match meta.get("overview").str() {
        "" => None,
        text => {
            let plain = opdata(&super::b64(text)?, overview).ok()?;
            let o = json::parse(plain.expose()).ok()?;
            Some(o.get("filename").str().to_owned()).filter(|n| !n.is_empty())
        }
    };
    Some(Some((name, content)))
}

#[cfg(test)]
// Rust rule 4 exempts tests; clippy.toml has no test switch for this lint.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use app_crypto::cipher::Encryptor;

    fn keys() -> Keys {
        Keys {
            enc: SecretBytes::new(vec![1; 32]),
            mac: SecretBytes::new(vec![2; 32]),
        }
    }

    /// An opdata01 blob of `plain` (FEA-08.34), built with app-crypto.
    fn blob(plain: &[u8], k: &Keys) -> Vec<u8> {
        let p = 16 - plain.len() % 16;
        let iv = [7u8; 16];
        let mut data = vec![9u8; p];
        data.extend(plain);
        let mut enc = Encryptor::new(Cipher::Aes256Cbc, &k.enc, &iv).unwrap();
        let ct = enc.update(&data).unwrap(); // whole blocks: no padding block
        let mut out = b"opdata01".to_vec();
        out.extend((plain.len() as u64).to_le_bytes());
        out.extend(iv);
        out.extend(ct);
        let tag = mac::hmac_sha256(k.mac.expose(), &[&out]).unwrap();
        out.extend(tag.expose());
        out
    }

    // Case 08-32.
    #[test]
    fn fea08_32_opdata01() {
        let k = keys();
        let five = blob(b"hello", &k);
        assert_eq!(five.len(), 80);
        assert_eq!(opdata(&five, &k).unwrap().expose(), b"hello");
        // L = 2^40 with the same bytes: refused from the size, before any
        // allocation.
        let mut huge = five.clone();
        huge[8..16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert_eq!(opdata(&huge, &k).unwrap_err(), Opd::Damaged);
        let mut wrapping = five.clone();
        wrapping[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(opdata(&wrapping, &k).unwrap_err(), Opd::Damaged);
        // One ciphertext bit flipped: the HMAC fails, nothing is decrypted.
        let mut flipped = five.clone();
        flipped[40] ^= 1;
        assert_eq!(opdata(&flipped, &k).unwrap_err(), Opd::BadMac);
        let sixteen = blob(&[3u8; 16], &k);
        assert_eq!(
            sixteen.len(),
            8 + 8 + 16 + 32 + 32,
            "P = 16 for a multiple of 16"
        );
        assert_eq!(opdata(&sixteen, &k).unwrap().expose(), &[3u8; 16]);
        assert_eq!(opdata(b"opdata02", &k).unwrap_err(), Opd::Damaged);
    }

    #[test]
    fn attachment_names_are_indexed_by_prefix() {
        let id = "0000000000000000000000000000000A";
        let names: Vec<String> = [
            format!("{id}_X.attachment"),
            format!("{id}_Y.attachment"),
            format!("{id}_Z.txt"),
            "short_A.attachment".to_owned(),
            format!("{}B_C.attachment", &id[..31]),
        ]
        .into_iter()
        .collect();
        let index = attachment_index(&names);
        assert_eq!(index.get(&format!("{id}_")).map(Vec::len), Some(2));
        assert_eq!(index.len(), 2, "the last name belongs to another id");
    }

    #[test]
    fn js_wrapper_and_ids() {
        assert_eq!(unwrap_js(b"ld({});\n \t", "ld(", ");"), Some(&b"{}"[..]));
        assert_eq!(unwrap_js(b"var profile={};", "ld(", ");"), None);
        assert_eq!(
            uuid("00000000-0000-0000-0000-00000000000A"),
            Some(Uuid([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]))
        );
        assert_eq!(uuid("0000000000000000000000000000000"), None);
        assert_eq!(uuid("0000000000000000000000000000000g"), None);
    }
}
