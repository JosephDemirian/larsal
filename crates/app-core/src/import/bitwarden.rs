//! Bitwarden JSON import (FEA-08 section E): plain exports and
//! password-protected ones (FEA-08.49, FEA-08.50).
//!
//! Guarantees for a protected file, in this order: the account-key form is
//! refused (`MSG-BW-ACCOUNT`); the key derivation is checked (`MSG-BW-KDF`,
//! then the FEA-08.68 ranges in app-crypto, `MSG-KDF-COST`); both cipher
//! strings must be type 2 with three base64 parts, a 16-byte IV and a
//! 32-byte MAC (L08-8, `MSG-BW-DAMAGED`); only then the key is derived. The
//! validation MAC and then the `data` MAC are compared in constant time
//! before anything is decrypted. The derived keys and the decrypted JSON
//! live only in `SecretBytes` and are wiped when the reader returns.

use super::json::{self, Json};
use super::{Builder, Context, Draft, ImportError, Imported, Limit, MAX_FILE, R};
use crate::text::Text;
use app_crypto::base64::{Form, decode, decode_secret, encode_secret};
use app_crypto::cipher::{self, Cipher};
use app_crypto::kdf::{self, Prf};
use app_crypto::secret::{SecretBytes, SecretString};
use app_crypto::{hash, mac};
use app_model::{Entry, Field};
use std::collections::HashMap;

/// The result's root group name.
pub const ROOT: &str = "Bitwarden Import";

/// Reads a Bitwarden JSON export. `password` is used only when the file is
/// encrypted; with `None` an encrypted file stops with
/// [`ImportError::WrongPassword`] after its envelope was checked, before
/// any key derivation.
///
/// # Errors
/// `MSG-JSON`, `MSG-BW-ACCOUNT`, `MSG-BW-KDF`, `MSG-KDF-COST`,
/// `MSG-WRONG-PASSWORD`, `MSG-BW-DAMAGED`, `MSG-TOO-LARGE`; `Cancelled`.
pub fn read(
    bytes: &[u8],
    password: Option<&SecretString>,
    ctx: &Context<'_>,
) -> Result<Imported, ImportError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE {
        return Err(ImportError::TooLarge(Limit::File));
    }
    let doc = json::parse(bytes)?;
    if !doc.get("encrypted").is_true() {
        return build(&doc, ctx);
    }
    let plain = decrypt(&doc, password, ctx)?;
    drop(doc);
    build(&json::parse(plain.expose())?, ctx)
}

/// One `<type>.<iv>|<ciphertext>|<mac>` value (FEA-08.50).
struct Sealed {
    iv: Vec<u8>,
    ct: Vec<u8>,
    mac: Vec<u8>,
}

fn sealed(v: &Json) -> R<Sealed> {
    let (kind, rest) = v.str().split_once('.').ok_or(ImportError::BwDamaged)?;
    if kind != "2" {
        return Err(ImportError::BwDamaged);
    }
    let mut parts = rest.split('|');
    let (Some(iv), Some(ct), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ImportError::BwDamaged);
    };
    let d = |s: &str| decode(Form::PaddingOptional, s).map_err(|_| ImportError::BwDamaged);
    let s = Sealed {
        iv: d(iv)?,
        ct: d(ct)?,
        mac: d(tag)?,
    };
    if s.iv.len() != 16 || s.mac.len() != 32 || s.ct.is_empty() {
        return Err(ImportError::BwDamaged);
    }
    Ok(s)
}

fn decrypt(doc: &Json, password: Option<&SecretString>, ctx: &Context<'_>) -> R<SecretBytes> {
    let (Some(kdf_type), Json::Str(salt)) = (doc.get("kdfType").int(), doc.get("salt")) else {
        return Err(ImportError::BwAccount);
    };
    let count = |k: &str| {
        doc.get(k)
            .int()
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0)
    };
    let iterations = count("kdfIterations");
    match kdf_type {
        0 if iterations == 0 => return Err(ImportError::BwKdf),
        0 | 1 => {}
        _ => return Err(ImportError::BwKdf),
    }
    let check = sealed(doc.get("encKeyValidation_DO_NOT_EDIT"))?;
    let data = sealed(doc.get("data"))?;
    let password = password.ok_or(ImportError::WrongPassword)?;
    ctx.check_cancel()?;
    let pw = SecretBytes::new(password.expose().as_bytes().to_vec());
    let salt = salt.expose().as_bytes();
    let key = if kdf_type == 0 {
        kdf::pbkdf2(Prf::Sha256, &pw, salt, iterations, 32)
    } else {
        let salt = hash::sha256(&[salt]);
        let (memory, lanes) = (count("kdfMemory"), count("kdfParallelism"));
        kdf::import_argon2id(&pw, salt.expose(), iterations, memory, lanes, 32)
    }
    .map_err(|e| match e {
        app_crypto::Error::KdfCost => ImportError::KdfCost,
        _ => ImportError::BwKdf,
    })?;
    drop(pw);
    ctx.check_cancel()?;
    let expand =
        |info: &[u8]| kdf::hkdf_expand_sha256(&key, info, 32).map_err(|_| ImportError::BwKdf);
    let (enc, mac_key) = (expand(b"enc")?, expand(b"mac")?);
    if !mac::verify_hmac_sha256(mac_key.expose(), &[&check.iv, &check.ct], &check.mac) {
        return Err(ImportError::WrongPassword);
    }
    if !mac::verify_hmac_sha256(mac_key.expose(), &[&data.iv, &data.ct], &data.mac) {
        return Err(ImportError::BwDamaged);
    }
    cipher::decrypt(Cipher::Aes256Cbc, &enc, &data.iv, &data.ct).map_err(|_| ImportError::BwDamaged)
}

/// FEA-08.43 to FEA-08.48 on a plain export (or the decrypted `data`).
fn build(doc: &Json, ctx: &Context<'_>) -> R<Imported> {
    let mut b = Builder::new(ctx, ROOT)?;
    let folders = match doc.get("folders") {
        f if f.is_array() => f,
        _ => doc.get("collections"),
    };
    let items = doc.get("items");
    if !folders.is_array() || !items.is_array() {
        return Ok(b.finish());
    }
    // FEA-08.44, L08-7c: every folder id maps to its deepest group.
    let mut groups: HashMap<String, usize> = HashMap::new();
    for f in folders.items() {
        let g = b.path(0, f.get("name").str().split('/').filter(|p| !p.is_empty()))?;
        groups.insert(f.get("id").str().to_owned(), g);
    }
    for item in items.items() {
        let folder = match item.get("folderId").str() {
            "" => item
                .get("collectionIds")
                .items()
                .first()
                .map_or("", Json::str),
            f => f,
        };
        // FEA-08.45: an empty or unknown id means the root.
        let g = match folder {
            "" => 0,
            f => groups.get(f).copied().unwrap_or(0),
        };
        let d = entry(&mut b, item)?;
        b.add(g, d)?;
    }
    Ok(b.finish())
}

fn entry(b: &mut Builder<'_>, item: &Json) -> R<Draft> {
    let zone = b.ctx().zone;
    let mut d = b.draft()?;
    d.set("Title", item.get("name").text(), false)?;
    d.set("Notes", item.get("notes").text(), false)?;
    if item.get("favorite").is_true() {
        d.tag("Favorite");
    }
    let login = item.get("login");
    d.set("UserName", login.get("username").text(), false)?;
    d.set("Password", login.get("password").text(), true)?;
    d.totp(login.get("totp").str())?;
    let mut first = true;
    for u in login.get("uris").items() {
        let uri = u.get("uri").text();
        if uri.is_empty() {
            continue;
        }
        if first {
            d.set("URL", uri, false)?;
            first = false;
        } else {
            d.extra_url(uri)?;
        }
    }
    let passkeys = login.get("fido2Credentials").items();
    for c in passkeys {
        passkey(&mut d, c)?;
    }
    if !passkeys.is_empty() {
        d.tag("Passkey");
    }
    let identity = item.get("identity");
    if identity.is_object() {
        identity_fields(&mut d, identity)?;
    }
    let card = item.get("card");
    for (key, protected) in [
        ("cardholderName", false),
        ("brand", false),
        ("number", false),
        ("expMonth", false),
        ("expYear", false),
        ("code", true),
    ] {
        let v = card.get(key).text();
        if !v.is_empty() {
            d.set(&format!("card_{key}"), v, protected)?;
        }
    }
    for f in item.get("fields").items() {
        let kind = f.get("type").int();
        let value = if kind == Some(3) {
            SecretString::new(String::new())
        } else {
            f.get("value").text()
        };
        d.custom(f.get("name").str(), value, kind == Some(1))?;
    }
    let t = |k: &str| super::parse_time(item.get(k).str(), zone);
    if let Some(c) = t("creationDate") {
        d.entry_mut().times.creation = c;
    }
    if let Some(m) = t("revisionDate") {
        let times = &mut d.entry_mut().times;
        times.last_modification = m;
        times.last_access = m;
    }
    // FEA-08.48: history items, in file order.
    for h in item.get("passwordHistory").items() {
        let old = h.get("password").str();
        let Some(when) = super::parse_time(h.get("lastUsedDate").str(), zone) else {
            continue;
        };
        if old.is_empty() {
            continue;
        }
        let created = d.entry_mut().times.creation;
        let mut e = Entry::new(d.entry_mut().uuid, created);
        let fields = ["Title", "UserName", "URL", "Notes"]
            .iter()
            .map(|n| ((*n).to_owned(), field(d.value(n), false)))
            .chain([("Password".to_owned(), field(old, true))])
            .collect();
        e.replace_fields(fields);
        e.times.last_modification = when;
        e.times.last_access = when;
        d.history(e)?;
    }
    Ok(d)
}

fn field(v: &str, protected: bool) -> Field {
    Field {
        value: Text::from(v).into_secret(),
        protected,
    }
}

/// FEA-08.46.
fn identity_fields(d: &mut Draft, id: &Json) -> R<()> {
    let s = |k: &str| id.get(k).str();
    // Built in wiping buffers: identity data is personal.
    let join = |out: &mut Text, keys: &[&str], sep: &str| {
        for (i, v) in keys
            .iter()
            .map(|k| s(k))
            .filter(|v| !v.is_empty())
            .enumerate()
        {
            if i > 0 {
                out.push_str(sep);
            }
            out.push_str(v);
        }
    };
    let mut name = Text::new();
    join(
        &mut name,
        &["title", "firstName", "middleName", "lastName"],
        " ",
    );
    d.set("identity_name", name.into_secret(), false)?;
    let mut address = Text::new();
    join(&mut address, &["address1", "address2", "address3"], "\n");
    for (sep, key) in [
        ("\n", "city"),
        (", ", "state"),
        (" ", "postalCode"),
        ("\n", "country"),
    ] {
        address.push_str(sep);
        address.push_str(s(key));
    }
    let address = address.into_secret();
    d.set("identity_address", address, false)?;
    for (key, protected) in [
        ("company", false),
        ("email", false),
        ("phone", false),
        ("ssn", true),
        ("passportNumber", true),
        ("licenseNumber", true),
    ] {
        let v = id.get(key).text();
        if !v.is_empty() {
            d.set(&format!("identity_{key}"), v, protected)?;
        }
    }
    let user = id.get("username").text();
    if d.value("UserName").is_empty() {
        d.set("UserName", user, false)
    } else {
        d.set("identity_username", user, false)
    }
}

/// FEA-08.47: one credential; a later one overwrites an earlier one.
fn passkey(d: &mut Draft, c: &Json) -> R<()> {
    let mut hex = Text::new();
    for ch in c
        .get("credentialId")
        .str()
        .chars()
        .filter(char::is_ascii_hexdigit)
    {
        hex.push(ch);
    }
    let raw = hex_decode(hex.as_str());
    d.set(
        "KPEX_PASSKEY_CREDENTIAL_ID",
        encode_secret(Form::Url, raw.expose()),
        true,
    )?;
    // LD-143 (4): a key that is not valid base64url leaves no PEM, also
    // when an earlier credential set one. Decoded into wiping memory.
    match decode_secret(Form::Url, c.get("keyValue").str()) {
        Ok(key) => {
            let mut pem = Text::from("-----BEGIN PRIVATE KEY-----");
            pem.push_str(encode_secret(Form::Padded, key.expose()).expose());
            pem.push_str("-----END PRIVATE KEY-----");
            d.set("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem.into_secret(), true)?;
        }
        Err(_) => d.remove("KPEX_PASSKEY_PRIVATE_KEY_PEM"),
    }
    d.set("KPEX_PASSKEY_USERNAME", c.get("userName").text(), false)?;
    d.set("KPEX_PASSKEY_RELYING_PARTY", c.get("rpId").text(), false)?;
    d.set("KPEX_PASSKEY_USER_HANDLE", c.get("userHandle").text(), true)
}

/// Hex digits to bytes; an odd count reads as if a `0` led. `hex` holds
/// only ASCII hex digits.
fn hex_decode(hex: &str) -> SecretBytes {
    let lead = hex.len() % 2;
    let mut out = SecretBytes::zeroed(hex.len().div_ceil(2));
    let mut acc = 0u8;
    for (i, c) in hex.chars().enumerate() {
        let v = c
            .to_digit(16)
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0);
        acc = acc.wrapping_shl(4) | v;
        let at = i.saturating_add(lead);
        if at % 2 == 1 {
            if let Some(slot) = out.expose_mut().get_mut(at / 2) {
                *slot = acc;
            }
            acc = 0;
        }
    }
    out
}
