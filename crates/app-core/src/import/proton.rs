//! Proton Pass JSON import (FEA-08 section F), the unzipped plain export.
//!
//! Guarantees: an encrypted export is refused (`MSG-PROTON-ENCRYPTED`);
//! vaults come in sorted key order, items in file order; wrong JSON types
//! read as empty values (FEA-08.65).

use super::json::{self, Json};
use super::{Builder, Context, Draft, ImportError, Imported, Limit, MAX_FILE, R};
use crate::text::Text;
use app_model::Time;
use app_model::entry::cmp_utf16;

/// The result's root group name.
pub const ROOT: &str = "Proton Pass Import";

/// `MSG-PROTON-UNKNOWN-TYPE`, written into the notes (FEA-08.52).
#[must_use]
pub fn unknown_type_note(kind: &str) -> String {
    format!("Unrecognized item type: {kind}. Its content is kept in the content_ custom fields.")
}

/// Reads a Proton Pass JSON export.
///
/// # Errors
/// `MSG-JSON`, `MSG-PROTON-ENCRYPTED`, `MSG-TOO-LARGE`; `Cancelled`.
pub fn read(bytes: &[u8], ctx: &Context<'_>) -> Result<Imported, ImportError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE {
        return Err(ImportError::TooLarge(Limit::File));
    }
    let doc = json::parse(bytes)?;
    if doc.get("encrypted").is_true() {
        return Err(ImportError::ProtonEncrypted);
    }
    let mut b = Builder::new(ctx, ROOT)?;
    let mut vaults: Vec<&(String, Json)> = doc.get("vaults").members().iter().collect();
    vaults.sort_by(|x, y| cmp_utf16(&x.0, &y.0));
    for (_, vault) in vaults {
        let g = b.new_child(0, vault.get("name").str(), None)?;
        if let Some(group) = b.group_mut(g) {
            group.notes = vault.get("description").str().to_owned();
        }
        for item in vault.get("items").items() {
            let d = entry(&mut b, item)?;
            b.add(g, d)?;
        }
    }
    Ok(b.finish())
}

fn entry(b: &mut Builder<'_>, item: &Json) -> R<Draft> {
    let now = b.ctx().now;
    let mut d = b.draft()?;
    let data = item.get("data");
    d.set("Title", data.at(&["metadata", "name"]).text(), false)?;
    d.set("Notes", data.at(&["metadata", "note"]).text(), false)?;
    if item.get("pinned").is_true() {
        d.tag("Favorite");
    }
    let c = data.get("content");
    let kind = data.get("type").str();
    let is = |k: &str| kind.eq_ignore_ascii_case(k);
    let text = |k: &str| c.get(k).text();
    if is("login") {
        d.set("UserName", text("itemUsername"), false)?;
        d.set("Password", text("password"), true)?;
        d.totp(c.get("totpUri").str())?;
        let email = text("itemEmail");
        if !email.is_empty() {
            if d.value("UserName").is_empty() {
                d.set("UserName", email, false)?;
            } else {
                d.set("login_email", email, false)?;
            }
        }
        let mut first = true;
        for u in c.get("urls").items() {
            let url = u.text();
            if url.is_empty() {
                continue;
            }
            if first {
                d.set("URL", url, false)?;
                first = false;
            } else {
                d.extra_url(url)?;
            }
        }
    } else if is("creditCard") {
        d.set("UserName", text("number"), false)?;
        d.set("Password", text("verificationNumber"), true)?;
        for (key, protected) in [
            ("cardholderName", false),
            ("pin", true),
            ("expirationDate", false),
        ] {
            let v = text(key);
            if !v.is_empty() {
                d.set(&format!("card_{key}"), v, protected)?;
            }
        }
    } else if is("wifi") {
        d.set("UserName", text("ssid"), false)?;
        d.set("Password", text("password"), true)?;
        d.set("wifi_security", text("security"), false)?;
    } else if is("sshKey") {
        d.set("ssh_public_key", text("publicKey"), false)?;
        d.set("ssh_private_key", text("privateKey"), true)?;
    } else if !is("note") && !is("custom") {
        let mut notes = Text::from(&unknown_type_note(kind));
        notes.push_str("\n\n");
        notes.push_str(d.value("Notes"));
        d.set("Notes", notes.into_secret(), false)?;
        let mut keys: Vec<&(String, Json)> = c.members().iter().collect();
        keys.sort_by(|x, y| cmp_utf16(&x.0, &y.0));
        for (key, v) in keys {
            let v = v.text();
            if !v.is_empty() {
                d.set(&format!("content_{key}"), v, false)?;
            }
        }
    }
    for f in data.get("extraFields").items() {
        let kind = f.get("type").str();
        // Types match ignoring case, as in the reference (LD-148).
        let value = if kind.eq_ignore_ascii_case("totp") {
            f.at(&["data", "totpUri"]).text()
        } else {
            f.at(&["data", "content"]).text()
        };
        d.custom(
            f.get("fieldName").str(),
            value,
            kind.eq_ignore_ascii_case("hidden"),
        )?;
    }
    if item.get("state").int() == Some(2) {
        let times = &mut d.entry_mut().times;
        times.expires = true;
        times.expiry = now;
    }
    let secs = |k: &str| {
        let v = item.get(k).int().unwrap_or(0);
        Time::from_unix(v)
            .or_else(|| Time::from_unix(0))
            .unwrap_or_default()
    };
    let times = &mut d.entry_mut().times;
    times.creation = secs("createTime");
    times.last_modification = secs("modifyTime");
    times.last_access = times.last_modification;
    Ok(d)
}
