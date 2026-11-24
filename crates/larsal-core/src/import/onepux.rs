//! .1pux import (FEA-08 section C): a ZIP archive read with Larsal's own ZIP
//! reader, its `export.data` JSON and its `files/` members.
//!
//! Guarantees: `export.data` is inflated only up to 256 MiB, and each
//! `files/` member (attachment or icon) only up to the room the result's
//! running byte budget has left (`Builder::room`), both checked from the
//! declared size before anything is inflated (FEA-08.67), so naming one
//! large member many times stops at the budget; a JSON error is
//! `MSG-JSON` (the reference imports nothing silently); only the first
//! account is read.

use super::json::{self, Json};
use super::zip::{self, Archive};
use super::{Builder, Context, Draft, ImportError, Imported, Limit, R};
use crate::export::csv::utc;
use crate::text::Text;
use larsal_model::{Icon, Time};

/// The result's root group name (L08-9).
pub const ROOT: &str = "1PUX Import";
/// The most `export.data` may inflate to (FEA-08.67).
pub const MAX_DATA: usize = 256 << 20;

/// Reads a .1pux file.
///
/// # Errors
/// `MSG-1PUX-NOTZIP`, `MSG-1PUX-NODATA`, the unsupported-ZIP error,
/// `MSG-JSON`, `MSG-TOO-LARGE`; `Cancelled`.
pub fn read(bytes: &[u8], ctx: &Context<'_>) -> Result<Imported, ImportError> {
    let archive = zip::open(bytes)?;
    let member = archive
        .find("export.data", true)
        .ok_or(ImportError::OnePuxNoData)?;
    let data = archive.read(member, MAX_DATA, Limit::File)?;
    let doc = json::parse(data.expose())?;
    drop(data);
    let mut b = Builder::new(ctx, ROOT)?;
    let account = doc.get("accounts").items().first();
    let vaults = account.map_or(&[][..], |a| a.get("vaults").items());
    for vault in vaults {
        let (attrs, items) = (vault.get("attrs"), vault.get("items"));
        if !attrs.is_object() || !items.is_array() {
            continue;
        }
        let g = b.new_child(0, attrs.get("name").str(), None)?;
        let avatar = attrs.get("avatar").str();
        if !avatar.is_empty()
            && let Some(m) = archive.find(&format!("files/{avatar}"), false)
        {
            let (room, over) = b.icon_room();
            let png = archive.read(m, room, over)?;
            let id = b.icon(png.expose())?;
            if let Some(group) = b.group_mut(g) {
                group.icon = Icon::Custom(id);
            }
        }
        for item in items.items() {
            let d = entry(&mut b, &archive, item)?;
            b.add(g, d)?;
        }
    }
    Ok(b.finish())
}

/// FEA-08.30.
fn entry(b: &mut Builder<'_>, archive: &Archive<'_>, item: &Json) -> R<Draft> {
    let mut d = b.draft()?;
    let (o, det) = (item.get("overview"), item.get("details"));
    d.set("Title", o.get("title").text(), false)?;
    d.set("URL", o.get("url").text(), false)?;
    for u in o.get("urls").items() {
        let url = u.get("url").text();
        if !url.is_empty() && url.expose() != d.value("URL") {
            d.extra_url(url)?;
        }
    }
    for t in o.get("tags").items() {
        if let Json::Str(tag) = t {
            d.tag(tag.expose());
        }
    }
    if item.get("favIndex").int() == Some(1) {
        d.tag("Favorite");
    }
    if item.get("state").str() == "archived" {
        d.tag("Archived");
    }
    for f in det.get("loginFields").items() {
        let designation = f.get("designation").str();
        if designation.eq_ignore_ascii_case("username") {
            d.set("UserName", f.get("value").text(), false)?;
        } else if designation.eq_ignore_ascii_case("password") {
            d.set("Password", f.get("value").text(), true)?;
        }
    }
    if d.value("Password").is_empty() {
        d.set("Password", det.get("password").text(), true)?;
    }
    d.set("Notes", det.get("notesPlain").text(), false)?;
    for section in det.get("sections").items() {
        section_fields(b, &mut d, archive, section)?;
    }
    attach(b, &mut d, archive, det.get("documentAttributes"))?;
    // A missing time counts as 0, 1970-01-01T00:00:00Z (FEA-08.30).
    let secs = |k: &str| {
        let v = item.get(k).int().unwrap_or(0);
        Time::from_unix(v)
            .or_else(|| Time::from_unix(0))
            .unwrap_or_default()
    };
    let times = &mut d.entry_mut().times;
    times.creation = secs("createdAt");
    times.last_modification = secs("updatedAt");
    times.last_access = times.last_modification;
    Ok(d)
}

/// FEA-08.31: one section's fields.
fn section_fields(b: &Builder<'_>, d: &mut Draft, archive: &Archive<'_>, section: &Json) -> R<()> {
    let title = section.get("title").str();
    let prefix = if title.is_empty() {
        super::random_hex(5)?
    } else {
        title.to_owned()
    };
    for f in section.get("fields").items() {
        let label = match f.get("title").str() {
            "" => f.get("id").str(),
            t => t,
        };
        let name = format!("{prefix}_{label}");
        // The value object's first key in sorted order decides.
        let Some((key, v)) = f
            .get("value")
            .members()
            .iter()
            .min_by(|a, b| larsal_model::entry::cmp_utf16(&a.0, &b.0))
        else {
            continue;
        };
        let mut protected = false;
        let mut text = Text::new();
        match key.as_str() {
            "totp" if !d.has_totp() => {
                d.totp(v.str())?;
                continue;
            }
            "totp" => {
                if !v.str().is_empty() {
                    let link = d.totp_link(v.str());
                    let n = d.numbered("otp");
                    d.set(&n, link, true)?;
                }
                continue;
            }
            "file" => {
                attach(b, d, archive, v)?;
                continue;
            }
            "date" => {
                if let Some(t) = v.int().and_then(Time::from_unix) {
                    text.push_str(&utc(t));
                }
            }
            "email" => text.push_str(v.get("email_address").str()),
            "address" => {
                let s = |k: &str| v.get(k).str();
                for (sep, k) in [
                    ("", "street"),
                    ("\n", "city"),
                    (", ", "state"),
                    (" ", "zip"),
                    ("\n", "country"),
                ] {
                    text.push_str(sep);
                    text.push_str(s(k));
                }
            }
            "concealed" => {
                text.push_str(v.text().expose());
                protected = true;
            }
            _ => text.push_str(v.text().expose()),
        }
        if !text.is_empty() {
            d.set(&name, text.into_secret(), protected)?;
        }
    }
    Ok(())
}

/// FEA-08.32: `files/<documentId>__<fileName>` becomes an attachment named
/// `fileName`; a missing member is skipped.
fn attach(b: &Builder<'_>, d: &mut Draft, archive: &Archive<'_>, doc: &Json) -> R<()> {
    let (id, file) = (doc.get("documentId").str(), doc.get("fileName").str());
    if id.is_empty() && file.is_empty() {
        return Ok(());
    }
    let Some(m) = archive.find(&format!("files/{id}__{file}"), false) else {
        return Ok(());
    };
    let (room, over) = b.room(d);
    let data = archive.read(m, room, over)?;
    d.attach(file, data)
}
