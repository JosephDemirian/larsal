//! CSV export (FEA-09.3 to FEA-09.6).
//!
//! Guarantees: the header line of FEA-09.3; every field in `"` with `"`
//! doubled and nothing else escaped; LF after every record; UTF-8 without
//! a byte order mark; groups depth first from the root, a group's own
//! entries in stored order before its child groups, the recycle bin
//! included; live entries only.

use crate::text::Text;
use crate::{refs, totp};
use larsal_crypto::secret::SecretBytes;
use larsal_model::{Entry, Group, Icon, Time, Vault};

/// The first line, LF included (FEA-09.3).
pub const HEADER: &str = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n";

/// The CSV export of `vault`. `now` is the clock for placeholders in the
/// TOTP label (MOD-08); stored values are written unresolved.
#[must_use]
pub fn csv(vault: &Vault, now: Time) -> SecretBytes {
    let mut out = Text::from(HEADER);
    let ctx = refs::Context::new(Some(vault), now);
    let mut stack: Vec<(&Group, String)> = vec![(&vault.root, vault.root.name.clone())];
    while let Some((g, path)) = stack.pop() {
        for e in &g.entries {
            record(&mut out, &path, e, &ctx);
        }
        stack.extend(
            g.groups
                .iter()
                .rev()
                .map(|c| (c, format!("{path}/{}", c.name))),
        );
    }
    out.into_secret_bytes()
}

fn record(out: &mut Text, path: &str, e: &Entry, ctx: &refs::Context<'_>) {
    field(out, path);
    for name in ["Title", "UserName", "Password", "URL", "Notes"] {
        out.push(',');
        field(out, e.value(name));
    }
    out.push(',');
    // FEA-09.6: the FEA-04 link from the settings, labels resolved.
    match totp::settings(e) {
        Some(s) => {
            let title = refs::resolve(e.value("Title"), e, ctx).text;
            let user = refs::resolve(e.value("UserName"), e, ctx).text;
            field(out, s.uri(title.expose(), user.expose()).expose());
        }
        None => field(out, ""),
    }
    out.push(',');
    let icon = match e.icon {
        Icon::Standard(n) => n,
        Icon::Custom(_) => 0,
    };
    field(out, &icon.to_string());
    out.push(',');
    field(out, &utc(e.times.last_modification));
    out.push(',');
    field(out, &utc(e.times.creation));
    out.push('\n');
}

fn field(out: &mut Text, value: &str) {
    out.push('"');
    for part in value.split_inclusive('"') {
        out.push_str(part);
        if part.ends_with('"') {
            out.push('"');
        }
    }
    out.push('"');
}

/// `YYYY-MM-DDTHH:mm:ssZ`; empty for a time outside year 1 to 9999.
pub(crate) fn utc(t: Time) -> String {
    t.to_civil().map_or_else(String::new, |c| {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    })
}
