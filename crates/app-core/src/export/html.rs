//! HTML export (FEA-09.7 to FEA-09.12): one self-contained page.
//!
//! Markup App chose (FEA-09.8: the class names the tests check):
//! - head: `<meta charset="UTF-8">`, the Content-Security-Policy meta
//!   element [`CSP`], `<title>` with the vault name, one inline `<style>`;
//! - `<h1>` vault name; `<p class="vault-description">` (only when not
//!   empty); `<p class="vault-path">`;
//! - one `<section class="group">` per shown group: `<h2>` with the path,
//!   then `<p class="group-notes">`, then one `<div class="entry">` per
//!   shown entry: `<h3>` title, then a `<dl>` of `<dt>` labels and `<dd>`
//!   values with class `user-name`, `password`, `url`, `field` (custom
//!   fields) or `notes`;
//! - icons (desktop only): `<img class="icon" alt="" src="data:image/png;base64,…">`
//!   first in each `<h2>` and `<h3>`.
//!
//! Multi-line values keep their line breaks and spaces through
//! `white-space: pre-wrap`. Every vault text is escaped (FEA-09.11); only
//! `http` and `https` URLs become links (L09-2).

use crate::recycle;
use crate::search::run::passkey_field;
use crate::text::Text;
use app_crypto::secret::SecretBytes;
use app_model::entry::STANDARD_FIELDS;
use app_model::{Entry, Group, Icon, Vault};
use core::cmp::Ordering;

/// The page's Content-Security-Policy (FEA-09.11, L09-2).
pub const CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'";

/// The "sort entries by" choice of the HTML dialog (FEA-09.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Name, ascending: the default.
    #[default]
    NameAscending,
    /// Name, descending.
    NameDescending,
    /// The order in the vault.
    VaultOrder,
}

/// The choices in dialog order.
pub const SORTS: [Sort; 3] = [Sort::NameAscending, Sort::NameDescending, Sort::VaultOrder];

/// What one HTML export needs.
pub struct Options<'a> {
    /// The sort choice.
    pub sort: Sort,
    /// The vault file's path: the full path on the desktop, as typed on the
    /// command line (FEA-09.8).
    pub path: &'a str,
    /// Desktop only (FEA-09.12): the PNG bytes of an icon at the entry
    /// list's size. `None` on the command line: no images at all.
    pub icon: Option<&'a dyn Fn(Icon) -> Option<Vec<u8>>>,
}

const STYLE: &str = "body{font:14px -apple-system,sans-serif;margin:24px;color:#1d1d1f}\
h1{font-size:22px}h2{font-size:17px;margin-top:28px}h3{font-size:15px;margin:16px 0 4px}\
.icon{width:16px;height:16px;vertical-align:-3px;margin-right:6px}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:0}\
dt{color:#6e6e73}dd{margin:0}\
.vault-description,.group-notes,.field,.notes{white-space:pre-wrap}";

/// The HTML export of `vault` (FEA-09.8 to FEA-09.12).
#[must_use]
pub fn html(vault: &Vault, o: &Options<'_>) -> SecretBytes {
    let mut out =
        Text::from("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
    out.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"");
    out.push_str(CSP); // fixed text, no `"` or `&` in it
    out.push_str("\">\n<title>");
    escape(&mut out, &vault.meta.name);
    out.push_str("</title>\n<style>");
    out.push_str(STYLE);
    out.push_str("</style>\n</head>\n<body>\n<h1>");
    escape(&mut out, &vault.meta.name);
    out.push_str("</h1>\n");
    if !vault.meta.description.is_empty() {
        out.push_str("<p class=\"vault-description\">");
        escape(&mut out, &vault.meta.description);
        out.push_str("</p>\n");
    }
    out.push_str("<p class=\"vault-path\">");
    escape(&mut out, o.path);
    out.push_str("</p>\n");
    let bin = recycle::bin_id(vault);
    // Depth first; `path` holds the escaped names joined by " › ".
    let mut stack: Vec<(&Group, String)> = vec![(&vault.root, escaped(&vault.root.name))];
    while let Some((g, path)) = stack.pop() {
        if Some(g.uuid) == bin {
            continue;
        }
        group(&mut out, g, &path, o);
        let mut children: Vec<&Group> = g.groups.iter().collect();
        sort(&mut children, |c| &c.name, o.sort);
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|c| (c, format!("{path} › {}", escaped(&c.name)))),
        );
    }
    out.push_str("</body>\n</html>\n");
    out.into_secret_bytes()
}

/// FEA-09.9: names compared ignoring case (character by character, no
/// lowercased copy of a title); stable, so equal names keep their stored
/// order.
fn sort<T>(items: &mut [&T], name: impl Fn(&T) -> &str, how: Sort) {
    let cmp = |a: &&T, b: &&T| -> Ordering {
        name(a)
            .chars()
            .flat_map(char::to_lowercase)
            .cmp(name(b).chars().flat_map(char::to_lowercase))
    };
    match how {
        Sort::NameAscending => items.sort_by(cmp),
        Sort::NameDescending => items.sort_by(|a, b| cmp(b, a)),
        Sort::VaultOrder => {}
    }
}

fn group(out: &mut Text, g: &Group, path: &str, o: &Options<'_>) {
    if g.entries.is_empty() && g.notes.is_empty() {
        return;
    }
    out.push_str("<section class=\"group\">\n<h2>");
    icon(out, g.icon, o);
    out.push_str(path);
    out.push_str("</h2>\n");
    if !g.notes.is_empty() {
        out.push_str("<p class=\"group-notes\">");
        escape(out, &g.notes);
        out.push_str("</p>\n");
    }
    let mut entries: Vec<&Entry> = g.entries.iter().collect();
    sort(&mut entries, |e| e.value("Title"), o.sort);
    for e in entries {
        entry(out, e, o);
    }
    out.push_str("</section>\n");
}

/// FEA-09.10: an entry with none of the values is left out.
fn entry(out: &mut Text, e: &Entry, o: &Options<'_>) {
    let custom: Vec<(&str, &str)> = e
        .fields()
        .filter(|(n, _)| !STANDARD_FIELDS.contains(n) && !passkey_field(n))
        .map(|(n, f)| (n, f.value.expose()))
        .collect();
    let (user, password, url, notes) = (
        e.value("UserName"),
        e.value("Password"),
        e.value("URL"),
        e.value("Notes"),
    );
    if user.is_empty()
        && password.is_empty()
        && url.is_empty()
        && notes.is_empty()
        && custom.is_empty()
    {
        return;
    }
    out.push_str("<div class=\"entry\">\n<h3>");
    icon(out, e.icon, o);
    escape(out, e.value("Title"));
    out.push_str("</h3>\n<dl>\n");
    if !user.is_empty() {
        row(out, "User name", "user-name", user);
    }
    if !password.is_empty() {
        row(out, "Password", "password", password);
    }
    if !url.is_empty() {
        out.push_str("<dt>URL</dt><dd class=\"url\">");
        let linked = url.split_once(':').is_some_and(|(s, _)| {
            s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https")
        });
        if linked {
            out.push_str("<a href=\"");
            escape(out, url);
            out.push_str("\">");
        }
        // FEA-09.11: the first 100 characters, then an ellipsis.
        match url.char_indices().nth(100) {
            Some((cut, _)) => {
                escape(out, url.get(..cut).unwrap_or(url));
                out.push('…');
            }
            None => escape(out, url),
        }
        if linked {
            out.push_str("</a>");
        }
        out.push_str("</dd>\n");
    }
    for (name, value) in custom {
        out.push_str("<dt>");
        escape(out, name);
        out.push_str("</dt><dd class=\"field\">");
        escape(out, value);
        out.push_str("</dd>\n");
    }
    if !notes.is_empty() {
        row(out, "Notes", "notes", notes);
    }
    out.push_str("</dl>\n</div>\n");
}

fn row(out: &mut Text, label: &str, class: &str, value: &str) {
    out.push_str("<dt>");
    out.push_str(label);
    out.push_str("</dt><dd class=\"");
    out.push_str(class);
    out.push_str("\">");
    escape(out, value);
    out.push_str("</dd>\n");
}

fn icon(out: &mut Text, i: Icon, o: &Options<'_>) {
    if let Some(png) = o.icon.and_then(|f| f(i)) {
        out.push_str("<img class=\"icon\" alt=\"\" src=\"data:image/png;base64,");
        out.push_str(&app_crypto::base64::encode(
            app_crypto::base64::Form::Padded,
            &png,
        ));
        out.push_str("\">");
    }
}

/// FEA-09.11 escaping.
fn escape(out: &mut Text, s: &str) {
    let mut rest = s;
    while let Some(i) = rest.find(['&', '<', '>', '"', '\'']) {
        out.push_str(rest.get(..i).unwrap_or(""));
        out.push_str(match rest.get(i..=i) {
            Some("&") => "&amp;",
            Some("<") => "&lt;",
            Some(">") => "&gt;",
            Some("\"") => "&quot;",
            _ => "&#39;",
        });
        rest = rest.get(i.saturating_add(1)..).unwrap_or("");
    }
    out.push_str(rest);
}

fn escaped(s: &str) -> String {
    let mut t = Text::new();
    escape(&mut t, s);
    t.as_str().to_owned()
}
