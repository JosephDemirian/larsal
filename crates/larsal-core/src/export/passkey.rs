//! Passkey export (INT-04.49, INT-04.50, SD-07): one entry's passkey as a
//! plain `.passkey` file.
//!
//! Guarantees: a JSON object with the six text members sorted by name,
//! indented by 4 spaces, `": "` after each name, LF line ends and a final
//! LF, UTF-8, `/` not escaped (INT-04.49); no backup flags and nothing
//! else of the entry. Built in a wiping buffer and returned as
//! `SecretBytes`; the caller writes it with
//! [`crate::storage::write_export`] (0600) after asking [`WARNING`].

use crate::text::Text;
use larsal_crypto::secret::SecretBytes;
use larsal_model::Entry;

/// MI04-30 (INT-04.50 step 1, SD-07): asked before every passkey export,
/// buttons Yes and No, No the default.
pub const WARNING: &str = "A .passkey file is plain text. The private key inside is not encrypted and works for anyone who has the file. Export anyway?";

/// The passkey user name other apps write (INT-04.4), as bytes.
const FOREIGN_USER: [u8; 21] = [
    0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x41, 0x53, 0x53, 0x4B, 0x45, 0x59, 0x5F, 0x55, 0x53, 0x45,
    0x52, 0x4E, 0x41, 0x4D, 0x45,
];

/// The `.passkey` file of `e`; `None` when it has no private key field
/// (the Passkeys report's rows, INT-04.52).
#[must_use]
pub fn file(e: &Entry) -> Option<SecretBytes> {
    let key = e.field("KPEX_PASSKEY_PRIVATE_KEY_PEM")?.value.expose();
    let foreign = core::str::from_utf8(&FOREIGN_USER).unwrap_or("");
    // INT-04.4: the id and the name the entry answers with.
    let id = e.field("KPEX_PASSKEY_GENERATED_USER_ID").map_or_else(
        || e.value("KPEX_PASSKEY_CREDENTIAL_ID"),
        |f| f.value.expose(),
    );
    let user = e
        .field(foreign)
        .map_or_else(|| e.value("KPEX_PASSKEY_USERNAME"), |f| f.value.expose());
    let members = [
        ("credentialId", id),
        ("privateKey", key),
        ("relyingParty", e.value("KPEX_PASSKEY_RELYING_PARTY")),
        ("url", e.value("URL")),
        ("userHandle", e.value("KPEX_PASSKEY_USER_HANDLE")),
        ("username", user),
    ];
    let mut out = Text::from("{\n");
    for (i, (name, value)) in members.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str("    \"");
        out.push_str(name);
        out.push_str("\": \"");
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                c if c < ' ' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push_str("\n}\n");
    Some(out.into_secret_bytes())
}

/// INT-04.50 step 4: the file name: the title with `/` as `_` and the
/// characters `: * ? " < > |` removed, white space trimmed at both ends,
/// plus `.passkey`; an empty result uses the RP ID (D-INT04-14), then
/// `Passkey`.
#[must_use]
pub fn file_name(e: &Entry) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
            .map(|c| if c == '/' { '_' } else { c })
            .collect::<String>()
            .trim()
            .to_owned()
    };
    let mut name = clean(e.value("Title"));
    if name.is_empty() {
        name = clean(e.value("KPEX_PASSKEY_RELYING_PARTY"));
    }
    if name.is_empty() {
        "Passkey".clone_into(&mut name);
    }
    name.push_str(".passkey");
    name
}
