//! Show as QR Code in the Mac app (FEA-10, E21-S2, LD-359 to LD-362): the one
//! value the user selected, or a Wi-Fi join text, as one module matrix. The
//! text stays in Rust; Swift gets the matrix, a ticket that names this one
//! request, and, only after a warning, PNG bytes or a written file.
//!
//! A ticket binds the request to its vault, source and revision. It lives in
//! the vault's edit state, so a lock or a close drops it. Every later step
//! makes the text again from the same source, at the ticket's own time, and
//! compares the revision. The session's change doors do the same on their way
//! out ([`EditState::qr_check`]), so an edit, a reload or a merge ends the
//! ticket for good when it happens: undoing it brings nothing back. FEA-10.14
//! asks for a source revision; this is one that no read of the vault can move
//! by accident, as the vault's change count can.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use larsal_core::{icons, storage};
use larsal_crypto::hash::{Algorithm, Hasher};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::{Entry, Time, Vault};

use crate::edit::{EditState, Qr, qr_of, showable};
use crate::session::{LarsalError, MAX_TEXT, Session};
use crate::views::{check_field, find, now, parse_id, resolved_at};

#[cfg(test)]
use larsal_qr::MAX_BYTES;
use larsal_qr::Refusal;
/// FEA-10.17: pixels per module of a saved or shared image.
const PNG_PITCH: usize = 8;

// The card's words live once, in larsal-qr, for the app and the `larsal` tool.
/// `MSG-QR-TOO-LARGE`.
#[cfg(test)]
const TOO_LARGE: &str = Refusal::TooLarge.message();
/// `MSG-QR-EMPTY`.
#[cfg(test)]
const EMPTY: &str = Refusal::Empty.message();
/// `MSG-QR-FAILED`.
const FAILED: &str = Refusal::Failed.message();
/// `MSG-QR-WIFI-INVALID`.
#[cfg(test)]
const WIFI_INVALID: &str = Refusal::WifiInvalid.message();
/// `MSG-QR-WIFI-UNSUPPORTED`.
#[cfg(test)]
const WIFI_UNSUPPORTED: &str = Refusal::WifiUnsupported.message();
/// `MSG-QR-SAVE-FAILED`.
const SAVE_FAILED: &str = "The QR image could not be saved.";
/// `MSG-QR-SHARE-FAILED`.
const SHARE_FAILED: &str = "The QR image could not be shared.";

/// Tickets and consents never repeat in a process, across locks and vaults.
static NEXT: AtomicU64 = AtomicU64::new(1);

fn next() -> u64 {
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn refused(text: &str) -> LarsalError {
    LarsalError::Refused(text.to_owned())
}

/// A shown code: its matrix and the ticket that names the request.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct QrShown {
    /// Names this request; never repeats.
    pub ticket: u64,
    /// The matrix (`Debug` hides its modules).
    pub symbol: Qr,
}

/// The action a warning was confirmed for (FEA-10.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum QrExport {
    /// Save Image…
    Save,
    /// Share…
    Share,
}

/// What a ticket was made from.
#[derive(Clone)]
enum Source {
    /// A saved entry's field, resolved as its Show (FEA-10.3).
    Saved { entry: String, field: String },
    /// A field of the open draft, literal.
    Draft { field: String },
    /// A saved entry's join text (FEA-10.4).
    Wifi { entry: String },
}

/// The one live request of a vault (FEA-10.11).
pub(crate) struct Ticket {
    id: u64,
    source: Source,
    /// The time its clock placeholders read at every step: a clock is no
    /// source change (FEA-10.14), and an export is the code on screen.
    at: Time,
    /// SHA-256 of the entry and the text when it was made; never crosses.
    revision: Vec<u8>,
    /// The warning's confirmation and the action it was for.
    consent: Option<(u64, QrExport)>,
}

/// A saved entry and where it sits: the ids of every group from the root down
/// to the one that holds it. A move of any of them is a source change, to the
/// Recycle Bin too, though no value changes (FEA-10.14).
fn located<'a>(v: &'a Vault, id: &str) -> Result<(&'a Entry, Vec<u8>), LarsalError> {
    let id = parse_id(id, LarsalError::UnknownEntry)?;
    let mut chain = Vec::new();
    let e = find(&v.root, id, &mut chain).ok_or(LarsalError::UnknownEntry)?;
    Ok((e, chain.iter().flat_map(|g| g.uuid.0).collect()))
}

/// The text and revision of `e` at `place` with `payload`: its id, place,
/// fields and last change, and the payload, so an edit of a reference's target
/// moves it too.
fn made(e: &Entry, place: &[u8], payload: &[u8]) -> (SecretBytes, Vec<u8>) {
    let mut hash = Hasher::new(Algorithm::Sha256);
    let mut part = |bytes: &[u8]| {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    };
    part(&e.uuid.0);
    part(place);
    part(&e.times.last_modification.0.to_le_bytes());
    for (name, field) in e.fields() {
        part(name.as_bytes());
        part(&[u8::from(field.protected)]);
        part(field.value.expose().as_bytes());
    }
    part(payload);
    (
        SecretBytes::new(payload.to_vec()),
        hash.finalize().expose().to_vec(),
    )
}

/// FEA-10.9: the size is decided on the final bytes, before the encoder
/// (larsal-qr, the path the `larsal` tool shares).
fn encode(payload: &[u8]) -> Result<Qr, LarsalError> {
    larsal_qr::encode(payload)
        .map(qr_of)
        .map_err(|r| refused(r.message()))
}

/// The text and revision of `source` as it reads now, with its clock at `at`.
fn read(
    v: &Vault,
    path: &Path,
    state: &EditState,
    source: &Source,
    at: Time,
) -> Result<(SecretBytes, Vec<u8>), LarsalError> {
    match source {
        Source::Saved { entry, field } => {
            check_field(field)?;
            let (e, place) = located(v, entry)?;
            let f = e.field(field).ok_or(LarsalError::UnknownField)?;
            let value = resolved_at(v, path, e, f.value.expose(), at);
            Ok(made(e, &place, value.expose().as_bytes()))
        }
        Source::Draft { field } => {
            if field.len() > MAX_TEXT {
                return Err(LarsalError::TooLong);
            }
            let e = state
                .draft_entry()
                .ok_or_else(|| refused("The editor is not open."))?;
            let f = e
                .field(field)
                .filter(|_| field == "Password" || showable(field))
                .ok_or(LarsalError::UnknownField)?;
            // A draft is its own source, wherever its entry sits.
            Ok(made(e, &[], f.value.expose().as_bytes()))
        }
        Source::Wifi { entry } => {
            let (e, place) = located(v, entry)?;
            Ok(made(e, &place, join_text(e)?.expose().as_bytes()))
        }
    }
}

impl EditState {
    /// FEA-10.14: the live ticket's text while its source reads as it did. The
    /// first look that finds it moved ends the ticket and its consent for good
    /// (FEA-10.16), so undoing the change brings neither back.
    pub(crate) fn qr_check(&mut self, v: &Vault, path: &Path) -> Option<SecretBytes> {
        let t = self.qr.as_ref()?;
        let same = read(v, path, self, &t.source, t.at)
            .ok()
            .filter(|(_, revision)| *revision == t.revision);
        if same.is_none() {
            self.qr = None;
        }
        same.map(|(payload, _)| payload)
    }

    /// The text of `ticket` while it is the live one and its source unchanged.
    fn qr_live(&mut self, v: &Vault, path: &Path, ticket: u64) -> Option<SecretBytes> {
        self.qr.as_ref().filter(|t| t.id == ticket)?;
        self.qr_check(v, path)
    }
}

/// FEA-10.17's picture: its edge in pixels and its RGBA, black on white at 8
/// pixels per module, quiet zone included.
fn rgba(symbol: &Qr) -> Option<(u32, Vec<u8>)> {
    let side = usize::try_from(symbol.size).ok()?;
    let edge = side.checked_mul(PNG_PITCH)?;
    let mut rgba = vec![0xFF_u8; edge.checked_mul(edge)?.checked_mul(4)?];
    for (row, line) in rgba.chunks_exact_mut(edge * 4).enumerate() {
        let cells = symbol.modules.chunks_exact(side).nth(row / PNG_PITCH)?;
        for (x, pixel) in line.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            if cells.get(x / PNG_PITCH) == Some(&1) {
                *pixel = [0, 0, 0, 0xFF];
            }
        }
    }
    Some((u32::try_from(edge).ok()?, rgba))
}

/// The encoder writes only its header, the image and its end.
fn png(symbol: &Qr) -> Option<Vec<u8>> {
    let (edge, rgba) = rgba(symbol)?;
    icons::encode_png(edge, edge, &rgba)
}

impl Session {
    /// A new request: the old one goes first, whatever comes of this one
    /// (the card's edge cases). The encoder runs outside the session lock,
    /// so a slower older request can end after a newer one: it is dropped,
    /// also when a lock came between (FEA-10.14).
    fn qr_make(&self, vault: u64, source: Source) -> Result<QrShown, LarsalError> {
        let (ticket, at) = (next(), now());
        let (payload, revision) = self.with_qr(vault, |v, path, state| {
            state.qr = None;
            state.qr_newest = ticket;
            read(v, path, state, &source, at)
        })?;
        let symbol = encode(payload.expose())?;
        self.qr_hold(vault, ticket, source, at, revision)?;
        Ok(QrShown { ticket, symbol })
    }

    /// The encoder is done: `ticket` goes live unless a newer request or a
    /// lock came meanwhile.
    fn qr_hold(
        &self,
        vault: u64,
        ticket: u64,
        source: Source,
        at: Time,
        revision: Vec<u8>,
    ) -> Result<(), LarsalError> {
        self.with_qr(vault, |_, _, state| {
            if state.qr_newest != ticket {
                return Err(refused(FAILED));
            }
            state.qr = Some(Ticket {
                id: ticket,
                source,
                at,
                revision,
                consent: None,
            });
            Ok(())
        })
    }

    /// The PNG of `ticket`, when `consent` is its live confirmation of
    /// `action`; `spend` makes it single use.
    fn qr_png(
        &self,
        vault: u64,
        ticket: u64,
        consent: u64,
        action: QrExport,
        spend: bool,
    ) -> Option<Vec<u8>> {
        let payload = self
            .with_qr(vault, |v, path, state| {
                let payload = state.qr_live(v, path, ticket);
                let held = state.qr.as_mut().filter(|t| t.id == ticket);
                let Some(t) = held.filter(|t| t.consent == Some((consent, action))) else {
                    return Err(LarsalError::UnknownEntry);
                };
                if spend {
                    t.consent = None;
                }
                Ok(payload)
            })
            .ok()??;
        png(&encode(payload.expose()).ok()?)
    }

    /// Save's last step: a link at `target`, or a ticket that went stale while
    /// the image was made, writes nothing. The rename never follows a link.
    fn qr_commit(
        &self,
        vault: u64,
        ticket: u64,
        target: &Path,
        bytes: &[u8],
    ) -> Result<(), LarsalError> {
        let link = std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink());
        if link || !self.qr_is_current(vault, ticket) {
            return Err(refused(SAVE_FAILED));
        }
        storage::write_export(target, bytes).map_err(|_| refused(SAVE_FAILED))
    }
}

#[uniffi::export]
impl Session {
    /// Show as QR Code for a saved field (FEA-10.3): the exact result of
    /// [`Session::show_field`], never the field's raw secret when that
    /// refuses it. A crossing of LD-220: the matrix the user asked for.
    ///
    /// # Errors
    /// As `show_field`; `Refused` with `MSG-QR-EMPTY`, `MSG-QR-TOO-LARGE` or
    /// `MSG-QR-FAILED`.
    pub fn qr_show_field(
        &self,
        vault: u64,
        entry: String,
        field: String,
    ) -> Result<QrShown, LarsalError> {
        self.qr_make(vault, Source::Saved { entry, field })
    }

    /// Show as QR Code for a field of the open draft (FEA-10.3): its literal
    /// text, unsaved, with no resolution. Password, or what
    /// [`Session::show_draft_field`] shows. A crossing of LD-220.
    ///
    /// # Errors
    /// `UnknownField`, `TooLong`; `Refused` when no editor is open, or as
    /// [`Session::qr_show_field`].
    pub fn qr_show_draft(&self, vault: u64, field: String) -> Result<QrShown, LarsalError> {
        self.qr_make(vault, Source::Draft { field })
    }

    /// Show Wi-Fi Join Code (FEA-10.4 to .6). A crossing of LD-220.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `Refused` with
    /// `MSG-QR-WIFI-INVALID`, `MSG-QR-WIFI-UNSUPPORTED`, or as
    /// [`Session::qr_show_field`].
    pub fn qr_show_wifi(&self, vault: u64, entry: String) -> Result<QrShown, LarsalError> {
        self.qr_make(vault, Source::Wifi { entry })
    }

    /// `ticket` is this vault's live request and its source has not changed
    /// (FEA-10.14). Ask before every repaint and export step. A ticket found
    /// stale is over: this never says yes for it again. No secret.
    #[must_use]
    pub fn qr_is_current(&self, vault: u64, ticket: u64) -> bool {
        self.with_qr(vault, |v, path, state| {
            Ok(state.qr_live(v, path, ticket).is_some())
        })
        .unwrap_or(false)
    }

    /// Ends `ticket`, with any consent it holds. No secret.
    pub fn qr_release(&self, vault: u64, ticket: u64) {
        let _ = self.with_qr(vault, |_, _, state| {
            if state.qr.as_ref().is_some_and(|t| t.id == ticket) {
                state.qr = None;
            }
            Ok(())
        });
    }

    /// The user confirmed the warning for `action` (FEA-10.16): a new
    /// consent for this ticket, replacing any earlier one. No secret.
    ///
    /// # Errors
    /// `Refused` with `MSG-QR-FAILED` when the ticket is no longer live.
    pub fn qr_consent(
        &self,
        vault: u64,
        ticket: u64,
        action: QrExport,
    ) -> Result<u64, LarsalError> {
        self.with_qr(vault, |v, path, state| {
            state
                .qr_live(v, path, ticket)
                .ok_or_else(|| refused(FAILED))?;
            let t = state.qr.as_mut().ok_or_else(|| refused(FAILED))?;
            let consent = next();
            t.consent = Some((consent, action));
            Ok(consent)
        })
    }

    /// Save Image… (FEA-10.17): writes the PNG to `path`, 0600, in one step,
    /// after `consent` and a last check of the ticket. The consent is spent
    /// whatever happens. A link at `path` is refused, never followed.
    ///
    /// # Errors
    /// `TooLong`; `Refused` with `MSG-QR-SAVE-FAILED`; nothing is written and
    /// a file at `path` stays as it was.
    pub fn qr_save_png(
        &self,
        vault: u64,
        ticket: u64,
        consent: u64,
        path: String,
    ) -> Result<(), LarsalError> {
        if path.len() > 4096 {
            return Err(LarsalError::TooLong);
        }
        let target = Path::new(&path);
        let bytes = self
            .qr_png(vault, ticket, consent, QrExport::Save, true)
            .ok_or_else(|| refused(SAVE_FAILED))?;
        self.qr_commit(vault, ticket, target, &bytes)
    }

    /// The in-memory PNG of Share… (FEA-10.18) for one live consent. A
    /// provider may ask more than once, so this does not spend it: ending
    /// the ticket does.
    ///
    /// # Errors
    /// `Refused` with `MSG-QR-SHARE-FAILED` when the consent or ticket is no
    /// longer live.
    pub fn qr_share_png(
        &self,
        vault: u64,
        ticket: u64,
        consent: u64,
    ) -> Result<Vec<u8>, LarsalError> {
        self.qr_png(vault, ticket, consent, QrExport::Share, false)
            .ok_or_else(|| refused(SHARE_FAILED))
    }
}

// ---------------------------------------------------------------------------
// The Wi-Fi join text (FEA-10.4 to .6): larsal-qr makes it, for the app and the
// `larsal` tool alike.

/// The join text of `e`. LD-361: enterprise Join stays unavailable.
fn join_text(e: &Entry) -> Result<SecretString, LarsalError> {
    larsal_qr::join_text(e).map_err(|r| refused(r.message()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::{EditText, qr_eci26};
    use crate::test_dir::TempDir;
    use crate::views::FieldKind;
    use larsal_model::{Field, Uuid};
    use std::sync::Arc;

    fn entry(fields: &[(&str, &str)]) -> Entry {
        let mut e = Entry::new(Uuid([0; 16]), Time(0));
        for (name, value) in fields {
            e.set_field(
                (*name).to_owned(),
                Field {
                    value: SecretString::new((*value).to_owned()),
                    protected: false,
                },
            );
        }
        e
    }

    fn join(fields: &[(&str, &str)]) -> Result<String, String> {
        match join_text(&entry(fields)) {
            Ok(text) => Ok(text.expose().to_owned()),
            Err(LarsalError::Refused(why)) => Err(why),
            Err(other) => Err(format!("{other:?}")),
        }
    }

    fn written(fields: &[(&str, &str)]) -> String {
        larsal_qr::written(&entry(fields)).unwrap()
    }

    #[test]
    fn qr_t07_personal_join_and_hidden() {
        let base = [
            ("UserName", "Demo Net"),
            ("Password", "demo-pass"),
            ("Security", "WPA2 Personal"),
        ];
        assert_eq!(
            join(&base).unwrap(),
            "WIFI:T:WPA;S:Demo Net;P:demo-pass;H:false;;"
        );
        let hidden = [base[0], base[1], base[2], ("Hidden", "true")];
        assert_eq!(
            join(&hidden).unwrap(),
            "WIFI:T:WPA;S:Demo Net;P:demo-pass;H:true;;"
        );
    }

    #[test]
    fn qr_t08_each_special_escaped_once() {
        let text = join(&[
            ("UserName", "Demo;Net"),
            ("Password", r#"a\b:c,d"e;f"#),
            ("Security", "WPA"),
        ])
        .unwrap();
        assert_eq!(
            text,
            r#"WIFI:T:WPA;S:Demo\;Net;P:a\\b\:c\,d\"e\;f;H:false;;"#
        );
    }

    #[test]
    fn qr_t09_only_even_hex_ssid_and_password_get_wrappers() {
        let net = |s: &str, p: &str| {
            join(&[("UserName", s), ("Password", p), ("Security", "WPA")]).unwrap()
        };
        assert_eq!(
            net("ABCD", "1234"),
            r#"WIFI:T:WPA;S:"ABCD";P:"1234";H:false;;"#
        );
        assert_eq!(net("ABC", "123"), "WIFI:T:WPA;S:ABC;P:123;H:false;;");
        assert_eq!(
            net(r#""AB""#, "abcd\u{e9}"),
            "WIFI:T:WPA;S:\\\"AB\\\";P:abcd\u{e9};H:false;;"
        );
        // I and A hold ABCD as it is, escaped but with no added quotes.
        let enterprise = written(&[
            ("UserName", "Corp"),
            ("Password", "demo"),
            ("Security", "WPA2-EAP"),
            ("EAP Method", "TTLS"),
            ("Phase 2 Method", "MSCHAPV2"),
            ("Identity", "ABCD"),
            ("Anonymous Identity", "ABCD"),
        ]);
        assert_eq!(
            enterprise,
            "WIFI:T:WPA2-EAP;S:Corp;P:demo;H:false;E:TTLS;I:ABCD;A:ABCD;PH2:MSCHAPV2;;"
        );
    }

    #[test]
    fn qr_t10_every_alias_wep_and_open() {
        for alias in [
            "WPA",
            "WPA Personal",
            "WPA2 Personal",
            "WPA/WPA2 Personal",
            "WPA2/WPA3 Personal",
        ] {
            let fields = [
                ("UserName", "Caf\u{e9} 5G"),
                ("Password", "p w"),
                ("Security", alias),
            ];
            assert_eq!(
                join(&fields).unwrap(),
                "WIFI:T:WPA;S:Caf\u{e9} 5G;P:p w;H:false;;"
            );
        }
        assert_eq!(
            join(&[("UserName", "n"), ("Password", "wep"), ("Security", "WEP")]).unwrap(),
            "WIFI:T:WEP;S:n;P:wep;H:false;;"
        );
        for open in ["Open", "nopass"] {
            let fields = [
                ("UserName", "n"),
                ("Password", "stale"),
                ("Security", open),
                ("Hidden", "true"),
            ];
            assert_eq!(join(&fields).unwrap(), "WIFI:T:nopass;S:n;H:true;;");
        }
    }

    #[test]
    fn qr_t11_enterprise_serializes_but_join_stays_unavailable() {
        let good = [
            ("UserName", "Corp;Net"),
            ("Password", "demo"),
            ("Security", "WPA2-EAP"),
            ("EAP Method", "TTLS"),
            ("Phase 2 Method", "MSCHAPV2"),
            ("Identity", "a:b"),
        ];
        assert_eq!(
            written(&good),
            r"WIFI:T:WPA2-EAP;S:Corp\;Net;P:demo;H:false;E:TTLS;I:a\:b;PH2:MSCHAPV2;;"
        );
        // Hidden true and false, as FEA-10.6 asks of every row.
        let mut hidden = good.to_vec();
        hidden.push(("Hidden", "true"));
        assert_eq!(
            written(&hidden),
            r"WIFI:T:WPA2-EAP;S:Corp\;Net;P:demo;H:true;E:TTLS;I:a\:b;PH2:MSCHAPV2;;"
        );
        // LD-361: no named receiver is proved, so the action refuses.
        assert_eq!(join(&good).unwrap_err(), WIFI_UNSUPPORTED);
        let drop_one = |name: &str| -> Vec<(&str, &str)> {
            good.iter().filter(|(n, _)| *n != name).copied().collect()
        };
        assert_eq!(join(&drop_one("Identity")).unwrap_err(), WIFI_INVALID);
        assert_eq!(join(&drop_one("UserName")).unwrap_err(), WIFI_INVALID);
        assert_eq!(join(&drop_one("Password")).unwrap_err(), WIFI_INVALID);
        // FEA-10.4: a required field that is missing is invalid.
        assert_eq!(join(&drop_one("EAP Method")).unwrap_err(), WIFI_INVALID);
        assert_eq!(join(&drop_one("Phase 2 Method")).unwrap_err(), WIFI_INVALID);
        // Other methods are not this profile, whatever else they lack.
        let mut peap = good.to_vec();
        peap[3] = ("EAP Method", "PEAP");
        assert_eq!(join(&peap).unwrap_err(), WIFI_UNSUPPORTED);
        peap.remove(4);
        assert_eq!(join(&peap).unwrap_err(), WIFI_UNSUPPORTED);
        let mut pap = good.to_vec();
        pap[4] = ("Phase 2 Method", "PAP");
        assert_eq!(join(&pap).unwrap_err(), WIFI_UNSUPPORTED);
        let mut bad = good.to_vec();
        bad.push(("Hidden", "yes"));
        assert_eq!(join(&bad).unwrap_err(), WIFI_INVALID);
    }

    #[test]
    fn qr_t12_invalid_and_unsupported_never_downgrade() {
        let full = |s: &str| join(&[("UserName", "n"), ("Password", "p"), ("Security", s)]);
        for unknown in [
            "WPA3 Personal",
            "OWE",
            "EAP-TLS",
            "wpa",
            "WPA2",
            " WPA",
            "wep",
        ] {
            assert_eq!(full(unknown).unwrap_err(), WIFI_UNSUPPORTED, "{unknown}");
        }
        assert_eq!(full("").unwrap_err(), WIFI_INVALID);
        assert_eq!(
            join(&[("UserName", "n"), ("Password", "p")]).unwrap_err(),
            WIFI_INVALID,
            "missing Security is invalid, not open"
        );
        assert_eq!(
            join(&[("Password", "p"), ("Security", "WPA")]).unwrap_err(),
            WIFI_INVALID
        );
        assert_eq!(
            join(&[("UserName", "n"), ("Security", "WPA")]).unwrap_err(),
            WIFI_INVALID
        );
        // FEA-10.4: the SSID is never guessed from the title.
        assert_eq!(
            join(&[("Title", "n"), ("Password", "p"), ("Security", "WPA")]).unwrap_err(),
            WIFI_INVALID
        );
        assert_eq!(
            join(&[
                ("UserName", "n"),
                ("Password", "p"),
                ("Security", "WPA"),
                ("Hidden", "TRUE")
            ])
            .unwrap_err(),
            WIFI_INVALID
        );
    }

    /// FEA-10.4: U+0000 to U+001F and U+007F in any join field, personal or
    /// enterprise; nothing outside that range, and no field a join leaves out.
    #[test]
    fn qr_t11_qr_t12_control_characters_in_every_join_field_are_invalid() {
        let personal = [
            ("UserName", "n"),
            ("Password", "p"),
            ("Security", "WPA"),
            ("Hidden", "true"),
        ];
        let enterprise = [
            ("UserName", "n"),
            ("Password", "p"),
            ("Security", "WPA2-EAP"),
            ("EAP Method", "TTLS"),
            ("Phase 2 Method", "MSCHAPV2"),
            ("Identity", "i"),
            ("Anonymous Identity", "a"),
        ];
        let with = |row: &[(&'static str, &'static str)], name: &str, value: &'static str| {
            let mut out = row.to_vec();
            out.iter_mut().find(|(n, _)| *n == name).unwrap().1 = value;
            out
        };
        for control in ["a\u{0}b", "a\tb", "a\nb", "a\r", "\u{1f}", "a\u{7f}b"] {
            for name in ["UserName", "Password", "Security", "Hidden"] {
                let got = join(&with(&personal, name, control));
                assert_eq!(got.unwrap_err(), WIFI_INVALID, "{name} {control:?}");
            }
            for name in [
                "UserName",
                "Password",
                "Security",
                "EAP Method",
                "Phase 2 Method",
                "Identity",
                "Anonymous Identity",
            ] {
                let got = join(&with(&enterprise, name, control));
                assert_eq!(got.unwrap_err(), WIFI_INVALID, "{name} {control:?}");
            }
            // An open network carries no password, so a stale one does not count.
            let open = [
                ("UserName", "n"),
                ("Password", control),
                ("Security", "Open"),
            ];
            assert_eq!(join(&open).unwrap(), "WIFI:T:nopass;S:n;H:false;;");
        }
        // U+0080 to U+009F are not in the card's range, so they stay data.
        let data = [
            ("UserName", "n\u{85}"),
            ("Password", "p\u{9f}"),
            ("Security", "WPA"),
        ];
        assert_eq!(
            join(&data).unwrap(),
            "WIFI:T:WPA;S:n\u{85};P:p\u{9f};H:false;;"
        );
    }

    /// FEA-10.6: an open network needs no password at all.
    #[test]
    fn qr_t10_an_open_network_with_no_password_joins() {
        let open = [("UserName", "n"), ("Security", "nopass")];
        assert_eq!(join(&open).unwrap(), "WIFI:T:nopass;S:n;H:false;;");
    }

    /// F-064: one buffer of the exact size, so no grown copy holds a password.
    #[test]
    fn f_064_join_text_is_made_in_one_buffer() {
        for fields in [
            vec![
                ("UserName", "Caf\u{e9};\"Net"),
                ("Password", r#"p\a;s,s:w"d-demo"#),
                ("Security", "WPA"),
                ("Hidden", "true"),
            ],
            vec![
                ("UserName", "ABCD"),
                ("Password", "1234"),
                ("Security", "WPA2-EAP"),
                ("EAP Method", "TTLS"),
                ("Phase 2 Method", "MSCHAPV2"),
                ("Identity", "i;d"),
                ("Anonymous Identity", "a"),
            ],
            vec![
                ("UserName", "n"),
                ("Password", "stale"),
                ("Security", "Open"),
            ],
        ] {
            let text = written(&fields);
            assert_eq!(text.capacity(), text.len(), "{text}");
        }
    }

    #[test]
    fn fea_10_17_png_is_black_on_white_at_eight_pixels_a_module() {
        // Not symmetric, so a shift or a flip shows.
        let symbol = Qr {
            size: 3,
            modules: vec![1, 0, 0, 0, 0, 1, 0, 1, 1],
        };
        let (edge, picture) = rgba(&symbol).unwrap();
        assert_eq!(edge, 24);
        assert_eq!(picture.len(), 24 * 24 * 4);
        for (i, pixel) in picture.as_chunks::<4>().0.iter().enumerate() {
            let (y, x) = (i / 24, i % 24);
            let dark = symbol.modules[(y / 8) * 3 + x / 8] == 1;
            let want = if dark { [0, 0, 0, 0xFF] } else { [0xFF; 4] };
            assert_eq!(*pixel, want, "pixel {x},{y}");
        }
        let bytes = png(&symbol).unwrap();
        assert_eq!(bytes, icons::encode_png(24, 24, &picture).unwrap());
        assert!(bytes.starts_with(b"\x89PNG"));
        let mut names = Vec::new();
        let mut at = 8;
        while at + 8 <= bytes.len() {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            names.push(String::from_utf8_lossy(&bytes[at + 4..at + 8]).into_owned());
            at += 12 + len;
        }
        assert_eq!(names, ["IHDR", "IDAT", "IEND"], "no metadata");
    }

    /// `text` fits by its final bytes alone; only oversize refuses.
    fn check_size(text: &str, note: &str) {
        match encode(text.as_bytes()) {
            Ok(_) => assert!(text.len() <= MAX_BYTES, "{note}"),
            Err(LarsalError::Refused(why)) => {
                assert_eq!(why, TOO_LARGE, "{note}");
                assert!(text.len() > MAX_BYTES, "{note}: {} bytes", text.len());
            }
            Err(other) => panic!("{note}: {other:?}"),
        }
    }

    #[test]
    fn qr_t31_generator_limits_stay_and_core_and_cli_maxima_refuse() {
        use larsal_core::generator::{passphrase, password, wordlist};
        assert_eq!(
            (
                password::SCREEN_MAX_LENGTH,
                password::MAX_LENGTH,
                password::MAX_TEXT
            ),
            (999, 10_000, 1_024)
        );
        assert_eq!(
            (
                passphrase::SCREEN_MAX_WORDS,
                passphrase::MAX_WORDS,
                passphrase::MAX_SEPARATOR
            ),
            (100, 1_000, 64)
        );
        assert_eq!(
            (
                wordlist::MAX_FILE,
                wordlist::MAX_ENTRIES,
                wordlist::MAX_ENTRY
            ),
            (4 * 1024 * 1024, 500_000, 256)
        );
        // Passwords: 999 and 10,000 ASCII, then 999 and 10,000 four-byte scalars.
        let ascii = |length| {
            let o = password::Options::command_line(length, &[], None, "", false, false);
            password::generate(&o).ok().unwrap()
        };
        let long = ascii(10_000);
        assert_eq!(long.expose().len(), 10_000);
        assert_eq!(
            format!("{:?}", encode(long.expose().as_bytes()).unwrap_err()),
            format!("{:?}", refused(TOO_LARGE))
        );
        assert_eq!(ascii(999).expose().len(), 999);
        check_size(ascii(999).expose(), "999 ASCII");
        let extra: String = (0x1F300..0x1F300 + 1_024_u32)
            .filter_map(char::from_u32)
            .collect();
        assert_eq!(extra.chars().count(), 1_024);
        let wide = |length, excluded: &str, classes: Vec<password::Class>| {
            let o = password::Options {
                length,
                classes,
                extra: extra.clone(),
                excluded: excluded.to_owned(),
                exclude_lookalike: false,
                every_group: false,
            };
            password::generate(&o)
        };
        for (length, bytes) in [(999, 3_996), (10_000, 40_000)] {
            let text = wide(length, "", Vec::new()).ok().unwrap();
            assert_eq!(text.expose().len(), bytes);
            assert!(encode(text.expose().as_bytes()).is_err());
        }
        // The 1,024-scalar excluded limit, used to the full: only lower is left.
        let text = wide(999, &extra, vec![password::Class::Lower])
            .ok()
            .unwrap();
        assert_eq!(text.expose().len(), 999);
        check_size(text.expose(), "excluded all extra");
        // One over the limit stays refused by the generator's own check.
        let over = password::Options {
            extra: format!("{extra}\u{1F7FF}"),
            ..password::Options::command_line(10, &[], None, "", false, false)
        };
        assert!(password::generate(&over).is_err());
        // Built-in phrases: the nine-byte words, 100 and 1,000 of them.
        let nine: Vec<u8> = wordlist::builtin()
            .words()
            .filter(|w| w.len() == 9)
            .flat_map(|w| format!("{w}\n").into_bytes())
            .collect();
        let list = wordlist::parse(&nine).ok().unwrap();
        let phrase = |o: &passphrase::Options, list: &wordlist::WordList| {
            passphrase::generate(o, list).ok().unwrap()
        };
        let ui = phrase(&passphrase::Options::command_line(100), &list);
        assert_eq!(ui.expose().len(), 999);
        check_size(ui.expose(), "999-byte phrase");
        let core = phrase(&passphrase::Options::command_line(1_000), &list);
        assert_eq!(core.expose().len(), 9_999);
        check_size(core.expose(), "9,999-byte phrase");
        check_size(
            phrase(
                &passphrase::Options::command_line(1_000),
                wordlist::builtin(),
            )
            .expose(),
            "CLI phrase",
        );
        // The longest separators, ASCII and four-byte, UI and core.
        for (words, separator, alone) in [
            (100, "-".repeat(64), 6_336),
            (1_000, "-".repeat(64), 63_936),
            (100, "\u{1F600}".repeat(64), 25_344),
            (1_000, "\u{1F600}".repeat(64), 255_744),
        ] {
            let o = passphrase::Options {
                words,
                separator,
                case: passphrase::Case::Lower,
            };
            let text = phrase(&o, wordlist::builtin());
            assert!(text.expose().len() > alone);
            check_size(text.expose(), "separator");
            assert!(encode(text.expose().as_bytes()).is_err());
        }
        // Custom lists: 256-scalar words and case expansion, in every mode.
        for word in [
            "w".repeat(256),
            "\u{390}".repeat(256),
            "\u{130}".repeat(256),
            "\u{390}".into(),
            "\u{130}".into(),
        ] {
            let list = wordlist::parse(word.as_bytes()).ok().unwrap();
            for case in [
                passphrase::Case::Lower,
                passphrase::Case::Upper,
                passphrase::Case::Title,
                passphrase::Case::Mixed,
            ] {
                for words in [1, 4, 5, 100, 1_000] {
                    let o = passphrase::Options {
                        words,
                        separator: " ".to_owned(),
                        case,
                    };
                    check_size(phrase(&o, &list).expose(), "custom list");
                }
            }
        }
    }

    #[test]
    fn fea_10_9_size_is_decided_before_the_encoder() {
        assert_eq!(
            format!("{:?}", encode(&[]).unwrap_err()),
            format!("{:?}", refused(EMPTY))
        );
        assert_eq!(
            format!("{:?}", encode(&[b'a'; MAX_BYTES + 1]).unwrap_err()),
            format!("{:?}", refused(TOO_LARGE))
        );
        let full = encode(&[b'a'; MAX_BYTES]).unwrap();
        assert_eq!(full.size, 185);
    }

    /// A copy of the demo vault, unlocked, and its entry `Wise`.
    fn demo(tag: &str) -> (TempDir, Arc<Session>, u64, String) {
        let dir = TempDir::new(&format!("qr-{tag}"));
        let path = dir.join("Demo.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let wise = s
            .list(v, crate::views::ListView::All)
            .unwrap()
            .rows
            .into_iter()
            .find(|r| r.title == "Wise")
            .unwrap()
            .id;
        (dir, s, v, wise)
    }

    /// Makes the live ticket stale with no door seeing it.
    fn stale(s: &Session, v: u64) {
        s.with_qr(v, |_, _, state| {
            state.qr.as_mut().unwrap().revision.clear();
            Ok(())
        })
        .unwrap();
    }

    fn held(s: &Session, v: u64) -> bool {
        s.with_qr(v, |_, _, state| Ok(state.qr.is_some())).unwrap()
    }

    #[test]
    fn qr_t29_a_late_older_request_never_goes_live() {
        let (_dir, s, v, wise) = demo("late");
        let source = || Source::Saved {
            entry: wise.clone(),
            field: "Password".into(),
        };
        // An older request is still encoding when a newer one ends.
        let older = next();
        let at = now();
        let (_, revision) = s
            .with_qr(v, |vault, path, state| {
                read(vault, path, state, &source(), at)
            })
            .unwrap();
        let newer = s.qr_show_field(v, wise.clone(), "Password".into()).unwrap();
        assert!(newer.ticket > older);
        assert!(s.qr_hold(v, older, source(), at, revision.clone()).is_err());
        assert!(!s.qr_is_current(v, older), "the late answer stays dead");
        assert!(s.qr_is_current(v, newer.ticket), "the newer one stays");
        // The same when a lock came between: nothing is held after it.
        let waiting = next();
        s.lock(v).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        assert!(s.qr_hold(v, waiting, source(), at, revision).is_err());
        assert!(!s.qr_is_current(v, waiting));
    }

    /// FEA-10.14: the source revision moves with each part of the entry and
    /// with the resolved text, which is how a reference's target reaches it.
    #[test]
    fn qr_t18_the_revision_moves_with_each_part() {
        // Id and time set: only the part named below differs.
        let fixed = |fields: &[(&str, &str)]| {
            let mut e = entry(fields);
            e.uuid = Uuid([2; 16]);
            e.times.last_modification = Time(2);
            e
        };
        // Where it sits: the groups' ids, the root first.
        let place = |groups: &[[u8; 16]]| groups.concat();
        let revision = |e: &Entry, payload: &[u8]| made(e, &place(&[[0; 16], [3; 16]]), payload).1;
        let base = fixed(&[("Password", "p")]);
        let start = revision(&base, b"p");
        assert_eq!(start, revision(&base, b"p"), "a read moves nothing");
        assert_eq!(
            start,
            revision(&fixed(&[("Password", "p")]), b"p"),
            "the same entry"
        );
        assert_ne!(start, revision(&base, b"q"), "the resolved text");
        let mut other = fixed(&[("Password", "p")]);
        other.uuid = Uuid([1; 16]);
        assert_ne!(start, revision(&other, b"p"), "the entry");
        let at = |groups: &[[u8; 16]]| made(&base, &place(groups), b"p").1;
        assert_ne!(start, at(&[[0; 16], [1; 16]]), "the group that holds it");
        assert_ne!(start, at(&[[1; 16], [3; 16]]), "a group above it");
        assert_ne!(
            start,
            at(&[[0; 16], [4; 16], [3; 16]]),
            "a group put between"
        );
        let mut other = fixed(&[("Password", "p")]);
        other.times.last_modification = Time(1);
        assert_ne!(start, revision(&other, b"p"), "the last change");
        assert_ne!(
            start,
            revision(&fixed(&[("Password", "q")]), b"p"),
            "a field's value"
        );
        // One custom field each, the same value, other names, in the same place in the order.
        assert_ne!(
            revision(&fixed(&[("Code A", "1")]), b"p"),
            revision(&fixed(&[("Code B", "1")]), b"p"),
            "a field's name"
        );
        let mut other = fixed(&[("Password", "p")]);
        other.set_field(
            "Password".to_owned(),
            Field {
                value: SecretString::new("p".to_owned()),
                protected: true,
            },
        );
        assert_ne!(start, revision(&other, b"p"), "a field's protection");
    }

    /// FEA-10.1, .2: a protected title has no place in the head, so the detail
    /// offers it as a field, with no value in the record.
    #[test]
    fn qr_t01_a_protected_title_is_offered_as_a_field_with_no_value() {
        let (_dir, s, v, wise) = demo("title");
        let title = |s: &Session| {
            let detail = s.entry(v, wise.clone()).unwrap();
            let row = detail.fields.into_iter().find(|f| f.name == "Title");
            (detail.title, row)
        };
        assert_eq!(title(&s), ("Wise".to_owned(), None), "plain: the head only");
        s.with_edit(v, |vault, _, _, _| {
            vault.meta.memory_protection.title = true;
            Ok(())
        })
        .unwrap();
        let (head, row) = title(&s);
        let row = row.unwrap();
        assert_eq!(head, "");
        assert_eq!(row.kind, FieldKind::Title);
        assert!(row.protected && row.value.is_empty());
        let shown = s.qr_show_field(v, wise.clone(), "Title".into()).unwrap();
        assert_eq!(
            shown.symbol,
            qr_eci26(b"Wise").unwrap(),
            "exactly the title"
        );
        s.begin_edit(v, wise.clone()).unwrap();
        s.set_text(v, EditText::Title, String::new()).unwrap();
        s.commit_edit(v).unwrap();
        assert_eq!(title(&s), (String::new(), None), "an empty one has no row");
    }

    /// Both documented length guards: refused as too long, by name and by path.
    #[test]
    fn qr_t02_a_draft_name_and_a_save_path_over_their_limits_are_too_long() {
        let (_dir, s, v, wise) = demo("long");
        s.begin_edit(v, wise.clone()).unwrap();
        let name = "n".repeat(MAX_TEXT + 1);
        assert!(matches!(
            s.qr_show_draft(v, name),
            Err(LarsalError::TooLong)
        ));
        s.cancel_edit(v).unwrap();
        let live = s.qr_show_field(v, wise, "Password".into()).unwrap();
        let consent = s.qr_consent(v, live.ticket, QrExport::Save).unwrap();
        let path = "/".repeat(4097);
        assert!(matches!(
            s.qr_save_png(v, live.ticket, consent, path),
            Err(LarsalError::TooLong)
        ));
    }

    /// C2-1: found stale once, gone, whatever the source reads next.
    #[test]
    fn qr_t18_a_ticket_found_stale_is_dropped_for_good() {
        let (_dir, s, v, wise) = demo("sticky");
        let live = s.qr_show_field(v, wise, "Password".into()).unwrap();
        assert!(s.qr_is_current(v, live.ticket));
        stale(&s, v);
        assert!(!s.qr_is_current(v, live.ticket));
        assert!(!held(&s, v), "nothing left to come back");
    }

    #[test]
    fn qr_t18_a_stale_ticket_takes_no_consent_and_gives_no_image() {
        let (_dir, s, v, wise) = demo("stale-consent");
        let live = s.qr_show_field(v, wise.clone(), "Password".into()).unwrap();
        stale(&s, v);
        assert!(s.qr_consent(v, live.ticket, QrExport::Share).is_err());
        let live = s.qr_show_field(v, wise, "Password".into()).unwrap();
        let consent = s.qr_consent(v, live.ticket, QrExport::Share).unwrap();
        assert!(s.qr_share_png(v, live.ticket, consent).is_ok());
        stale(&s, v);
        assert!(s.qr_share_png(v, live.ticket, consent).is_err());
    }

    /// QR-T20's race: the source moves after the image is made and before the
    /// commit. Nothing is written; a live ticket writes.
    #[test]
    fn qr_t20_the_last_check_before_the_commit_refuses_a_stale_ticket() {
        let (dir, s, v, wise) = demo("commit");
        let target = dir.join("late.png");
        let live = s.qr_show_field(v, wise.clone(), "Password".into()).unwrap();
        stale(&s, v);
        assert!(s.qr_commit(v, live.ticket, &target, b"demo").is_err());
        assert!(!target.exists());
        let live = s.qr_show_field(v, wise, "Password".into()).unwrap();
        s.qr_commit(v, live.ticket, &target, b"demo").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"demo");
    }

    /// The door a share import and a server merge change the vault through:
    /// the ticket ends when the change lands, not at the next look.
    #[test]
    fn qr_t18_the_share_door_ends_a_ticket_when_the_source_moves() {
        let (_dir, s, v, wise) = demo("share-door");
        let live = s.qr_show_field(v, wise.clone(), "Password".into()).unwrap();
        let id = crate::views::parse_id(&wise, LarsalError::UnknownEntry).unwrap();
        fn entry_in(group: &mut larsal_model::Group, id: Uuid) -> Option<&mut Entry> {
            if let Some(i) = group.entries.iter().position(|e| e.uuid == id) {
                return group.entries.get_mut(i);
            }
            group.groups.iter_mut().find_map(|g| entry_in(g, id))
        }
        s.with_share(v, |slot| {
            let _ = slot.vault.as_deref();
        })
        .unwrap();
        assert!(held(&s, v), "a look leaves it");
        let before = s.show_field(v, wise.clone(), "Password".into()).unwrap();
        let set = |value: &str| {
            s.with_share(v, |slot| {
                let vault = slot.vault.unwrap();
                let e = entry_in(&mut vault.root, id).unwrap();
                e.set_field(
                    "Password".to_owned(),
                    Field {
                        value: SecretString::new(value.to_owned()),
                        protected: true,
                    },
                );
            })
            .unwrap();
        };
        set("demo-moved");
        assert!(!held(&s, v), "gone with the change");
        set(&before);
        assert!(!s.qr_is_current(v, live.ticket), "not back with the undo");
    }

    /// R3C2-1, C1R3-2, FEA-10.14: a move of a group above the entry, the one
    /// that holds it or one further up, to the Recycle Bin or into another
    /// group, ends a saved field's and a join's ticket and its consent; the move
    /// back brings nothing back, and another group's move leaves it. No session
    /// call moves or deletes a group, so larsal-core's own moves run through the
    /// session's change door `with_edit`, the way a merge, a sync or a reload
    /// changes the vault.
    #[test]
    fn qr_t18_a_move_of_any_group_above_the_entry_ends_the_ticket() {
        use larsal_core::edit::{Position, move_group};
        use larsal_core::recycle::{delete_group, restore_group};
        let (_dir, s, v, _) = demo("group-move");
        let id = |text: &str| parse_id(text, LarsalError::UnknownGroup).unwrap();
        let group = |parent: Option<&str>, name: &str| {
            s.add_group(v, parent.map(str::to_owned), name.into(), 0, None)
                .unwrap()
        };
        let elsewhere = id(&group(None, "Elsewhere"));
        // 0: the holding group to the bin; 1: the group above it to the bin;
        // 2: the group above it into another group.
        for (step, join) in [
            (0, false),
            (0, true),
            (1, false),
            (1, true),
            (2, false),
            (2, true),
        ] {
            let above = group(None, "Above");
            let holder = group(Some(&above), "Holder");
            s.begin_new(v, Some(holder.clone())).unwrap();
            s.set_text(v, EditText::UserName, "demo-net".into())
                .unwrap();
            s.set_password(v, "demo-pass-m".into()).unwrap();
            let made = s.add_field(v).unwrap();
            s.rename_field(v, made, "Security".into()).unwrap();
            s.set_field(v, "Security".into(), "WPA".into()).unwrap();
            let entry = s.commit_edit(v).unwrap();
            let (above, holder, other) = (id(&above), id(&holder), id(&group(None, "Other")));
            let live = if join {
                s.qr_show_wifi(v, entry.clone())
            } else {
                s.qr_show_field(v, entry.clone(), "Password".into())
            }
            .unwrap();
            let consent = s.qr_consent(v, live.ticket, QrExport::Share).unwrap();
            let change = |back: bool| {
                s.with_edit(v, |vault, _, _, _| {
                    let root = vault.root.uuid;
                    let (group, at) = (if step == 0 { holder } else { above }, now());
                    match (step, back) {
                        (2, false) => {
                            move_group(vault, group, elsewhere, Position::End, at).map(drop)
                        }
                        (2, true) => move_group(vault, group, root, Position::End, at).map(drop),
                        (_, false) => delete_group(vault, group, at).map(drop),
                        (_, true) => restore_group(vault, group, at).map(drop),
                    }
                    .unwrap();
                    Ok(())
                })
                .unwrap();
            };
            s.with_edit(v, |vault, _, _, _| {
                delete_group(vault, other, now()).unwrap();
                Ok(())
            })
            .unwrap();
            assert!(
                s.qr_is_current(v, live.ticket),
                "{step} {join}: another group's move"
            );
            assert!(s.qr_share_png(v, live.ticket, consent).is_ok());
            change(false);
            assert!(
                !s.qr_is_current(v, live.ticket),
                "{step} {join}: the move ends it"
            );
            assert!(
                s.qr_share_png(v, live.ticket, consent).is_err(),
                "and its consent"
            );
            assert!(s.qr_consent(v, live.ticket, QrExport::Share).is_err());
            change(true);
            assert!(
                !s.qr_is_current(v, live.ticket),
                "{step} {join}: not back with the move back"
            );
        }
    }

    /// QR-T18's sync: a server copy that changed the entry, merged in.
    #[cfg(feature = "sync")]
    #[test]
    fn qr_t18_a_server_copy_merged_in_ends_the_ticket() {
        let (dir, s, v, wise) = demo("sync");
        s.confirm_format_notice(v).unwrap();
        s.save(v).unwrap();
        let copy = dir.join("Server copy.larsalvault");
        std::fs::copy(dir.join("Demo.larsalvault"), &copy).unwrap();
        let other = Session::new();
        let w = other.open(copy.to_string_lossy().into_owned()).unwrap();
        other.unlock(w, Some("demo-pass-7".into()), None).unwrap();
        other.confirm_format_notice(w).unwrap();
        other.begin_edit(w, wise.clone()).unwrap();
        other.set_password(w, "server-demo".into()).unwrap();
        other.commit_edit(w).unwrap();
        other.save(w).unwrap();
        let bytes = std::fs::read(&copy).unwrap();
        let live = s.qr_show_field(v, wise.clone(), "Password".into()).unwrap();
        assert!(s.qr_is_current(v, live.ticket));
        assert!(matches!(
            s.merge_server(v, &bytes),
            larsal_sync::sync::Merge::Done { .. }
        ));
        assert_eq!(
            s.show_field(v, wise, "Password".into()).unwrap(),
            "server-demo"
        );
        assert!(!held(&s, v), "gone with the merge");
        assert!(!s.qr_is_current(v, live.ticket));
    }
}
