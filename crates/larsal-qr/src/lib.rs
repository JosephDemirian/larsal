//! Show as QR Code's encoder (FEA-10.4 to .10, LD-198, LD-359, LD-361), one
//! path for the Mac app's core (larsal-ffi) and the `larsal` tool
//! (larsal-cli): the module matrix of the pinned `qrcode` crate, and the Wi-Fi
//! join text. The only crate that imports `qrcode`.
//!
//! Guarantees: error correction H, the smallest normal version 1 to 40 that
//! fits, an optional ECI designator before one byte segment, a quiet zone of 4
//! modules; never a lower level, a truncation or a second segment. No file,
//! network, process or environment access.
//!
//! Wiping (Rust rule 3, LD-198): the matrix and the join text it hands out are
//! a [`SecretBytes`] and a [`SecretString`], wiped on drop. The copies `qrcode`
//! makes inside one call (the bits, the codewords, its module grid and colours)
//! are freed unwiped by `qrcode`, so they are wiped only by a zeroing global
//! allocator (LD-193). Programs that install one: the `larsal` tool and
//! larsal-cli's unit test program (`Zeroing` in larsal-cli `main.rs`), and the
//! larsal-ffi library, with every program that links it: the Mac app and each
//! of larsal-ffi's test programs. The one program that links this crate without
//! one: larsal-cli's `int10` test program, which encodes demo values only.
#![forbid(unsafe_code)]

use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::Entry;

/// FEA-10.9: version 40 at level H less the ECI, mode and count headers.
pub const MAX_BYTES: usize = 1_272;

/// Why no code was made. [`Refusal::message`] gives the card's words, which
/// never hold a value (AT-E03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `MSG-QR-EMPTY`.
    Empty,
    /// `MSG-QR-TOO-LARGE`.
    TooLarge,
    /// `MSG-QR-FAILED`.
    Failed,
    /// `MSG-QR-WIFI-INVALID`.
    WifiInvalid,
    /// `MSG-QR-WIFI-UNSUPPORTED`.
    WifiUnsupported,
}

impl Refusal {
    /// The card's text for this refusal.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Empty => "This field is empty.",
            Self::TooLarge => {
                "This value is too large for one QR code. Nothing was shown, saved or shared."
            }
            Self::Failed => "The QR code could not be made.",
            Self::WifiInvalid => "This Wi-Fi entry is incomplete or has invalid settings.",
            Self::WifiUnsupported => {
                "This network type cannot be shared as a Wi-Fi join code. Show an individual field as text instead."
            }
        }
    }
}

/// A QR symbol: `size` modules a side, the 4-module quiet zone included, row
/// by row; 1 is dark. A picture of the secret: wiped on drop, no `Debug`, no
/// `Clone`.
pub struct Matrix {
    size: usize,
    modules: SecretBytes,
}

impl Matrix {
    /// Modules per side.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// `size × size` values, 0 or 1. Do not copy them into a type that is not
    /// wiped on drop.
    #[must_use]
    pub fn modules(&self) -> &[u8] {
        self.modules.expose()
    }
}

/// The QR symbol of `text`: error correction H, byte mode, the smallest
/// version that fits, a quiet zone of 4 modules, and with `eci` one ECI
/// designator before the byte segment. `None` when no version holds it.
#[must_use]
pub fn symbol(text: &[u8], eci: Option<u32>) -> Option<Matrix> {
    use qrcode::bits::Bits;
    use qrcode::{Color, EcLevel, QrCode, Version};
    let code = (1..=40).find_map(|v| {
        let mut bits = Bits::new(Version::Normal(v));
        if let Some(designator) = eci {
            bits.push_eci_designator(designator).ok()?;
        }
        bits.push_byte_data(text).ok()?;
        bits.push_terminator(EcLevel::H).ok()?;
        QrCode::with_bits(bits, EcLevel::H).ok()
    })?;
    let width = code.width();
    let size = width.saturating_add(8);
    let colors = code.to_colors();
    let mut modules = SecretBytes::zeroed(size.saturating_mul(size));
    for (i, c) in colors.iter().enumerate() {
        if *c == Color::Dark {
            let (y, x) = (i / width, i % width);
            if let Some(m) = modules
                .expose_mut()
                .get_mut((y.saturating_add(4)) * size + x.saturating_add(4))
            {
                *m = 1;
            }
        }
    }
    Some(Matrix { size, modules })
}

/// Show as QR Code's symbol of the final bytes (FEA-10.8, .9): the size is
/// decided on them, before the encoder; then ECI 26 (UTF-8) and one byte
/// segment.
///
/// # Errors
/// [`Refusal::Empty`], [`Refusal::TooLarge`] past [`MAX_BYTES`], or
/// [`Refusal::Failed`].
pub fn encode(payload: &[u8]) -> Result<Matrix, Refusal> {
    if payload.is_empty() {
        return Err(Refusal::Empty);
    }
    if payload.len() > MAX_BYTES {
        return Err(Refusal::TooLarge);
    }
    symbol(payload, Some(26)).ok_or(Refusal::Failed)
}

// ---------------------------------------------------------------------------
// The Wi-Fi join text (FEA-10.4 to .6).

/// The stored settings of a join, read literally.
struct Wire<'a> {
    kind: &'a str,
    ssid: &'a str,
    /// `None` for an open network, even with a stale password.
    password: Option<&'a str>,
    hidden: bool,
    enterprise: Option<Enterprise<'a>>,
}

/// LD-361: the selected enterprise serialization.
struct Enterprise<'a> {
    eap: &'a str,
    identity: &'a str,
    anonymous: Option<&'a str>,
    phase2: &'a str,
}

/// FEA-10.6's table, from exact stored values: [`Refusal::WifiInvalid`] or
/// [`Refusal::WifiUnsupported`] when they cannot be a join.
fn wire(e: &Entry) -> Result<Wire<'_>, Refusal> {
    let invalid = || Refusal::WifiInvalid;
    let filled = |name: &'static str| e.field(name).map(|f| f.value.expose()).unwrap_or_default();
    let control = |text: &str| text.chars().any(|c| c.is_ascii_control());
    let hidden = match e.field("Hidden").map(|f| f.value.expose()) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(invalid()),
    };
    let (ssid, security, password) = (
        e.value("UserName"),
        e.value("Security"),
        e.value("Password"),
    );
    if security.is_empty() || ssid.is_empty() || control(security) {
        return Err(invalid());
    }
    let kind = match security {
        "WPA" | "WPA Personal" | "WPA2 Personal" | "WPA/WPA2 Personal" | "WPA2/WPA3 Personal" => {
            "WPA"
        }
        "WEP" => "WEP",
        "Open" | "nopass" => "nopass",
        "WPA2-EAP" => "WPA2-EAP",
        _ => return Err(Refusal::WifiUnsupported),
    };
    let enterprise = if kind == "WPA2-EAP" {
        // Missing fields are INVALID (FEA-10.4). Other profiles stay open work,
        // never arbitrary E/PH2: a method that is not the selected one decides
        // before what that method would need (FEA-10.6).
        for (name, selected) in [("EAP Method", "TTLS"), ("Phase 2 Method", "MSCHAPV2")] {
            let method = filled(name);
            if method.is_empty() || control(method) {
                return Err(invalid());
            }
            if method != selected {
                return Err(Refusal::WifiUnsupported);
            }
        }
        if filled("Identity").is_empty() {
            return Err(invalid());
        }
        Some(Enterprise {
            eap: "TTLS",
            identity: filled("Identity"),
            anonymous: Some(filled("Anonymous Identity")).filter(|a| !a.is_empty()),
            phase2: "MSCHAPV2",
        })
    } else {
        None
    };
    let open = kind == "nopass";
    if !open && password.is_empty() {
        return Err(invalid());
    }
    let out = Wire {
        kind,
        ssid,
        password: (!open).then_some(password),
        hidden,
        enterprise,
    };
    if out.strings().any(control) {
        return Err(invalid());
    }
    Ok(out)
}

impl Wire<'_> {
    /// The stored strings the join carries.
    fn strings(&self) -> impl Iterator<Item = &str> {
        let enterprise = self.enterprise.as_ref();
        [
            Some(self.ssid),
            self.password,
            enterprise.map(|x| x.identity),
            enterprise.and_then(|x| x.anonymous),
        ]
        .into_iter()
        .flatten()
    }
}

fn special(c: char) -> bool {
    matches!(c, '\\' | ';' | ',' | ':' | '"')
}

/// FEA-10.5: S and P only, nonempty even-length ASCII hex.
fn hex_looking(text: &str) -> bool {
    !text.is_empty() && text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `‹key›‹value›;` with each special character escaped once.
fn push(out: &mut String, key: &str, value: &str, wrap: bool) {
    let quoted = wrap && hex_looking(value);
    out.push_str(key);
    if quoted {
        out.push('"');
    }
    for c in value.chars() {
        if special(c) {
            out.push('\\');
        }
        out.push(c);
    }
    if quoted {
        out.push('"');
    }
    out.push(';');
}

/// The room [`push`] takes.
fn room(key: &str, value: &str, wrap: bool) -> usize {
    let quotes = if wrap && hex_looking(value) { 2 } else { 0 };
    key.len() + value.len() + value.matches(special).count() + quotes + 1
}

/// FEA-10.5's stable order, in one buffer of the exact size, so no part of
/// the password is left in a grown one (F-064, Rust rule 3).
fn join_buffer(w: &Wire<'_>) -> String {
    let hidden = if w.hidden { "true" } else { "false" };
    let mut size = "WIFI:;".len()
        + room("T:", w.kind, false)
        + room("S:", w.ssid, true)
        + room("H:", hidden, false);
    size += w.password.map_or(0, |p| room("P:", p, true));
    if let Some(x) = &w.enterprise {
        size += room("E:", x.eap, false)
            + room("I:", x.identity, false)
            + room("PH2:", x.phase2, false);
        size += x.anonymous.map_or(0, |a| room("A:", a, false));
    }
    let mut out = String::with_capacity(size);
    out.push_str("WIFI:");
    push(&mut out, "T:", w.kind, false);
    push(&mut out, "S:", w.ssid, true);
    if let Some(p) = w.password {
        push(&mut out, "P:", p, true);
    }
    push(&mut out, "H:", hidden, false);
    if let Some(x) = &w.enterprise {
        push(&mut out, "E:", x.eap, false);
        push(&mut out, "I:", x.identity, false);
        if let Some(a) = x.anonymous {
            push(&mut out, "A:", a, false);
        }
        push(&mut out, "PH2:", x.phase2, false);
    }
    out.push(';');
    out
}

/// The join text of `e`. LD-361: enterprise Join stays unavailable until a
/// named receiver proves the association and its trust; its text exists only
/// for that later proof.
///
/// # Errors
/// [`Refusal::WifiInvalid`] or [`Refusal::WifiUnsupported`].
pub fn join_text(e: &Entry) -> Result<SecretString, Refusal> {
    let w = wire(e)?;
    if w.enterprise.is_some() {
        return Err(Refusal::WifiUnsupported);
    }
    Ok(SecretString::new(join_buffer(&w)))
}

/// Tests only (`test-join`, never in a product build): the join text of `e`
/// as it is written, enterprise included, in its own `String`, so larsal-ffi's
/// join tests can read a text [`join_text`] withholds (QR-T11) and its
/// buffer's capacity (F-064).
#[cfg(feature = "test-join")]
#[must_use]
pub fn written(e: &Entry) -> Option<String> {
    wire(e).ok().map(|w| join_buffer(&w))
}
