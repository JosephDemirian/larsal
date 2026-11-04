//! Growable buffers for values that may be secret: resolved field values,
//! URL parts, conversion results (MOD-08 security notes).
//!
//! Guarantees: the bytes live only in `SecretBytes`; growing allocates the
//! bigger buffer, copies and drops the old one, which wipes it, so no
//! unwiped copy is left behind (SR-07, AT-C02). [`Text`] takes only `&str`
//! and `char`, so its bytes are always UTF-8.

use app_crypto::secret::{SecretBytes, SecretString};

/// The shared buffer: `buf[..len]` holds the bytes.
struct Buf {
    buf: SecretBytes,
    len: usize,
}

impl Buf {
    fn new() -> Self {
        Self {
            buf: SecretBytes::new(Vec::new()),
            len: 0,
        }
    }

    /// Makes room for `more` bytes: at least doubles, never less than 64.
    fn reserve(&mut self, more: usize) {
        let need = self.len.saturating_add(more);
        if need <= self.buf.len() {
            return;
        }
        let cap = self.buf.len().saturating_mul(2).max(need).max(64);
        let mut next = SecretBytes::zeroed(cap);
        if let (Some(d), Some(s)) = (
            next.expose_mut().get_mut(..self.len),
            self.buf.expose().get(..self.len),
        ) {
            d.copy_from_slice(s);
        }
        self.buf = next; // the old buffer is wiped as it drops
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        let end = self.len.saturating_add(bytes.len());
        if let Some(d) = self.buf.expose_mut().get_mut(self.len..end) {
            d.copy_from_slice(bytes);
            self.len = end;
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.buf.expose().get(..self.len).unwrap_or(&[])
    }
}

/// A wiping UTF-8 text buffer that counts its characters.
pub(crate) struct Text {
    buf: Buf,
    chars: usize,
}

impl Text {
    pub(crate) fn new() -> Self {
        Self {
            buf: Buf::new(),
            chars: 0,
        }
    }

    pub(crate) fn from(s: &str) -> Self {
        let mut t = Self::new();
        t.push_str(s);
        t
    }

    pub(crate) fn push_str(&mut self, s: &str) {
        self.buf.extend(s.as_bytes());
        self.chars = self.chars.saturating_add(char_count(s));
    }

    pub(crate) fn push(&mut self, c: char) {
        self.push_str(c.encode_utf8(&mut [0; 4]));
    }

    pub(crate) fn as_str(&self) -> &str {
        // Only whole `&str` and `char` values are ever pushed.
        core::str::from_utf8(self.buf.as_slice()).unwrap_or("")
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.len == 0
    }

    /// The number of characters (code points).
    pub(crate) fn chars(&self) -> usize {
        self.chars
    }

    /// The bytes as `SecretBytes`, in one allocation of the exact size;
    /// this buffer is wiped when it drops.
    pub(crate) fn into_secret_bytes(self) -> SecretBytes {
        SecretBytes::new(self.buf.as_slice().to_vec())
    }

    /// The text as a `SecretString`, built in one allocation of the exact
    /// size; this buffer is wiped when it drops.
    pub(crate) fn into_secret(self) -> SecretString {
        let mut s = String::with_capacity(self.len());
        s.push_str(self.as_str());
        SecretString::new(s)
    }
}

/// `write!` into the wiping buffer: numbers are formatted on the stack and
/// copied in, never into a plain `String` first.
impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

/// A wiping byte buffer, for bytes that become text later.
pub(crate) struct Bytes(Buf);

impl Bytes {
    pub(crate) fn new() -> Self {
        Self(Buf::new())
    }

    pub(crate) fn extend(&mut self, bytes: &[u8]) {
        self.0.extend(bytes);
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Shortens to `len` bytes (no change when already shorter); the bytes
    /// past it stay in the wiping buffer until it drops.
    pub(crate) fn truncate(&mut self, len: usize) {
        self.0.len = self.0.len.min(len);
    }

    /// The bytes as UTF-8 text, each bad sequence as U+FFFD.
    pub(crate) fn utf8_lossy_into(&self, out: &mut Text) {
        for chunk in self.0.as_slice().utf8_chunks() {
            out.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                out.push('\u{FFFD}');
            }
        }
    }
}

/// The number of characters (code points) of `s`, without decoding.
pub(crate) fn char_count(s: &str) -> usize {
    s.bytes().filter(|b| b & 0xC0 != 0x80).count()
}
