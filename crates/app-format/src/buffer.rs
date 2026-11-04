//! A growable secret byte buffer for text read piece by piece (key file
//! texts, document values).
//!
//! Guarantees: the bytes live only in [`SecretBytes`]; growing allocates the
//! bigger buffer, copies, and drops the old one, which wipes it, so no
//! unwiped copy is ever left behind (Rust rule 3; F-036, LD-85).

use app_crypto::secret::SecretBytes;

/// The buffer: `buf[..len]` holds the bytes.
pub(crate) struct Grow {
    buf: SecretBytes,
    pub(crate) len: usize,
}

impl Grow {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn push(&mut self, b: u8) {
        self.extend(&[b]);
    }

    pub(crate) fn extend(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        let end = self.len.saturating_add(bytes.len());
        if let Some(d) = self.buf.expose_mut().get_mut(self.len..end) {
            d.copy_from_slice(bytes);
            self.len = end;
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.expose().get(..self.len).unwrap_or(&[])
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Drops the first `n` bytes, moving the rest down in place.
    pub(crate) fn drain_front(&mut self, n: usize) {
        let n = n.min(self.len);
        let len = self.len;
        self.buf.expose_mut().copy_within(n..len, 0);
        self.len = len.saturating_sub(n);
    }
}
