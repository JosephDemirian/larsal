//! Payload ciphers, one-shot and streaming (story E2-S4, spec CRY-01):
//! AES-256-CBC and Twofish-256-CBC with PKCS#7 padding, and ChaCha20.
//!
//! Guarantees:
//! - The key is 32 bytes; the IV is 16 bytes for the CBC ciphers and 12 bytes
//!   for ChaCha20 (CRY-01.8, CRY-01.9). Any other length is refused with
//!   [`Error::KeyLength`] or [`Error::IvLength`] before any work.
//! - Every decrypt failure (empty input, a length that is not a whole number
//!   of blocks, bad padding, the keystream limit) is the one value
//!   [`Error::Decrypt`], with no detail (spec/decisions.md LD-04, CRY-01.11).
//!   The padding check is constant time in the decrypted bytes (AT-B07).
//! - ChaCha20 is the RFC 8439 block function with a 96-bit nonce and a 32-bit
//!   block counter that starts at 0, not 1 (CRY-01.6). It stops before the
//!   counter would wrap (CRY-01.13): block 2^32 - 1 is never used, so one key
//!   and nonce cover 2^32 - 1 blocks (just under 256 GiB).
//! - Streaming in chunks of any size gives the same bytes as one call
//!   (CRY-01.7). Each call holds back at most one block, so memory stays flat
//!   however large the payload is (CRY-01.12).
//! - Key schedules, cipher state and held-back plaintext are wiped on drop
//!   (the crates' `zeroize` features and [`Zeroizing`]). They live on the
//!   heap, so moving an [`Encryptor`] or [`Decryptor`] copies only pointers,
//!   and after every public call a fixed 32 KiB of stack below it is zeroed
//!   (best effort; see `secret::scrubbed`). Decrypted
//!   bytes are returned only inside [`SecretBytes`].
//!
//! Not done here: integrity. A CBC decrypt with a wrong key fails the padding
//! check most of the time, but not always, and ChaCha20 never notices. The
//! caller checks the header HMAC and the block HMACs (or the version 3 start
//! bytes and hashed blocks) before it decrypts (FMT-05, FMT-06, FMT-08.11).

use crate::error::Error;
use crate::secret::{SecretBytes, scrubbed};
use cbc::cipher::array::Array;
use cbc::cipher::consts::U16;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use subtle::{ConstantTimeEq, ConstantTimeGreater};
use zeroize::Zeroizing;

/// Bytes in one AES or Twofish block.
pub const BLOCK_LEN: usize = 16;

/// Key length of every payload cipher, in bytes.
pub const KEY_LEN: usize = 32;

/// The three payload ciphers (CRY-01 table). Mapping a header cipher id to a
/// value of this type is the vault format's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256 in CBC mode with PKCS#7 padding (NIST SP 800-38A, FIPS 197).
    Aes256Cbc,
    /// Twofish with a 256-bit key in CBC mode with PKCS#7 padding.
    Twofish256Cbc,
    /// ChaCha20 (RFC 8439 block function), 96-bit nonce, counter from 0.
    ChaCha20,
}

impl Cipher {
    /// The IV or nonce length this cipher takes: 16 bytes for the CBC
    /// ciphers, 12 bytes for ChaCha20.
    #[must_use]
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Aes256Cbc | Self::Twofish256Cbc => BLOCK_LEN,
            Self::ChaCha20 => 12,
        }
    }
}

/// Encrypts `plaintext` in one call. CBC output is the plaintext padded to
/// the next whole block (1 to 16 bytes of PKCS#7 padding are always added);
/// ChaCha20 output has the plaintext's length.
///
/// # Errors
/// [`Error::KeyLength`] or [`Error::IvLength`] before any work;
/// [`Error::StreamLimit`] if ChaCha20 would pass its block limit.
pub fn encrypt(
    cipher: Cipher,
    key: &SecretBytes,
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    scrubbed(|| {
        let mut enc = Encryptor::new(cipher, key, iv)?;
        let mut out = enc.update(plaintext)?;
        out.extend(enc.finish());
        Ok(out)
    })
}

/// Decrypts `ciphertext` in one call and removes the CBC padding. The result
/// is returned only if every check passed.
///
/// # Errors
/// [`Error::KeyLength`] or [`Error::IvLength`] before any work; otherwise
/// [`Error::Decrypt`] for every failure, whatever the cause.
pub fn decrypt(
    cipher: Cipher,
    key: &SecretBytes,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    scrubbed(|| {
        let mut dec = Decryptor::new(cipher, key, iv)?;
        let head = dec.update(ciphertext)?;
        let tail = dec.finish()?;
        // Chain of two slices has an exact length, so the Vec never grows.
        Ok(SecretBytes::new(
            head.expose().iter().chain(tail.expose()).copied().collect(),
        ))
    })
}

/// Streaming encryption: [`Encryptor::update`] for each chunk, then
/// [`Encryptor::finish`] once. The joined output equals [`encrypt`] of the
/// joined input, however the input was split.
pub struct Encryptor {
    mode: EncMode,
    pending: Box<Pending>,
}

enum EncMode {
    Aes(Box<cbc::Encryptor<aes::Aes256>>),
    Twofish(Box<cbc::Encryptor<twofish::Twofish>>),
    ChaCha(Box<chacha20::ChaCha20>),
}

impl Encryptor {
    /// Starts an encryption with `key` and `iv`.
    ///
    /// # Errors
    /// [`Error::KeyLength`] if the key is not 32 bytes, then
    /// [`Error::IvLength`] if the IV does not fit the cipher. No work is done.
    pub fn new(cipher: Cipher, key: &SecretBytes, iv: &[u8]) -> Result<Self, Error> {
        check_lengths(cipher, key, iv)?;
        scrubbed(|| {
            let k = key.expose();
            let mode = match cipher {
                Cipher::Aes256Cbc => EncMode::Aes(Box::new(init(k, iv)?)),
                Cipher::Twofish256Cbc => EncMode::Twofish(Box::new(init(k, iv)?)),
                Cipher::ChaCha20 => EncMode::ChaCha(Box::new(init(k, iv)?)),
            };
            Ok(Self {
                mode,
                pending: Box::default(),
            })
        })
    }

    /// Encrypts the next chunk and returns the ciphertext ready so far. CBC
    /// returns whole blocks only and keeps the last partial block (wiped
    /// later) for the next call or [`Encryptor::finish`].
    ///
    /// # Errors
    /// [`Error::StreamLimit`] if ChaCha20 would pass its block limit; nothing
    /// of this chunk is encrypted then.
    pub fn update(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        scrubbed(|| match &mut self.mode {
            EncMode::Aes(m) => Ok(cbc_encrypt(m.as_mut(), &mut self.pending, plaintext)),
            EncMode::Twofish(m) => Ok(cbc_encrypt(m.as_mut(), &mut self.pending, plaintext)),
            EncMode::ChaCha(c) => {
                let mut out = vec![0; plaintext.len()];
                c.try_apply_keystream_b2b(plaintext, &mut out)
                    .map_err(|_| Error::StreamLimit)?;
                Ok(out)
            }
        })
    }

    /// Ends the encryption. CBC returns the last block with the PKCS#7
    /// padding (always 16 bytes); ChaCha20 returns nothing.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        scrubbed(|| match &mut self.mode {
            EncMode::Aes(m) => cbc_pad_last(m.as_mut(), &self.pending),
            EncMode::Twofish(m) => cbc_pad_last(m.as_mut(), &self.pending),
            EncMode::ChaCha(_) => Vec::new(),
        })
    }
}

/// Streaming decryption: [`Decryptor::update`] for each chunk, then
/// [`Decryptor::finish`] once. The joined output equals [`decrypt`] of the
/// joined input, however the input was split.
///
/// Output from `update` is not checked yet: the CBC length and padding are
/// checked only by `finish`. If any call fails, drop everything returned so
/// far (FMT-08.11).
pub struct Decryptor {
    mode: DecMode,
    pending: Box<Pending>,
}

enum DecMode {
    Aes(Box<cbc::Decryptor<aes::Aes256>>),
    Twofish(Box<cbc::Decryptor<twofish::Twofish>>),
    ChaCha(Box<chacha20::ChaCha20>),
}

impl Decryptor {
    /// Starts a decryption with `key` and `iv`.
    ///
    /// # Errors
    /// [`Error::KeyLength`] if the key is not 32 bytes, then
    /// [`Error::IvLength`] if the IV does not fit the cipher. No work is done.
    pub fn new(cipher: Cipher, key: &SecretBytes, iv: &[u8]) -> Result<Self, Error> {
        check_lengths(cipher, key, iv)?;
        scrubbed(|| {
            let k = key.expose();
            let mode = match cipher {
                Cipher::Aes256Cbc => DecMode::Aes(Box::new(init(k, iv)?)),
                Cipher::Twofish256Cbc => DecMode::Twofish(Box::new(init(k, iv)?)),
                Cipher::ChaCha20 => DecMode::ChaCha(Box::new(init(k, iv)?)),
            };
            Ok(Self {
                mode,
                pending: Box::default(),
            })
        })
    }

    /// Decrypts the next chunk and returns the plaintext ready so far. CBC
    /// always holds back the last 1 to 16 ciphertext bytes, because the last
    /// block carries the padding; [`Decryptor::finish`] decrypts them.
    ///
    /// # Errors
    /// [`Error::Decrypt`] if ChaCha20 would pass its block limit; nothing of
    /// this chunk is decrypted then.
    pub fn update(&mut self, ciphertext: &[u8]) -> Result<SecretBytes, Error> {
        scrubbed(|| match &mut self.mode {
            DecMode::Aes(m) => Ok(cbc_decrypt(m.as_mut(), &mut self.pending, ciphertext)),
            DecMode::Twofish(m) => Ok(cbc_decrypt(m.as_mut(), &mut self.pending, ciphertext)),
            DecMode::ChaCha(c) => {
                let mut out = SecretBytes::zeroed(ciphertext.len());
                c.try_apply_keystream_b2b(ciphertext, out.expose_mut())
                    .map_err(|_| Error::Decrypt)?;
                Ok(out)
            }
        })
    }

    /// Ends the decryption. CBC checks that the whole ciphertext was a
    /// non-zero number of blocks and that the padding is valid (last byte n
    /// from 1 to 16, last n bytes all n), then returns the last block's
    /// plaintext without the padding. ChaCha20 returns nothing.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for any failed check, one value for all of them.
    pub fn finish(mut self) -> Result<SecretBytes, Error> {
        scrubbed(|| match &mut self.mode {
            DecMode::Aes(m) => cbc_unpad_last(m.as_mut(), &self.pending),
            DecMode::Twofish(m) => cbc_unpad_last(m.as_mut(), &self.pending),
            DecMode::ChaCha(_) => Ok(SecretBytes::new(Vec::new())),
        })
    }

    /// Ends the decryption without any padding check, for version 3 files
    /// whose padding lies after the logical end and is never read
    /// (spec/decisions.md LD-41, CRY-01.10, FMT-07.11). CBC returns the held
    /// last block decrypted as a whole block, padding bytes included, or
    /// nothing when no block is held; ChaCha20 returns nothing.
    ///
    /// # Errors
    /// [`Error::Decrypt`] when the CBC input was not a whole number of blocks.
    pub fn finish_unpadded(mut self) -> Result<SecretBytes, Error> {
        scrubbed(|| match &mut self.mode {
            DecMode::Aes(m) => cbc_whole_last(m.as_mut(), &self.pending),
            DecMode::Twofish(m) => cbc_whole_last(m.as_mut(), &self.pending),
            DecMode::ChaCha(_) => Ok(SecretBytes::new(Vec::new())),
        })
    }
}

/// The held block of a CBC decryption, decrypted with no padding check.
fn cbc_whole_last<M: BlockModeDecrypt<BlockSize = U16>>(
    mode: &mut M,
    pending: &Pending,
) -> Result<SecretBytes, Error> {
    match pending.len {
        0 => Ok(SecretBytes::new(Vec::new())),
        BLOCK_LEN => {
            let mut block = SecretBytes::new(pending.buf.to_vec());
            mode.decrypt_blocks(Array::<u8, U16>::slice_as_chunks_mut(block.expose_mut()).0);
            Ok(block)
        }
        _ => Err(Error::Decrypt),
    }
}

/// Key first, then IV, so the error names the first wrong input.
fn check_lengths(cipher: Cipher, key: &SecretBytes, iv: &[u8]) -> Result<(), Error> {
    if key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    if iv.len() != cipher.iv_len() {
        return Err(Error::IvLength);
    }
    Ok(())
}

/// Lengths are checked before this; the crate checks them again.
fn init<T: KeyIvInit>(key: &[u8], iv: &[u8]) -> Result<T, Error> {
    T::new_from_slices(key, iv).map_err(|_| Error::KeyLength)
}

/// Input bytes that do not make a whole block yet: 0 to 15 for encryption,
/// 0 to 16 for decryption (the held-back last block). Wiped on drop.
#[derive(Default)]
struct Pending {
    buf: Zeroizing<[u8; BLOCK_LEN]>,
    len: usize,
}

impl Pending {
    /// How many bytes of `held ++ input` to process now: whole blocks only,
    /// and with `hold_last` never the final 1 to 16 bytes.
    fn ready_len(&self, input_len: usize, hold_last: bool) -> usize {
        let total = self.len.saturating_add(input_len);
        let total = if hold_last {
            total.saturating_sub(1)
        } else {
            total
        };
        total.saturating_sub(total % BLOCK_LEN)
    }

    /// Writes the first `out.len()` bytes of `held ++ input` into `out` and
    /// holds the rest, which [`Self::ready_len`] keeps to at most one block.
    fn fill(&mut self, input: &[u8], out: &mut [u8]) {
        let mut src = self.buf.iter().take(self.len).chain(input).copied();
        for (o, b) in out.iter_mut().zip(&mut src) {
            *o = b;
        }
        let mut next = Zeroizing::new([0u8; BLOCK_LEN]);
        let len = next.iter_mut().zip(src).map(|(p, b)| *p = b).count();
        self.buf = next;
        self.len = len;
    }
}

fn cbc_encrypt<M: BlockModeEncrypt<BlockSize = U16>>(
    mode: &mut M,
    pending: &mut Pending,
    input: &[u8],
) -> Vec<u8> {
    // Plaintext is copied in and encrypted in place, so `out` ends up
    // holding only ciphertext.
    let mut out = vec![0; pending.ready_len(input.len(), false)];
    pending.fill(input, &mut out);
    mode.encrypt_blocks(Array::<u8, U16>::slice_as_chunks_mut(&mut out).0);
    out
}

fn cbc_pad_last<M: BlockModeEncrypt<BlockSize = U16>>(mode: &mut M, pending: &Pending) -> Vec<u8> {
    // PKCS#7: n bytes of value n, n = 16 - held, so 1 to 16 (CRY-01.4).
    // `held` is at most 15 here, so the cast is exact.
    let pad = BLOCK_LEN.saturating_sub(pending.len) as u8;
    let mut block: Vec<u8> = pending
        .buf
        .iter()
        .take(pending.len)
        .copied()
        .chain(core::iter::repeat(pad))
        .take(BLOCK_LEN)
        .collect();
    mode.encrypt_blocks(Array::<u8, U16>::slice_as_chunks_mut(&mut block).0);
    block
}

fn cbc_decrypt<M: BlockModeDecrypt<BlockSize = U16>>(
    mode: &mut M,
    pending: &mut Pending,
    input: &[u8],
) -> SecretBytes {
    let mut out = SecretBytes::zeroed(pending.ready_len(input.len(), true));
    pending.fill(input, out.expose_mut());
    mode.decrypt_blocks(Array::<u8, U16>::slice_as_chunks_mut(out.expose_mut()).0);
    out
}

fn cbc_unpad_last<M: BlockModeDecrypt<BlockSize = U16>>(
    mode: &mut M,
    pending: &Pending,
) -> Result<SecretBytes, Error> {
    // Empty input, or a length that is not a whole number of blocks.
    if pending.len != BLOCK_LEN {
        return Err(Error::Decrypt);
    }
    let mut block = SecretBytes::new(pending.buf.to_vec());
    mode.decrypt_blocks(Array::<u8, U16>::slice_as_chunks_mut(block.expose_mut()).0);
    let keep = unpadded_len(block.expose()).ok_or(Error::Decrypt)?;
    Ok(SecretBytes::new(
        block.expose().iter().take(keep).copied().collect(),
    ))
}

/// The plaintext length of the decrypted last block if its PKCS#7 padding is
/// valid. Looks at all 16 bytes whatever their values: constant time.
fn unpadded_len(block: &[u8]) -> Option<usize> {
    let n = block.last().copied().unwrap_or(0);
    let mut ok = n.ct_gt(&0) & !n.ct_gt(&16);
    // The k-th byte from the end is padding when k <= n; it must equal n.
    for (k, b) in (1u8..=16).zip(block.iter().rev()) {
        ok &= k.ct_gt(&n) | b.ct_eq(&n);
    }
    bool::from(ok).then(|| BLOCK_LEN.saturating_sub(usize::from(n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::StreamCipherSeek;

    // CRY-01.13, CRY-01 T21: past the last usable block every call fails and
    // nothing wraps around to block 0.
    #[test]
    fn chacha20_stops_at_the_block_limit() {
        let key = SecretBytes::new(vec![7; KEY_LEN]);
        let mut enc = Encryptor::new(Cipher::ChaCha20, &key, &[0; 12]).unwrap();
        let mut dec = Decryptor::new(Cipher::ChaCha20, &key, &[0; 12]).unwrap();
        let last_usable = u64::from(u32::MAX - 1) * 64;
        if let EncMode::ChaCha(c) = &mut enc.mode {
            c.seek(last_usable);
        }
        if let DecMode::ChaCha(c) = &mut dec.mode {
            c.seek(last_usable);
        }
        assert_eq!(enc.update(&[0; 64]).unwrap().len(), 64);
        assert_eq!(enc.update(&[0; 1]).err(), Some(Error::StreamLimit));
        assert_eq!(enc.update(&[0; 1]).err(), Some(Error::StreamLimit));
        // The decryptor gives the one decrypt error (LD-04).
        assert_eq!(dec.update(&[0; 65]).err(), Some(Error::Decrypt));
        assert_eq!(dec.update(&[0; 64]).unwrap().len(), 64);
        assert_eq!(dec.update(&[0; 1]).err(), Some(Error::Decrypt));
    }

    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    // Compile-time proof: every cipher state and the held-back bytes wipe
    // themselves on drop (the crates' zeroize features, Zeroizing).
    #[test]
    fn state_and_held_bytes_are_wiped_on_drop() {
        wipes(&Pending::default().buf);
        let key = SecretBytes::new(vec![1; KEY_LEN]);
        for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc, Cipher::ChaCha20] {
            let iv = vec![0; c.iv_len()];
            match &Encryptor::new(c, &key, &iv).unwrap().mode {
                EncMode::Aes(m) => wipes(m.as_ref()),
                EncMode::Twofish(m) => wipes(m.as_ref()),
                EncMode::ChaCha(m) => wipes(m.as_ref()),
            }
            match &Decryptor::new(c, &key, &iv).unwrap().mode {
                DecMode::Aes(m) => wipes(m.as_ref()),
                DecMode::Twofish(m) => wipes(m.as_ref()),
                DecMode::ChaCha(m) => wipes(m.as_ref()),
            }
        }
    }

    // For one IV byte value the padding check alone would pass, so the
    // length check must refuse empty and partial-block input by itself.
    #[test]
    fn length_check_is_not_hidden_by_the_padding_check() {
        let key = SecretBytes::new(vec![5; KEY_LEN]);
        for c in [Cipher::Aes256Cbc, Cipher::Twofish256Cbc] {
            for v in 0u8..=255 {
                let mut iv = [0u8; BLOCK_LEN];
                iv[15] = v;
                assert_eq!(decrypt(c, &key, &iv, &[]).err(), Some(Error::Decrypt));
                let mut ct = [0u8; 21];
                ct[15] = v;
                let got = decrypt(c, &key, &[0; BLOCK_LEN], &ct).err();
                assert_eq!(got, Some(Error::Decrypt), "{c:?} v = {v}");
            }
        }
    }

    #[test]
    fn unpad_accepts_exactly_the_valid_paddings() {
        for n in 0u8..=255 {
            let mut block = [0xAB; BLOCK_LEN];
            let valid = (1..=16).contains(&n);
            if valid {
                block[BLOCK_LEN - usize::from(n)..].fill(n);
            } else {
                block[BLOCK_LEN - 1] = n;
            }
            let want = valid.then(|| BLOCK_LEN - usize::from(n));
            assert_eq!(unpadded_len(&block), want, "n = {n}");
        }
        // A last byte above 16 fails even when every byte equals it.
        for n in 17u8..=255 {
            assert_eq!(unpadded_len(&[n; BLOCK_LEN]), None, "n = {n}");
        }
        assert_eq!(unpadded_len(&[0; BLOCK_LEN]), None);
        // One wrong byte anywhere inside the padding fails.
        for n in 2u8..=16 {
            for wrong in BLOCK_LEN - usize::from(n)..BLOCK_LEN - 1 {
                let mut block = [0u8; BLOCK_LEN];
                block[BLOCK_LEN - usize::from(n)..].fill(n);
                block[wrong] ^= 0x01;
                assert_eq!(unpadded_len(&block), None, "n = {n}, byte {wrong}");
            }
        }
    }

    #[test]
    fn pending_holds_at_most_one_block() {
        let mut p = Pending::default();
        // Encryption: never holds a whole block.
        let n = p.ready_len(33, false);
        let mut out = vec![0; n];
        p.fill(&[1; 33], &mut out);
        assert_eq!((n, p.len), (32, 1));
        // Decryption: always holds the last 1 to 16 bytes.
        let n = p.ready_len(15, true);
        let mut out = vec![0; n];
        p.fill(&[2; 15], &mut out);
        assert_eq!((n, p.len), (0, 16));
        let n = p.ready_len(1, true);
        let mut out = vec![0; n];
        p.fill(&[3; 1], &mut out);
        assert_eq!((n, p.len, out), (16, 1, [vec![1], vec![2; 15]].concat()));
    }
}
