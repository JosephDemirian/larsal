//! AES-SIV (RFC 5297), the deterministic interface with an associated-data vector,
//! for folder names and directory IDs (E23-S3, FIL-04.9). Never the crate's
//! nonce wrapper, and no PMAC.
//!
//! The 64-byte key is RFC 5297's `K1 || K2`: the first half keys S2V (CMAC), the
//! second keys CTR. No associated data and one empty component are different inputs
//! to S2V, and stay different here: `ad` is the vector as given.
//!
//! Guarantees: a sealed value is the 16-byte tag, then the ciphertext; an open
//! proves the tag over the plaintext and gives it only in a [`SecretBytes`], which a
//! failure wipes; the crate's key state wipes itself on drop (checked below); 32 KiB
//! of stack below each call is zeroed after it. Limit, from the crate's publisher: no
//! audit and no thorough constant-time assessment of this crate.

use crate::Error;
use crate::secret::{SecretBytes, scrubbed};
use aes_siv::KeyInit;
use aes_siv::aead::inout::InOutBuf;
#[cfg(test)]
use aes_siv::siv::Aes128Siv;
use aes_siv::siv::Aes256Siv;

/// Bytes of a key: the S2V key, then the CTR key.
pub const KEY: usize = 64;
/// Bytes of the tag at the front of a sealed value.
pub const TAG: usize = 16;

macro_rules! seal_as {
    ($siv:ty, $key:expr, $ad:expr, $plain:expr) => {{
        let len = $plain.len().checked_add(TAG).ok_or(Error::TooLarge)?;
        let mut out = vec![0u8; len];
        scrubbed(|| {
            let mut siv = <$siv>::new_from_slice($key).map_err(|_| Error::KeyLength)?;
            let (front, body) = out.split_at_mut_checked(TAG).ok_or(Error::TooLarge)?;
            let buf = InOutBuf::new($plain, body).map_err(|_| Error::TooLarge)?;
            let tag = siv
                .encrypt_inout_detached($ad.iter().copied(), buf)
                .map_err(|_| Error::TooLarge)?;
            front.copy_from_slice(&tag);
            Ok::<(), Error>(())
        })?;
        Ok::<Vec<u8>, Error>(out)
    }};
}

macro_rules! open_as {
    ($siv:ty, $key:expr, $ad:expr, $sealed:expr) => {{
        let (tag, body) = $sealed.split_at_checked(TAG).ok_or(Error::Decrypt)?;
        // In place, on purpose: on a failure the crate undoes its work only in place,
        // and with two buffers the plaintext would stay in the second.
        let mut plain = SecretBytes::new(body.to_vec());
        scrubbed(|| {
            let mut siv = <$siv>::new_from_slice($key).map_err(|_| Error::KeyLength)?;
            let tag = tag.try_into().map_err(|_| Error::Decrypt)?;
            siv.decrypt_inout_detached($ad.iter().copied(), plain.expose_mut().into(), tag)
                .map_err(|_| Error::Decrypt)
        })?;
        Ok::<SecretBytes, Error>(plain)
    }};
}

/// Seals `plain` under `key`, deterministically, binding the vector `ad`.
///
/// # Errors
/// [`Error::KeyLength`] for a key that is not 64 bytes, before any work;
/// [`Error::TooLarge`] for more components than RFC 5297 allows.
pub fn seal(key: &SecretBytes, ad: &[&[u8]], plain: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    seal_as!(Aes256Siv, key.expose(), ad, plain)
}

/// Opens a value [`seal`] made, with the same key and vector.
///
/// # Errors
/// [`Error::Decrypt`] for any change of the key, vector or value, and for a value
/// shorter than the tag; [`Error::KeyLength`] for a key that is not 64 bytes.
pub fn open(key: &SecretBytes, ad: &[&[u8]], sealed: &[u8]) -> Result<SecretBytes, Error> {
    if key.len() != KEY {
        return Err(Error::KeyLength);
    }
    open_as!(Aes256Siv, key.expose(), ad, sealed)
}

// Compile-time proof of "wipes itself on drop".
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<Aes256Siv>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let t: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        t.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 5297 A.1 and A.2 name AES-128: the same macros, the same arrangement. The
    /// AES-256 path is held to names and IDs a peer made, in larsal-folders.
    #[test]
    fn rfc5297_a1_deterministic() -> Result<(), Error> {
        let key = hex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");
        let ad = hex("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
        let plain = hex("11223344 55667788 99aabbcc ddee");
        let want = hex("85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c");
        let parts: [&[u8]; 1] = [&ad];
        let got = seal_as!(Aes128Siv, &key, parts, &plain[..])?;
        assert_eq!(got, want);
        let back = open_as!(Aes128Siv, &key, parts, &got[..])?;
        assert_eq!(back.expose(), &plain[..]);
        Ok(())
    }

    #[test]
    fn rfc5297_a2_nonce_based_vector() -> Result<(), Error> {
        let key = hex("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f");
        let ad1 = hex(
            "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
        );
        let ad2 = hex("10203040 50607080 90a0");
        let nonce = hex("09f91102 9d74e35b d84156c5 635688c0");
        let plain = hex(
            "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
        );
        let want = hex(
            "7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d",
        );
        let parts: [&[u8]; 3] = [&ad1, &ad2, &nonce];
        assert_eq!(seal_as!(Aes128Siv, &key, parts, &plain[..])?, want);
        Ok(())
    }

    #[test]
    fn fil04_t09_no_associated_data_and_an_empty_component_differ() {
        let key = SecretBytes::new(vec![7u8; KEY]);
        let none: [&[u8]; 0] = [];
        let empty: [&[u8]; 1] = [b""];
        let a = seal(&key, &none, b"demo").unwrap();
        let b = seal(&key, &empty, b"demo").unwrap();
        assert_ne!(a, b);
        assert!(open(&key, &empty, &a).is_err());
        assert!(open(&key, &none, &b).is_err());
        assert_eq!(open(&key, &none, &a).unwrap().expose(), b"demo");
        assert_eq!(open(&key, &empty, &b).unwrap().expose(), b"demo");
    }

    #[test]
    fn fil04_t09_every_changed_byte_fails_and_gives_nothing() {
        let key = SecretBytes::new(vec![9u8; KEY]);
        let parent: [&[u8]; 1] = [b"parent"];
        let sealed = seal(&key, &parent, b"a demo name").unwrap();
        for at in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert_eq!(open(&key, &parent, &bad).err(), Some(Error::Decrypt));
        }
        assert!(open(&key, &parent, &sealed[..TAG - 1]).is_err());
        assert_eq!(
            seal(&SecretBytes::new(vec![0; 32]), &parent, b"x"),
            Err(Error::KeyLength)
        );
    }
}
