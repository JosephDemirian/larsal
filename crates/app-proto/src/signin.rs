//! The sign-in message (SYN-04.4, CRY-04.2): the bytes a Mac's device key
//! signs and the server checks, so both sides build the same ones.
//!
//! The message is the field list (`sync-signin-v1`, origin, nonce, device
//! id): the label binds the signature to sign-in, the origin to this
//! server, the nonce to this one challenge and the id to this device, so a
//! signature captured by another server or replayed later signs nobody in
//! (AT-L07). Crypto only through app-crypto.

use crate::Error;
use crate::messages::DeviceId;
use app_crypto::sign;

/// The label of the sign-in message (CRY-04.2's table).
pub const LABEL: &[u8] = b"sync-signin-v1";

/// The origin both sides sign (SYN-04.4): `https://`, the host in lower
/// case, `:`, the port in decimal, always written (unlike RFC 6454 section
/// 6.2, which leaves out a scheme's default port).
#[must_use]
pub fn origin(host: &str, port: u16) -> String {
    format!("https://{}:{port}", host.to_ascii_lowercase())
}

/// The bytes the device key signs: the field list (`sync-signin-v1`,
/// `origin`, `nonce`, the 16 bytes of `device`) (CRY-04.2).
///
/// # Errors
/// [`Error::TooLarge`] for an origin of 4 GiB or more.
pub fn message(origin: &str, nonce: &[u8; 32], device: &DeviceId) -> Result<Vec<u8>, Error> {
    sign::field_list(&[LABEL, origin.as_bytes(), nonce, device.as_bytes()])
        .map_err(|_| Error::TooLarge)
}

/// True when `signature` is the P-256 signature of [`message`] by
/// `public_key` (65 SEC1 bytes; CRY-04.4, which also takes a high S).
#[must_use]
pub fn verify(
    public_key: &[u8],
    origin: &str,
    nonce: &[u8; 32],
    device: &DeviceId,
    signature: &[u8],
) -> bool {
    message(origin, nonce, device)
        .is_ok_and(|m| sign::p256_verify(public_key, &m, signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use app_crypto::sign::P256TestKey;

    const DEVICE: DeviceId = DeviceId::from_bytes([7; 16]);

    #[test]
    fn syn04_4_origin_always_writes_the_port_in_lower_case() {
        assert_eq!(origin("127.0.0.1", 8443), "https://127.0.0.1:8443");
        assert_eq!(origin("LocalHost", 443), "https://localhost:443");
    }

    /// CRY-04.2: the message is the field list of the label, the origin,
    /// the nonce and the device id, each after its u32 length.
    #[test]
    fn syn04_4_message_is_the_field_list() {
        let m = message("https://a:1", &[9; 32], &DEVICE).unwrap();
        let mut want = Vec::new();
        for field in [LABEL, b"https://a:1", &[9; 32], &[7; 16]] {
            want.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            want.extend_from_slice(field);
        }
        assert_eq!(m, want);
        assert_eq!(&m[..18], b"\x00\x00\x00\x0esync-signin-v1");
    }

    /// AT-L07: the signature holds only for its own origin, nonce, device
    /// and key; one changed byte of the signature fails.
    #[test]
    fn syn04_4_signature_binds_origin_nonce_device_and_key() {
        let key = P256TestKey::new().unwrap();
        let o = origin("127.0.0.1", 8443);
        let nonce = [3; 32];
        let sig = key.sign(&message(&o, &nonce, &DEVICE).unwrap());
        let public = key.public();
        assert!(verify(&public, &o, &nonce, &DEVICE, &sig));
        assert!(!verify(
            &public,
            "https://localhost:8443",
            &nonce,
            &DEVICE,
            &sig
        ));
        assert!(!verify(
            &public,
            "https://127.0.0.1:8444",
            &nonce,
            &DEVICE,
            &sig
        ));
        assert!(!verify(&public, &o, &[4; 32], &DEVICE, &sig));
        assert!(!verify(
            &public,
            &o,
            &nonce,
            &DeviceId::from_bytes([8; 16]),
            &sig
        ));
        let other = P256TestKey::new().unwrap().public();
        assert!(!verify(&other, &o, &nonce, &DEVICE, &sig));
        for i in 0..sig.len() {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert!(!verify(&public, &o, &nonce, &DEVICE, &bad), "byte {i}");
        }
        assert_eq!(format!("{key:?}"), "[hidden]");
    }
}
