//! The sign-in message (SYN-04.4, CRY-04.2): the bytes a Mac's device key
//! signs and the server checks, so both sides build the same ones.
//!
//! The message is the field list (`sync-signin-v1`, origin, nonce, device
//! id): the label binds the signature to sign-in, the origin to this
//! server, the nonce to this one challenge and the id to this device, so a
//! signature captured by another server or replayed later signs nobody in
//! (AT-L07). Crypto only through larsal-crypto.

use crate::Error;
use crate::messages::{AccountId, DeviceId};
use larsal_crypto::sign;

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

/// The label of the recovery sign-in message (SYN-06.12, CRY-04.2).
pub const RECOVERY_LABEL: &[u8] = b"sync-recovery-signin-v1";

/// The bytes the recovery key signs (SYN-06.12): the field list
/// (`sync-recovery-signin-v1`, `origin`, `nonce`, the 16 bytes of
/// `account`, the new device's 65-byte public key). The key binds the
/// signature to this server, this challenge, this account and this device,
/// so a captured one registers no other key (AT-L07).
///
/// # Errors
/// [`Error::TooLarge`] for an origin of 4 GiB or more.
pub fn recovery_message(
    origin: &str,
    nonce: &[u8; 32],
    account: &AccountId,
    device_public_key: &[u8; 65],
) -> Result<Vec<u8>, Error> {
    sign::field_list(&[
        RECOVERY_LABEL,
        origin.as_bytes(),
        nonce,
        account.as_bytes(),
        device_public_key,
    ])
    .map_err(|_| Error::TooLarge)
}

/// True when `signature` is the Ed25519 signature (CRY-04.3) of
/// [`recovery_message`] by the 32-byte recovery public key.
#[must_use]
pub fn recovery_verify(
    public_key: &[u8; 32],
    origin: &str,
    nonce: &[u8; 32],
    account: &AccountId,
    device_public_key: &[u8; 65],
    signature: &[u8; 64],
) -> bool {
    recovery_message(origin, nonce, account, device_public_key)
        .is_ok_and(|m| sign::ed25519_verify(public_key, &m, signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_crypto::sign::P256TestKey;

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

    /// SYN-06.12: the recovery message is the field list of the label, the
    /// origin, the nonce, the account id and the device key; the Ed25519
    /// signature holds only for those and its own key.
    #[test]
    fn syn06_12_recovery_signature_binds_origin_nonce_account_and_device() {
        use larsal_crypto::secret::SecretBytes;
        let account = AccountId::from_bytes([3; 16]);
        let device_key = [4u8; 65];
        let m = recovery_message("https://a:1", &[9; 32], &account, &device_key).unwrap();
        let mut want = Vec::new();
        for field in [RECOVERY_LABEL, b"https://a:1", &[9; 32], &[3; 16], &[4; 65]] {
            want.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            want.extend_from_slice(field);
        }
        assert_eq!(m, want);
        let seed = SecretBytes::new(vec![0x21; 32]);
        let public = sign::ed25519_public(&seed).unwrap();
        let o = origin("127.0.0.1", 8443);
        let sig = sign::ed25519_sign(
            &seed,
            &recovery_message(&o, &[9; 32], &account, &device_key).unwrap(),
        )
        .unwrap();
        assert!(recovery_verify(
            &public,
            &o,
            &[9; 32],
            &account,
            &device_key,
            &sig
        ));
        let other_account = AccountId::from_bytes([5; 16]);
        assert!(!recovery_verify(
            &public,
            "https://127.0.0.1:8444",
            &[9; 32],
            &account,
            &device_key,
            &sig
        ));
        assert!(!recovery_verify(
            &public,
            &o,
            &[8; 32],
            &account,
            &device_key,
            &sig
        ));
        assert!(!recovery_verify(
            &public,
            &o,
            &[9; 32],
            &other_account,
            &device_key,
            &sig
        ));
        assert!(!recovery_verify(
            &public, &o, &[9; 32], &account, &[5; 65], &sig
        ));
        let other = sign::ed25519_public(&SecretBytes::new(vec![0x22; 32])).unwrap();
        assert!(!recovery_verify(
            &other,
            &o,
            &[9; 32],
            &account,
            &device_key,
            &sig
        ));
    }
}
