use super::*;
use larsal_crypto::secret::SecretBytes;

const ACCOUNT: AccountId = AccountId::from_bytes([3; 16]);
const VAULT: VaultId = VaultId::from_bytes([9; 16]);

fn keys() -> AccountKeys {
    AccountKeys {
        identity_public_key: vec![1; IDENTITY_PUBLIC],
        kem_public_key: vec![2; PUBLIC_KEY],
        kem_signature: vec![3; SIGNATURE],
        recovery_public_key: [4; 32],
        blob: vec![5; 158],
    }
}

/// The record's JSON with `field` set to base64url of `len` bytes.
fn with(field: &str, len: usize) -> Vec<u8> {
    let text = String::from_utf8(keys().to_json()).unwrap();
    let mut v = larsal_model::json::from_slice_unique(text.as_bytes()).unwrap();
    *v.get_mut(field).unwrap() = b64(&vec![7u8; len]).into();
    larsal_model::json::to_string(&v).into_bytes()
}

/// CRY-05.8, CRY-05 T14, SYN-01.8: the keys record has CRY-05.8's names
/// and sizes; one byte more or less in any field, a padded or standard
/// base64 field, a missing field or a blob over 4 KiB is refused.
#[test]
fn cry05_8_t14_keys_record_names_and_sizes() {
    let k = keys();
    assert_eq!(AccountKeys::read(&k.to_json()).unwrap(), k);
    let text = String::from_utf8(k.to_json()).unwrap();
    for name in [
        "identity_public_key",
        "kem_public_key",
        "kem_signature",
        "recovery_public_key",
        "blob",
    ] {
        assert!(text.contains(&format!("\"{name}\":")), "{name}");
    }
    for (field, len) in [
        ("identity_public_key", IDENTITY_PUBLIC),
        ("kem_public_key", PUBLIC_KEY),
        ("kem_signature", SIGNATURE),
        ("recovery_public_key", 32),
    ] {
        assert!(AccountKeys::read(&with(field, len)).is_ok(), "{field}");
        for bad in [len - 1, len + 1, 0] {
            assert_eq!(
                AccountKeys::read(&with(field, bad)),
                Err(Error::Invalid(match field {
                    "identity_public_key" => "identity_public_key",
                    "kem_public_key" => "kem_public_key",
                    "kem_signature" => "kem_signature",
                    _ => "recovery_public_key",
                })),
                "{field} {bad}"
            );
        }
    }
    assert!(AccountKeys::read(&with("blob", 1)).is_ok());
    assert!(AccountKeys::read(&with("blob", MAX_BLOB)).is_ok());
    assert_eq!(
        AccountKeys::read(&with("blob", MAX_BLOB + 1)),
        Err(Error::Invalid("blob"))
    );
    assert_eq!(
        AccountKeys::read(&with("blob", 0)),
        Err(Error::Invalid("blob"))
    );
    let padded = text.replacen(&b64(&k.blob), &format!("{}==", b64(&k.blob)), 1);
    assert_eq!(
        AccountKeys::read(padded.as_bytes()),
        Err(Error::Invalid("blob"))
    );
    let standard = text.replacen(
        &b64(&k.recovery_public_key),
        &base64::encode(Form::Padded, &[0xfb; 32]),
        1,
    );
    assert!(AccountKeys::read(standard.as_bytes()).is_err());
    let missing = text.replacen("\"blob\":", "\"blab\":", 1);
    assert_eq!(
        AccountKeys::read(missing.as_bytes()),
        Err(Error::Missing("blob"))
    );
}

/// SYN-01.7: the upload message is the field list of the label, the vault
/// id's 16 bytes, the version as a u64 big endian and the body's SHA-256.
#[test]
fn syn01_7_upload_message_is_the_field_list() {
    let m = upload_message(&VAULT, 5, &[8; 32]).unwrap();
    let mut want = Vec::new();
    for field in [UPLOAD_LABEL, &[9; 16], &5u64.to_be_bytes(), &[8; 32]] {
        want.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        want.extend_from_slice(field);
    }
    assert_eq!(m, want);
    assert_eq!(&m[..18], b"\x00\x00\x00\x0esync-upload-v1");
    assert_ne!(m, upload_message(&VAULT, 4, &[8; 32]).unwrap());
}

/// CRY-05.10, CRY-05 T18: `Upload-Signature` is exactly 4,498 base64url
/// characters of 3,373 bytes, on one line; anything else reads as none.
#[test]
fn cry05_10_t18_upload_signature_header() {
    let sig = vec![0xa5u8; SIGNATURE];
    let text = b64(&sig);
    assert_eq!(text.len(), UPLOAD_SIGNATURE_LEN);
    assert_eq!(upload_signature(&[text.as_bytes()]), Some(sig.clone()));
    let short = &text[1..];
    let long = format!("{text}A");
    let padded = format!("{text}==");
    let plus = text.replacen('p', "+", 1);
    let mut odd = text.clone().into_bytes();
    let last = odd.len() - 1;
    odd[last] = odd[last].wrapping_add(1);
    for bad in [
        short.as_bytes(),
        long.as_bytes(),
        padded.as_bytes(),
        plus.as_bytes(),
        &odd,
        b"",
    ] {
        assert_eq!(upload_signature(&[bad]), None);
    }
    assert_eq!(upload_signature(&[]), None);
    assert_eq!(upload_signature(&[text.as_bytes(), text.as_bytes()]), None);
}

/// SYN-06.9: the key-file part's info is the field list of the label,
/// `keypart`, the account id and the vault id.
#[test]
fn syn06_9_keypart_info_is_the_field_list() {
    let info = keypart_info(&ACCOUNT, &VAULT).unwrap();
    let mut want = Vec::new();
    for field in [WRAP_INFO_LABEL, b"keypart", &[3; 16], &[9; 16]] {
        want.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        want.extend_from_slice(field);
    }
    assert_eq!(info, want);
    assert_ne!(info, keypart_info(&ACCOUNT, &ACCOUNT).unwrap());
}

/// SYN-06.12, SYN-01.13: the recovery records read back; the sign-in's
/// `Debug` hides the nonce and the signature; a bad name or key is
/// refused; the reply carries the new device's id and the token.
#[test]
fn syn06_12_recovery_records() {
    let ask = RecoveryChallengeRequest {
        account_id: ACCOUNT,
    };
    assert_eq!(RecoveryChallengeRequest::read(&ask.to_json()).unwrap(), ask);
    assert!(RecoveryChallengeRequest::read(br#"{"account_id":"03"}"#).is_err());
    let s = RecoverySignIn {
        account_id: ACCOUNT,
        nonce: [0xab; 32],
        device_public_key: [4; 65],
        device_name: "Mac".into(),
        signature: [0xcd; 64],
    };
    assert_eq!(RecoverySignIn::read(&s.to_json()).unwrap(), s);
    let shown = format!("{s:?}");
    assert!(!shown.contains("171") && !shown.contains("ab") && !shown.contains("205"));
    assert!(shown.contains("[hidden]"));
    let text = String::from_utf8(s.to_json()).unwrap();
    let unnamed = text.replace("\"Mac\"", "\"\"");
    assert_eq!(
        RecoverySignIn::read(unnamed.as_bytes()),
        Err(Error::Invalid("device_name"))
    );
    let short_key = text.replace(&b64(&[4; 65]), &b64(&[4; 64]));
    assert_eq!(
        RecoverySignIn::read(short_key.as_bytes()),
        Err(Error::Invalid("device_public_key"))
    );
    let r = Recovered {
        device_id: DeviceId::from_bytes([6; 16]),
        session: Session {
            token: SecretBytes::new(vec![0x77; 32]),
            idle_seconds: 900,
            expires: 1_000,
        },
    };
    let back = Recovered::read(&r.to_json()).unwrap();
    assert_eq!(back.device_id, r.device_id);
    assert_eq!(back.session.token.expose(), &[0x77; 32]);
    assert_eq!(
        (back.session.idle_seconds, back.session.expires),
        (900, 1_000)
    );
    let session_only = String::from_utf8(r.to_json())
        .unwrap()
        .replace("\"device_id\"", "\"device\"");
    assert_eq!(
        Recovered::read(session_only.as_bytes()).map(|r| r.device_id),
        Err(Error::Missing("device_id"))
    );
}
