//! E17-S2's wire checks (SYN-05, SYN-06.11): the known values of the code
//! and the commitment against an independent SHA-256, the key lists, the
//! approval header and every record.
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use larsal_crypto::base64::{self, Form};
use larsal_crypto::pq::{ENC, xwing_keypair};

/// CRY-04.2 written by hand, so the field lists below do not come from the
/// code under test.
fn by_hand(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&u32::try_from(p.len()).unwrap().to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `/usr/bin/shasum -a 256` of the two files this test writes
/// (proof/syn05-t02-shasum.txt): the code's and the commitment's field
/// lists of SYN-05 T02's values.
const T02_CODE_SHA: &str = "b94b667655acd2f11cc01695d6e3a25d233b8a771e249c2758d05ecd9a7b43ee";
const T02_COMMIT_SHA: &str = "041b9d1297ded6bdbd709c42491d38b86bfe6591ff382b174e7d3c9f08aa64d6";

/// `ctx`, `K_C`, `K_R`, `n_C` and `n_R`.
type Inputs = (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]);

/// T02's inputs: `ctx` = ("test", 16 bytes of 0x11); `K_C` = (32 bytes of
/// 0x22); `K_R` = (32 bytes of 0x33); `n_C` 32 bytes of 0x44; `n_R` 32 bytes
/// of 0x55.
fn t02() -> Inputs {
    (
        by_hand(&[b"test", &[0x11; 16]]),
        by_hand(&[&[0x22; 32]]),
        by_hand(&[&[0x33; 32]]),
        [0x44; 32],
        [0x55; 32],
    )
}

/// SYN-05.4, SYN-05 T02: Larsal's code of T02's values equals the code read
/// from an independent SHA-256 (`shasum -a 256` over the field list this
/// test writes out): the first 8 bytes as a u64 big endian, mod 10^6.
/// SYN-05.1: the commitment equals that tool's SHA-256 too.
#[test]
fn syn05_4_t02_known_value_against_an_independent_sha256() {
    let (ctx, kc, kr, nc, nr) = t02();
    let fields = by_hand(&[b"sync-compare-code-v1", &ctx, &kr, &kc, &nr, &nc]);
    let commit_fields = by_hand(&[b"sync-compare-commit-v1", &ctx, &kc, &nc]);
    let dir = std::env::temp_dir();
    std::fs::write(dir.join("larsal-syn05-t02-code-fields.bin"), &fields).unwrap();
    std::fs::write(
        dir.join("larsal-syn05-t02-commit-fields.bin"),
        &commit_fields,
    )
    .unwrap();
    let want = u64::from_str_radix(&T02_CODE_SHA[..16], 16).unwrap() % 1_000_000;
    let got = code(&ctx, &kr, &kc, &nr, &nc).unwrap();
    assert_eq!(u64::from(got), want);
    assert_eq!((got, shown(got).as_str()), (530_993, "530 993"));
    assert_eq!(
        hex(commitment(&ctx, &kc, &nc).unwrap().expose()),
        T02_COMMIT_SHA
    );
    println!(
        "SYN-05 T02: code field list {} bytes, independent SHA-256 {T02_CODE_SHA}, code {}; commitment {T02_COMMIT_SHA}",
        fields.len(),
        shown(got)
    );
}

/// SYN-05.4: the order of the fields is fixed by role: the other role's
/// order (`K_C` before `K_R`, `n_C` before `n_R`) gives another code.
#[test]
fn syn05_4_the_fields_go_in_the_roles_order() {
    let (ctx, kc, kr, nc, nr) = t02();
    let right = code(&ctx, &kr, &kc, &nr, &nc).unwrap();
    assert_ne!(code(&ctx, &kc, &kr, &nc, &nr).unwrap(), right);
    assert_ne!(code(&ctx, &kc, &kr, &nr, &nc).unwrap(), right);
    assert_ne!(code(&ctx, &kr, &kc, &nc, &nr).unwrap(), right);
}

/// SYN-05.4, SYN-05 T10: a value of 417 is shown as `000 417`; the nonce
/// (28 bytes of 0x44 and the u32 1,936,900) was found with Python's hashlib
/// over T02's other values.
#[test]
fn syn05_4_t10_leading_zeros_are_shown() {
    let (ctx, kc, kr, _, nr) = t02();
    let mut nc = [0x44u8; 32];
    nc[28..].copy_from_slice(&1_936_900u32.to_be_bytes());
    let got = code(&ctx, &kr, &kc, &nr, &nc).unwrap();
    assert_eq!((got, shown(got).as_str()), (417, "000 417"));
    assert_eq!(shown(0), "000 000");
    assert_eq!(shown(999_999), "999 999");
}

/// SYN-06.11 with CRY-05.8: the key lists hold exactly the keys of their
/// sizes, read back whole; any other length or a changed length prefix is
/// refused.
#[test]
fn syn06_11_key_lists_and_the_context() {
    let (_, xwing) = xwing_keypair().unwrap();
    let device = [4u8; DEVICE_KEY];
    let kc = keys_c(&device, &xwing).unwrap();
    assert_eq!(kc.len(), KEYS_C);
    assert_eq!(kc, by_hand(&[&device, &xwing]));
    assert_eq!(split_keys_c(&kc), Some((device, xwing.clone())));
    let identity = vec![7u8; IDENTITY_PUBLIC];
    let kr = keys_r(&identity, &device).unwrap();
    assert_eq!(kr.len(), KEYS_R);
    assert_eq!(split_keys_r(&kr), Some((identity.clone(), device)));
    assert!(keys_c(&device, &xwing[1..]).is_err());
    assert!(keys_r(&identity[1..], &device).is_err());
    assert!(split_keys_c(&kr).is_none());
    assert!(split_keys_r(&kc).is_none());
    assert!(split_keys_c(&kc[..KEYS_C - 1]).is_none());
    let mut longer = kc.clone();
    longer.push(0);
    assert!(split_keys_c(&longer).is_none());
    let mut prefix = kc.clone();
    prefix[3] ^= 1;
    assert!(split_keys_c(&prefix).is_none());
    let account = AccountId::from_bytes([1; 16]);
    let approval = Id::from_bytes([2; 16]);
    assert_eq!(
        ctx(&account, &approval).unwrap(),
        by_hand(&[b"sync-approval-v1", &[1; 16], &[2; 16]])
    );
    assert_eq!(
        seal_info(&account, &approval, &device).unwrap(),
        by_hand(&[
            b"sync-wrap-info-v1",
            b"account-secret",
            &[1; 16],
            &[2; 16],
            &device
        ])
    );
    assert_eq!(
        device_message(&account, &device, &approval).unwrap(),
        by_hand(&[b"sync-device-v1", &[1; 16], &device, &[2; 16]])
    );
}

/// SYN-06.11 step 1, ruling (4): the code is shown in groups of 4, read
/// case-blind with spaces and dashes ignored, and sent as
/// `Authorization: Approval` and its 26 characters; the header takes one
/// line, the scheme in any case, and only the canonical upper-case form.
/// The code's SHA-256 is what `POST /v1/approvals` carries.
#[test]
fn syn06_11_the_approval_code_and_its_header() {
    let code = SecretBytes::new((0u8..16).collect());
    let typed = code_shown(&code);
    assert_eq!(typed.expose(), "AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4");
    assert_eq!(
        read_code("aaaq eaye-auda ocaj bifq ydio b4")
            .unwrap()
            .expose(),
        code.expose()
    );
    assert!(read_code("AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B").is_none());
    let header = authorization(&code);
    assert_eq!(header.expose(), "Approval AAAQEAYEAUDAOCAJBIFQYDIOB4");
    let read = |line: &str| approval(&[line.as_bytes()]).map(|c| c.expose().to_vec());
    let text = "AAAQEAYEAUDAOCAJBIFQYDIOB4";
    for good in [
        format!("Approval {text}"),
        format!("approval {text}"),
        format!("APPROVAL   {text} "),
    ] {
        assert_eq!(read(&good), Some(code.expose().to_vec()), "{good}");
    }
    for bad in [
        String::new(),
        "Approval".to_owned(),
        format!("Approval{text}"),
        format!("Bearer {text}"),
        format!("Approval {}", text.to_lowercase()),
        "Approval AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4".to_owned(),
        format!("Approval {}", &text[1..]),
        format!("Approval {text}A"),
        format!("Approval {}5", &text[..25]),
        format!("Approval\t{text}"),
        format!("Approval {text} x"),
    ] {
        assert_eq!(read(&bad), None, "{bad:?}");
    }
    let line = format!("Approval {text}");
    assert!(approval(&[]).is_none());
    assert!(approval(&[line.as_bytes(), line.as_bytes()]).is_none());
    let hash = code_hash(&code).unwrap();
    assert_eq!(
        hash.to_vec(),
        hash::sha256(&[code.expose()]).expose().to_vec()
    );
    let body = ApprovalCreate { code_hash: hash }.to_json();
    assert!(!String::from_utf8_lossy(&body).contains(text));
    assert_eq!(ApprovalCreate::read(&body).unwrap().code_hash, hash);
}

/// SYN-01.8 for E17-S2's records: each reads back as written; a field of
/// another length, a device name SYN-04.2 refuses, a key list of the other
/// side's length and a half-sent pair are refused; unknown fields are
/// ignored.
#[test]
#[allow(clippy::too_many_lines)]
fn syn01_8_approval_records() {
    let id = Id::from_bytes([3; 16]);
    let account = AccountId::from_bytes([5; 16]);
    let start = ApprovalStart {
        approval_id: id,
        expires: 1_800_000_900,
    };
    assert_eq!(ApprovalStart::read(&start.to_json()).unwrap(), start);
    let claim = ApprovalClaim {
        device_public_key: [4; DEVICE_KEY],
        device_name: "Mac".to_owned(),
    };
    assert_eq!(ApprovalClaim::read(&claim.to_json()).unwrap(), claim);
    let bad_name = ApprovalClaim {
        device_name: "a\u{7}".to_owned(),
        ..claim.clone()
    };
    assert!(ApprovalClaim::read(&bad_name.to_json()).is_err());
    let claimed = ApprovalClaimed {
        approval_id: id,
        account_id: account,
        expires: 9,
    };
    assert_eq!(ApprovalClaimed::read(&claimed.to_json()).unwrap(), claimed);
    let commit = CompareCommit { commit: [6; 32] };
    assert_eq!(CompareCommit::read(&commit.to_json()).unwrap(), commit);
    assert!(CompareCommit::read(br#"{"commit":"AAAA"}"#).is_err());
    let keys = CompareKeys {
        keys: vec![7; KEYS_R],
        nonce: [8; 32],
    };
    assert_eq!(CompareKeys::read(&keys.to_json(), KEYS_R).unwrap(), keys);
    assert!(CompareKeys::read(&keys.to_json(), KEYS_C).is_err());
    let reveal = CompareReveal {
        keys: vec![9; KEYS_C],
        nonce: [10; 32],
    };
    assert_eq!(
        CompareReveal::read(&reveal.to_json(), KEYS_C).unwrap(),
        reveal
    );
    let mut extra = reveal.to_json();
    extra.pop();
    extra.extend_from_slice(br#","x":1}"#);
    assert_eq!(CompareReveal::read(&extra, KEYS_C).unwrap(), reveal);

    let (_, xwing) = xwing_keypair().unwrap();
    let (identity, _) = larsal_crypto::pq::identity_keypair().unwrap();
    let record =
        larsal_crypto::wrap_record::make(&xwing, b"info", &[1; 32], [5; 16], &identity).unwrap();
    let seal = ApprovalSeal {
        seal: record.clone(),
        device_signature: vec![11; SIGNATURE],
    };
    let bytes = seal.to_json();
    assert!(bytes.len() <= MAX_WRAP, "{}", bytes.len());
    assert_eq!(ApprovalSeal::read(&bytes).unwrap(), seal);
    assert_eq!(
        wire::read(&bytes).unwrap(),
        record,
        "the wrap record's fields"
    );
    let short = ApprovalSeal {
        device_signature: vec![11; SIGNATURE - 1],
        ..seal.clone()
    };
    assert!(ApprovalSeal::read(&short.to_json()).is_err());
    assert!(
        ApprovalSeal::read(&wire::to_json(&record)).is_err(),
        "no device signature"
    );

    let empty = ApprovalState {
        expires: 5,
        ..ApprovalState::default()
    };
    let text = String::from_utf8(empty.to_json()).unwrap();
    assert!(
        text.contains(r#""commit":"""#) && text.contains(r#""seal":"""#),
        "{text}"
    );
    assert_eq!(ApprovalState::read(text.as_bytes()).unwrap(), empty);
    let full = ApprovalState {
        device_public_key: Some([4; DEVICE_KEY]),
        device_name: Some("Mac".to_owned()),
        commit: Some([6; 32]),
        keys_r: Some((vec![7; KEYS_R], [8; 32])),
        keys_c: Some((vec![9; KEYS_C], [10; 32])),
        seal: Some((wire::to_json(&record), DeviceId::from_bytes([12; 16]))),
        expires: 7,
    };
    assert_eq!(ApprovalState::read(&full.to_json()).unwrap(), full);
    let half = text.replace(
        r#""nonce_r":"""#,
        &format!(r#""nonce_r":"{}""#, base64::encode(Form::Url, &[1; 32])),
    );
    assert!(
        ApprovalState::read(half.as_bytes()).is_err(),
        "n_R without K_R"
    );
    let short_keys = text
        .replace(
            r#""keys_c":"""#,
            &format!(
                r#""keys_c":"{}""#,
                base64::encode(Form::Url, &[1; KEYS_C - 1])
            ),
        )
        .replace(
            r#""nonce_c":"""#,
            &format!(r#""nonce_c":"{}""#, base64::encode(Form::Url, &[1; 32])),
        );
    assert!(ApprovalState::read(short_keys.as_bytes()).is_err());
    let debug = format!("{full:?}");
    assert!(
        !debug.contains("[6, 6") && debug.contains("sealed: true"),
        "{debug}"
    );
    assert_eq!(record.enc.len(), ENC);
}
