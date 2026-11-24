//! E0-S7 R5: Larsal's base64 (`larsal_crypto::base64`, LD-258 (2)): the RFC 4648
//! section 10 known answers, the three forms, bad input and a round trip.

use larsal_crypto::Error;
use larsal_crypto::base64::{Form, decode, decode_secret, encode, encode_secret};
use proptest::prelude::*;

const FORMS: [Form; 3] = [Form::Padded, Form::PaddingOptional, Form::Url];

/// RFC 4648 section 10, standard alphabet with padding.
const RFC: [(&str, &str); 7] = [
    ("", ""),
    ("f", "Zg=="),
    ("fo", "Zm8="),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="),
    ("foobar", "Zm9vYmFy"),
];

fn ok(form: Form, text: &str) -> Vec<u8> {
    let plain = decode(form, text).unwrap();
    assert_eq!(decode_secret(form, text).unwrap().expose(), plain, "{text}");
    plain
}

fn bad(form: Form, text: &[u8]) {
    assert_eq!(decode(form, text), Err(Error::Base64), "{form:?} {text:?}");
    assert!(decode_secret(form, text).is_err(), "{form:?} {text:?}");
}

#[test]
fn r5_rfc4648_known_answers() {
    for (plain, text) in RFC {
        for form in [Form::Padded, Form::PaddingOptional] {
            assert_eq!(encode(form, plain.as_bytes()), text);
            assert_eq!(encode_secret(form, plain.as_bytes()).expose(), text);
            assert_eq!(ok(form, text), plain.as_bytes(), "{form:?}");
        }
        let url = text.trim_end_matches('=');
        assert_eq!(encode(Form::Url, plain.as_bytes()), url);
        assert_eq!(encode_secret(Form::Url, plain.as_bytes()).expose(), url);
        assert_eq!(ok(Form::Url, url), plain.as_bytes());
        assert_eq!(ok(Form::Url, text), plain.as_bytes());
    }
}

#[test]
fn r5_padded_needs_the_padding_and_ignores_unused_bits() {
    for text in ["Zg", "Zg=", "Zm8", "Zg===", "Zm8==", "Zm9v=", "Zm9v===="] {
        bad(Form::Padded, text.as_bytes());
    }
    // FMT-18.12: the low bits after the last byte are not checked.
    assert_eq!(ok(Form::Padded, "QR=="), b"A");
    assert_eq!(ok(Form::Padded, "QUJ="), b"AB");
    assert_eq!(ok(Form::Padded, "QUI="), b"AB");
}

#[test]
fn r5_padding_optional_reads_unpadded_text_and_checks_unused_bits() {
    for (text, want) in [
        ("Zg", &b"f"[..]),
        ("Zg=", b"f"),
        ("Zg==", b"f"),
        ("Zm8", b"fo"),
        ("Zm8=", b"fo"),
    ] {
        assert_eq!(ok(Form::PaddingOptional, text), want, "{text}");
    }
    assert_eq!(ok(Form::PaddingOptional, "Zm9vYg"), b"foob");
    assert_eq!(ok(Form::PaddingOptional, "Zm9vYmE"), b"fooba");
    for text in ["Zg===", "Zm8==", "Zm9v=", "QR==", "QR", "QUJ", "QUJ="] {
        bad(Form::PaddingOptional, text.as_bytes());
    }
}

#[test]
fn r5_url_uses_its_own_alphabet() {
    let bytes = [0xFB, 0xEF, 0xBE, 0xFF];
    assert_eq!(encode(Form::Url, &bytes), "----_w");
    assert_eq!(encode(Form::Padded, &bytes), "++++/w==");
    assert_eq!(ok(Form::Url, "----_w"), bytes);
    assert_eq!(ok(Form::Url, "----_w=="), bytes);
    assert_eq!(ok(Form::Padded, "++++/w=="), bytes);
    bad(Form::Url, b"++++/w");
    bad(Form::PaddingOptional, b"----_w");
    bad(Form::Padded, b"----_w==");
}

#[test]
fn r5_bad_input_is_an_error_in_every_form() {
    let cases: [&[u8]; 13] = [
        b"Z",
        b"Zm9vY",
        b"Zm 9v",
        b"Zm9v\n",
        b" Zm9v",
        b"Zm9v\0",
        b"Zg==Zg==",
        b"Z=g=",
        b"=Zg=",
        b"====",
        b"Zm9v\xC3\xA9",
        b"Zm9.",
        b"Zm9v*A==",
    ];
    for form in FORMS {
        for text in cases {
            bad(form, text);
        }
    }
    assert_eq!(Error::Base64.to_string(), "invalid base64 text");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn r5_round_trip_in_every_form(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        for form in FORMS {
            let text = encode(form, &bytes);
            let secret = encode_secret(form, &bytes);
            prop_assert_eq!(secret.expose(), text.as_str());
            prop_assert_eq!(decode(form, &text).unwrap(), bytes.clone());
            let back = decode_secret(form, &text).unwrap();
            prop_assert_eq!(back.expose(), &bytes[..]);
        }
        let padded = encode(Form::Padded, &bytes);
        let bare = padded.trim_end_matches('=');
        prop_assert_eq!(decode(Form::PaddingOptional, bare).unwrap(), bytes.clone());
        prop_assert_eq!(encode(Form::Url, &bytes), bare.replace('+', "-").replace('/', "_"));
    }

    #[test]
    fn r5_any_text_gives_bytes_or_an_error(text in proptest::collection::vec(any::<u8>(), 0..64)) {
        for form in FORMS {
            match decode(form, &text) {
                Ok(bytes) => {
                    let back = decode_secret(form, &text).unwrap();
                    prop_assert_eq!(back.expose(), &bytes[..]);
                    prop_assert!(bytes.len() <= text.len() * 3 / 4);
                }
                Err(e) => {
                    prop_assert_eq!(e, Error::Base64);
                    prop_assert!(decode_secret(form, &text).is_err());
                }
            }
        }
    }
}
