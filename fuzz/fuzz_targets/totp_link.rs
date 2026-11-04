//! Fuzz target `totp_link` (E4-S10): one-time password settings (FEA-04)
//! from arbitrary storage forms: `otpauth://` links, key-query text, the
//! legacy pair and the four read-only fields. Must never panic, hang or
//! allocate by a hostile number (FEA-04 security notes). Valid settings
//! give a code of exactly `digits` characters (at most 10), and their form
//! U text reads back as the same settings and key.
//!
//! Input: a presence byte (one bit per field below), then the field values
//! separated by byte 0x1E, in this order: `otp`, `TOTP Seed`,
//! `TOTP Settings`, the four `TimeOtp-*` fields.
#![no_main]

use larsal_core::totp::{self, FORM_T, OTP, SEED, SETTINGS};
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Time, Uuid};
use libfuzzer_sys::fuzz_target;

fn entry(fields: &[(&str, &str)]) -> Entry {
    let mut e = Entry::new(Uuid([7; 16]), Time(0));
    for (n, v) in fields {
        e.set_field(
            (*n).to_owned(),
            Field {
                value: SecretString::new((*v).to_owned()),
                protected: true,
            },
        );
    }
    e
}

fuzz_target!(|data: &[u8]| {
    let Some((&present, rest)) = data.split_first() else {
        return;
    };
    let names = [
        OTP, SEED, SETTINGS, FORM_T[0], FORM_T[1], FORM_T[2], FORM_T[3],
    ];
    let values: Vec<String> = rest
        .split(|&b| b == 0x1E)
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    let fields: Vec<(&str, &str)> = names
        .iter()
        .enumerate()
        .filter(|(i, _)| present & (1 << i) != 0)
        .map(|(i, n)| (*n, values.get(i).map_or("", String::as_str)))
        .collect();
    let e = entry(&fields);
    let started = std::time::Instant::now();
    if let Some(s) = totp::settings(&e) {
        for unix in [0i64, 59, 1_111_111_109, 20_000_000_000] {
            let now = Time::from_unix(unix).unwrap();
            match s.code(now) {
                Some(code) => {
                    assert!(s.problem().is_none());
                    assert_eq!(code.expose().chars().count(), s.digits as usize);
                    assert!((1..=10).contains(&s.digits));
                    let shown = totp::display(code.expose());
                    assert_eq!(shown.expose().replace(' ', ""), code.expose());
                    let left = s.seconds_left(now).unwrap();
                    assert!((1..=s.period).contains(&left));
                }
                None => assert!(s.problem().is_some()),
            }
        }
        let uri = s.uri("Demo: title", "user@example");
        if s.problem().is_none() {
            let back = totp::settings(&entry(&[(OTP, uri.expose())])).expect("form U reads back");
            assert_eq!(
                (back.digits, back.period, back.algorithm, back.encoder),
                (s.digits, s.period, s.algorithm, s.encoder)
            );
            assert_eq!(back.key().unwrap().expose(), s.key().unwrap().expose());
        }
        let _ = totp::prefill(&e);
    }
    for text in values.iter().take(2) {
        let _ = totp::from_text(text, values.get(1).map_or("", String::as_str));
        if let Ok(Some(secret)) = totp::setup_secret(text) {
            let mut w = e.duplicate(false);
            let setup = totp::prefill(&w);
            totp::write(&mut w, &secret, &setup, "t", "u");
            assert!(totp::settings(&w).is_some_and(|s| s.problem().is_none()));
        }
    }
    assert!(started.elapsed().as_secs() < 2, "too slow");
});
