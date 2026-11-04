//! Fuzz target `strength_estimate` (E4-S11, LD-134 (2)): any password and
//! up to 3 user inputs, text of any length, through health's estimate with
//! the 256-character cap (`bits_with`) and through the entry path that
//! takes title, user name and URL host as user inputs (`entry_bits`).
//! Must never panic or hang; E is finite and never negative. The
//! wall-time guard is only for real hangs (LD-137 (3), as LD-126 (2)): one
//! estimate takes up to about 430 ms in release (l33t-heavy text of 100
//! characters), and the sanitizer build runs about 50 times slower. The
//! seed `slow-unit` is the Checker's slowest unit (3.2 to 3.7 s here).
//!
//! Input (made with `arbitrary`'s `Unstructured`): a byte whose value mod 4
//! is the number of inputs and whose bit 2 picks the entry path; each input
//! a 2-byte little-endian length and that many bytes; the password the
//! rest. Bytes become text with U+FFFD for invalid UTF-8, so every input is
//! used. One path per input keeps it to one crate call.
#![no_main]

use app_core::health::{bits_with, entry_bits, zxcvbn_bits};
use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Time, Uuid};
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct Case {
    password: String,
    inputs: Vec<String>,
    entry_path: bool,
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let head = u8::arbitrary(u)?;
        let n = head % 4;
        let mut inputs = Vec::new();
        for _ in 0..n {
            let len = usize::from(u16::from_le_bytes([u8::arbitrary(u)?, u8::arbitrary(u)?]));
            let bytes = u.bytes(len.min(u.len()))?;
            inputs.push(String::from_utf8_lossy(bytes).into_owned());
        }
        let rest = u.bytes(u.len())?;
        Ok(Case {
            password: String::from_utf8_lossy(rest).into_owned(),
            inputs,
            entry_path: head & 4 != 0,
        })
    }
}

fuzz_target!(|case: Case| {
    let started = std::time::Instant::now();
    let e = if case.entry_path {
        let mut entry = Entry::new(Uuid([7; 16]), Time(63_900_000_000));
        for (name, value) in ["Title", "UserName", "URL"].iter().zip(&case.inputs) {
            entry.set_field(
                (*name).to_owned(),
                Field {
                    value: SecretString::new(value.clone()),
                    protected: false,
                },
            );
        }
        entry_bits(&case.password, &entry)
    } else {
        let inputs: Vec<&str> = case.inputs.iter().map(String::as_str).collect();
        bits_with(&zxcvbn_bits, &case.password, &inputs)
    };
    assert!(e.is_finite() && e >= 0.0, "{e}");
    assert!(started.elapsed().as_secs() < 30, "an estimate hung");
});
