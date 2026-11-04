//! E5-S6: the generator through the session's exports (FEA-02, FEA-03,
//! FEA-05.8, APP-03 `copy.generated`), on a copy of the Option A Personal
//! demo vault (password in testdata/README.md). Every session copies to its
//! own private pasteboard, never the user's clipboard. Each test names its
//! card rule.

use larsal_core::generator::wordlist;
use larsal_core::health::{bits_with, zxcvbn_bits};
use larsal_ffi::generator::{GeneratorOptions, WordCase};
use larsal_ffi::session::{LarsalError, Session, UnlockResult};
use std::path::PathBuf;
use std::sync::Arc;

const SPECIAL: &str = "()[]{},.:;\"'-/\\_!*+<=>?#$%&@^`~";
const LOOKALIKES: &str = "lBGIO0168|";

/// A fresh copy of the Personal vault, opened and unlocked.
fn personal(name: &str) -> (Arc<Session>, u64) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("generator-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.larsalvault"));
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault"),
        &path,
    )
    .unwrap();
    let session = Session::new();
    let id = session.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        session.unlock(id, Some("demo-pass-7".into()), None),
        Ok(UnlockResult::Unlocked)
    );
    (session, id)
}

fn phrase(words: u32, separator: &str, case: WordCase) -> GeneratorOptions {
    GeneratorOptions {
        passphrase: true,
        words,
        separator: separator.to_owned(),
        case,
        ..GeneratorOptions::default()
    }
}

/// The pasteboard's text (one item, both markers), as clipboard.rs reads it.
fn pasted(session: &Session) -> Option<String> {
    let items = session.clipboard().peek();
    let item = items.first()?;
    let mut types: Vec<&str> = item.iter().map(|(k, _)| k.as_str()).collect();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "org.nspasteboard.ConcealedType",
            "org.nspasteboard.TransientType",
            "public.utf8-plain-text"
        ]
    );
    let (_, text) = item.iter().find(|(k, _)| k == "public.utf8-plain-text")?;
    Some(String::from_utf8(text.clone()).unwrap())
}

/// FEA-02.11, FEA-02.12 (Larsal simple view), FEA-05.8: the defaults make 20
/// characters with one of each type and no look-alike, rated by FEA-05.
#[test]
fn fea_02_11_defaults() {
    let s = Session::new();
    let o = s.generator_options(None);
    assert_eq!(o, GeneratorOptions::default());
    assert_eq!(
        (o.length, o.upper, o.lower, o.digits, o.special, o.extended),
        (20, true, true, true, true, false)
    );
    assert!(o.exclude_lookalike && o.every_group && !o.passphrase);
    assert_eq!(
        (o.words, o.separator.as_str(), o.case),
        (7, " ", WordCase::Lower)
    );
    for _ in 0..200 {
        let g = s.generate(o.clone());
        assert_eq!(g.problem, None);
        let v = &g.value;
        assert_eq!(v.chars().count(), 20);
        assert!(v.chars().any(|c| c.is_ascii_uppercase()), "{v}");
        assert!(v.chars().any(|c| c.is_ascii_lowercase()), "{v}");
        assert!(v.chars().any(|c| c.is_ascii_digit()), "{v}");
        assert!(v.chars().any(|c| SPECIAL.contains(c)), "{v}");
        assert!(!v.chars().any(|c| LOOKALIKES.contains(c)), "{v}");
        let bits = bits_with(&zxcvbn_bits, v, &[]);
        assert_eq!(g.rating.bits, bits.round() as u32);
        assert_eq!(g.rating.chars, 20);
    }
}

/// FEA-02.1 classes through the chips: each chip alone draws only its set;
/// extended without U+0080 to U+00A0, U+00AD and (look-alike on) U+00B7.
#[test]
fn fea_02_1_chips() {
    let s = Session::new();
    let none = GeneratorOptions {
        upper: false,
        lower: false,
        digits: false,
        special: false,
        length: 200,
        ..GeneratorOptions::default()
    };
    type Check = fn(char) -> bool;
    let cases: [(GeneratorOptions, Check); 5] = [
        (
            GeneratorOptions {
                upper: true,
                ..none.clone()
            },
            |c| c.is_ascii_uppercase(),
        ),
        (
            GeneratorOptions {
                lower: true,
                ..none.clone()
            },
            |c| c.is_ascii_lowercase(),
        ),
        (
            GeneratorOptions {
                digits: true,
                ..none.clone()
            },
            |c| c.is_ascii_digit(),
        ),
        (
            GeneratorOptions {
                special: true,
                ..none.clone()
            },
            |c| SPECIAL.contains(c),
        ),
        (
            GeneratorOptions {
                extended: true,
                ..none.clone()
            },
            |c| ('\u{a1}'..='\u{ff}').contains(&c) && c != '\u{ad}' && c != '\u{b7}',
        ),
    ];
    for (o, ok) in cases {
        let g = s.generate(o);
        assert_eq!(g.problem, None);
        assert!(g.value.chars().all(ok), "{}", g.value);
        assert_eq!(g.value.chars().count(), 200);
    }
}

/// D-02-3 (b), FEA-02.5: invalid options give no value, the reason, and
/// nothing to copy or use.
#[test]
fn d_02_3_invalid_options() {
    let (s, v) = personal("invalid");
    s.begin_new(v, None).unwrap();
    let none = GeneratorOptions {
        upper: false,
        lower: false,
        digits: false,
        special: false,
        ..GeneratorOptions::default()
    };
    let g = s.generate(none);
    assert_eq!(g.value, "");
    assert_eq!(
        g.problem.as_deref(),
        Some("Choose at least one character type.")
    );
    assert_eq!(
        (g.rating.bits, g.rating.chars, g.rating.level.as_str()),
        (0, 0, "Poor")
    );
    let short = GeneratorOptions {
        digits: false,
        special: false,
        length: 1,
        ..GeneratorOptions::default()
    };
    assert_eq!(
        s.generate(short).problem.as_deref(),
        Some("A character of every chosen type needs a length of at least 2.")
    );
    for length in [0, 1000] {
        let o = GeneratorOptions {
            length,
            ..GeneratorOptions::default()
        };
        assert_eq!(
            s.generate(o).problem.as_deref(),
            Some("Choose a length from 1 to 999.")
        );
    }
    for words in [0, 101] {
        assert_eq!(
            s.generate(phrase(words, " ", WordCase::Lower))
                .problem
                .as_deref(),
            Some("Choose from 1 to 100 words.")
        );
    }
    let copied = s.copy_generated().unwrap();
    assert!(copied.empty && copied.seconds == 0);
    assert_eq!(pasted(&s), None);
    assert!(matches!(s.use_generated(v), Err(LarsalError::Refused(_))));
    assert_eq!(s.draft_password(v).unwrap(), "");
}

/// FEA-03.4, FEA-03.5, FEA-03.7 bands (built-in list): the separator only
/// between words, the case, and the formula's bits and level.
#[test]
fn fea_03_7_passphrases() {
    let s = Session::new();
    let list: Vec<&str> = wordlist::builtin().words().collect();
    for (words, bits, level) in [
        (3, 39, "Poor"),
        (5, 65, "Weak"),
        (6, 78, "Good"),
        (7, 90, "Good"),
        (8, 103, "Excellent"),
    ] {
        let g = s.generate(phrase(words, "_", WordCase::Lower));
        assert_eq!(g.problem, None);
        let parts: Vec<&str> = g.value.split('_').collect();
        assert_eq!(parts.len(), words as usize, "{}", g.value);
        assert!(parts.iter().all(|w| list.contains(w)), "{}", g.value);
        assert_eq!((g.rating.bits, g.rating.level.as_str()), (bits, level));
        assert_eq!(g.rating.chars as usize, g.value.chars().count());
    }
    // The mockup's frame: 5 words with "-"; Weak by the card (64.62 bits).
    let g = s.generate(phrase(5, "-", WordCase::Lower));
    assert_eq!((g.rating.bits, g.rating.level.as_str()), (65, "Weak"));
    let g = s.generate(phrase(4, " ", WordCase::Title));
    assert!(
        g.value
            .split(' ')
            .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase())),
        "{}",
        g.value
    );
    let g = s.generate(phrase(4, ".", WordCase::Upper));
    assert_eq!(g.value, g.value.to_uppercase());
    assert_eq!(g.value.matches('.').count(), 3);
}

/// FEA-02.20, APP-03.8, APP-03.21: Copy puts the value Rust holds on the
/// (private) pasteboard with both markers; Swift gets the label and seconds.
#[test]
fn fea_02_20_copy() {
    let s = Session::new();
    let g = s.generate(GeneratorOptions::default());
    let copied = s.copy_generated().unwrap();
    assert_eq!(
        (copied.label.as_str(), copied.seconds, copied.empty),
        ("Password", 10, false)
    );
    assert!(!format!("{copied:?}").contains(&g.value));
    assert_eq!(pasted(&s).as_deref(), Some(g.value.as_str()));
    // A new value replaces the old one: Copy takes the new one.
    let next = s.generate(phrase(5, "-", WordCase::Lower));
    s.copy_generated().unwrap();
    assert_eq!(pasted(&s).as_deref(), Some(next.value.as_str()));
}

/// FEA-02.16, FEA-02.17 Apply, D-03-7: Use fills the editor's password with
/// the value as shown, the user's edit included; an edit is rated by
/// FEA-05's estimate, also on the Passphrase tab.
#[test]
fn fea_02_16_use_and_edit() {
    let (s, v) = personal("use");
    s.begin_new(v, None).unwrap();
    let g = s.generate(GeneratorOptions::default());
    assert_eq!(s.use_generated(v).unwrap(), 20);
    assert_eq!(s.draft_password(v).unwrap(), g.value);
    let rating = s.edit_generated("demo-pass-42".to_owned()).unwrap();
    assert_eq!(
        rating.bits,
        bits_with(&zxcvbn_bits, "demo-pass-42", &[]).round() as u32
    );
    assert_eq!(s.use_generated(v).unwrap(), 12);
    assert_eq!(s.draft_password(v).unwrap(), "demo-pass-42");
    let _ = s.generate(phrase(7, " ", WordCase::Lower));
    let demo = s.edit_generated("demo".to_owned()).unwrap();
    assert_eq!(
        demo.bits,
        bits_with(&zxcvbn_bits, "demo", &[]).round() as u32
    );
    assert_eq!(demo.level, "Poor");
    assert!(matches!(
        s.edit_generated("x".repeat(64 * 1024 + 1)),
        Err(LarsalError::TooLong)
    ));
    s.cancel_edit(v).unwrap();
    assert!(matches!(s.use_generated(v), Err(LarsalError::Refused(_))));
}

/// FEA-02.17: the popup on a password field starts at the field's length
/// (at most 999), else the saved length.
#[test]
fn fea_02_17_start_length() {
    let (s, v) = personal("start");
    s.begin_new(v, None).unwrap();
    assert_eq!(s.generator_options(Some(v)).length, 20);
    s.set_password(v, "abcdefghijkl".to_owned()).unwrap();
    assert_eq!(s.generator_options(Some(v)).length, 12);
    s.set_password(v, "y".repeat(1500)).unwrap();
    assert_eq!(s.generator_options(Some(v)).length, 999);
    // The window's generator is not tied to a field.
    assert_eq!(s.generator_options(None).length, 20);
}

/// FEA-02.18, FEA-03.15: options are saved on Apply and when the window's
/// generator closes; a popup closed without Apply keeps the saved ones.
#[test]
fn fea_02_18_saving() {
    let s = Session::new();
    let o = GeneratorOptions {
        length: 24,
        ..GeneratorOptions::default()
    };
    s.close_generator(Some(o));
    assert_eq!(s.generator_options(None).length, 24);
    s.close_generator(None);
    assert_eq!(s.generator_options(None).length, 24);
    s.close_generator(Some(phrase(9, " ", WordCase::Lower)));
    let back = s.generator_options(None);
    assert!(back.passphrase && back.words == 9);
}

/// FEA-02.23, D-02-5: closing the generator, a lock, lock-all and close
/// drop the value; Copy then copies nothing.
#[test]
fn d_02_5_value_dropped() {
    let (s, v) = personal("dropped");
    let empty = |s: &Session| s.copy_generated().unwrap().empty;
    let _ = s.generate(GeneratorOptions::default());
    s.close_generator(None);
    assert!(empty(&s));
    let _ = s.generate(GeneratorOptions::default());
    s.lock(v).unwrap();
    assert!(empty(&s));
    let _ = s.generate(GeneratorOptions::default());
    s.lock_all();
    assert!(empty(&s));
    let _ = s.generate(GeneratorOptions::default());
    s.close(v).unwrap();
    assert!(empty(&s));
}

/// FEA-02.16 (Checker 1, finding 1): a refused edit (over 64 KiB) drops the
/// value too, so Copy and Use never act on a value no longer shown.
#[test]
fn fea_02_16_refused_edit_drops_the_value() {
    let (s, v) = personal("refused");
    s.begin_new(v, None).unwrap();
    let _ = s.generate(GeneratorOptions::default());
    assert!(matches!(
        s.edit_generated("x".repeat(64 * 1024 + 1)),
        Err(LarsalError::TooLong)
    ));
    let copied = s.copy_generated().unwrap();
    assert!(copied.empty && copied.seconds == 0);
    assert_eq!(pasted(&s), None, "nothing on the private pasteboard");
    assert!(matches!(s.use_generated(v), Err(LarsalError::Refused(_))));
    assert_eq!(s.draft_password(v).unwrap(), "");
}

/// D-03-5, AT-E03 (Checker 1, finding 2): options with a separator over 64
/// characters are neither saved nor made; the saved options stay.
#[test]
fn d_03_5_oversized_separator_is_not_saved() {
    let s = Session::new();
    s.close_generator(Some(phrase(9, "-", WordCase::Lower)));
    let huge = "-".repeat(10 * 1024 * 1024);
    s.close_generator(Some(phrase(4, &huge, WordCase::Upper)));
    let back = s.generator_options(None);
    assert_eq!((back.words, back.separator.as_str()), (9, "-"));
    // The save filter's edge: 65 is not saved, 64 is (Verify M10).
    s.close_generator(Some(phrase(4, &"#".repeat(65), WordCase::Upper)));
    assert_eq!(s.generator_options(None).separator, "-");
    s.close_generator(Some(phrase(4, &"#".repeat(64), WordCase::Upper)));
    assert_eq!(s.generator_options(None).separator, "#".repeat(64));
    let g = s.generate(phrase(4, &"#".repeat(65), WordCase::Lower));
    assert_eq!(
        g.problem.as_deref(),
        Some("The separator can have at most 64 characters.")
    );
    assert_eq!(g.value, "");
    // 64 is still allowed.
    assert_eq!(
        s.generate(phrase(2, &"#".repeat(64), WordCase::Lower))
            .problem,
        None
    );
}

/// Rust rule 3 (Checker 1, advisory): `Generated`'s `Debug` never prints
/// the value.
#[test]
fn rule_3_generated_debug_hides_the_value() {
    let s = Session::new();
    let g = s.generate(GeneratorOptions::default());
    let text = format!("{g:?}");
    assert!(!g.value.is_empty() && !text.contains(&g.value), "{text}");
    assert!(text.contains("<hidden>") && text.contains(&g.rating.level));
}
