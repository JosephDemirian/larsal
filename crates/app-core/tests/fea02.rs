//! Story E4-S9, card FEA-02: the password generator; parity rows SG-01 and
//! SG-02. One test per rule (`fea02_NN_…`) with the card's cases inside.
//!
//! Statistical cases use the real OS source and the card's bars at
//! α = 10^-6. The scripted cases (FEA-02.1, .6, .7, .8 "scripted") are unit
//! tests in `src/generator/password.rs`: the scripted source exists only
//! there, never in the public API (AT-B04).
//!
//! Screen-only rules belong to E5-S6: live regeneration (FEA-02.14), the
//! editable output (FEA-02.16), saving settings (FEA-02.18), Copy
//! (FEA-02.20). The strength number of FEA-02.15 is FEA-05's estimate
//! (E4-S11); its level bands are tested here.

use app_core::generator::password::{
    self, Class, Error, Invalid, MAX_LENGTH, Options, SCREEN_MAX_LENGTH, generate,
};
use app_core::generator::{Level, level};
use std::collections::{BTreeMap, BTreeSet};

fn opts(classes: &[Class], length: u32) -> Options {
    Options {
        length,
        classes: classes.to_vec(),
        extra: String::new(),
        excluded: String::new(),
        exclude_lookalike: false,
        every_group: false,
    }
}

fn gen_text(o: &Options) -> String {
    generate(o).unwrap().expose().to_owned()
}

/// The card's long single passwords (50,000, 270,000 characters) are over
/// D-02-4's core limit of 10,000: with every group off the characters are
/// independent, so passwords of at most 10,000 joined are the same draw.
fn gen_long(o: &Options, total: u32) -> String {
    assert!(!o.every_group);
    let mut out = String::new();
    let mut left = total;
    while left > 0 {
        let part = Options {
            length: left.min(MAX_LENGTH),
            ..o.clone()
        };
        out.push_str(&gen_text(&part));
        left -= part.length;
    }
    out
}

fn counts<'a>(texts: impl IntoIterator<Item = &'a str>) -> BTreeMap<char, u64> {
    let mut m = BTreeMap::new();
    for t in texts {
        for c in t.chars() {
            *m.entry(c).or_insert(0) += 1;
        }
    }
    m
}

fn chi_square(counts: &BTreeMap<char, u64>, cells: usize) -> f64 {
    let total: u64 = counts.values().sum();
    let expected = total as f64 / cells as f64;
    let seen: f64 = counts
        .values()
        .map(|&o| (o as f64 - expected).powi(2) / expected)
        .sum();
    // Cells never seen add their full expected value.
    seen + (cells - counts.len()) as f64 * expected
}

fn invalid(o: &Options) -> Option<Invalid> {
    match generate(o) {
        Err(Error::InvalidOptions(i)) => Some(i),
        _ => None,
    }
}

const SYMBOLS32: &str = "()[]{},.:;\"'-/\\_|!*+<=>?#$%&@^`~";

#[test]
fn fea02_01_class_sets_and_order() {
    let want: [(Class, usize); 11] = [
        (Class::Lower, 26),
        (Class::Upper, 26),
        (Class::Digits, 10),
        (Class::Brackets, 6),
        (Class::Punctuation, 4),
        (Class::Quotes, 2),
        (Class::Dashes, 5),
        (Class::Math, 7),
        (Class::Signs, 8),
        (Class::Extended, 94),
        (Class::Special, 32),
    ];
    for (class, n) in want {
        let set: BTreeSet<char> = class.chars().into_iter().collect();
        assert_eq!(set.len(), n, "{class:?}");
        let out = gen_text(&opts(&[class], 2_000));
        assert_eq!(out.chars().count(), 2_000);
        assert!(out.chars().all(|c| set.contains(&c)), "{class:?}");
    }
    // The six symbol classes are the 32 printable non-alphanumerics, in
    // order; with letters and digits all 94 printable ASCII but space.
    assert_eq!(
        Class::Special.chars().into_iter().collect::<String>(),
        SYMBOLS32
    );
    let ascii: BTreeSet<char> = [Class::Lower, Class::Upper, Class::Digits, Class::Special]
        .iter()
        .flat_map(|c| c.chars())
        .collect();
    assert_eq!(ascii, ('!'..='~').collect());
    let ext = Class::Extended.chars();
    assert!(
        ext.iter()
            .all(|c| !('\u{80}'..='\u{a0}').contains(c) && *c != '\u{ad}')
    );
    assert_eq!((ext[0], ext[93]), ('\u{a1}', '\u{ff}'));
}

#[test]
fn fea02_02_lookalike_exclusion() {
    let mut o = opts(
        &[
            Class::Lower,
            Class::Upper,
            Class::Digits,
            Class::Dashes,
            Class::Extended,
        ],
        1,
    );
    o.exclude_lookalike = true;
    let out = gen_long(&o, 50_000);
    for c in ['l', 'B', 'G', 'I', 'O', '0', '1', '6', '8', '|', '\u{b7}'] {
        assert!(!out.contains(c), "{c:?} must be removed");
    }
    for c in ['o', 'S', '5', 'Z', '2', '\u{f9}'] {
        assert!(out.contains(c), "{c:?} must stay (D-02-1)");
    }
    // Group sizes after the exclusion.
    let g = password::groups(&o).unwrap();
    assert_eq!(
        g.iter().map(Vec::len).collect::<Vec<_>>(),
        [25, 22, 6, 4, 93]
    );
    let mut s = opts(&[Class::Special], 1);
    s.exclude_lookalike = true;
    assert_eq!(password::groups(&s).unwrap()[0].len(), 31);
    // The extra group is never filtered by this option.
    let mut e = opts(&[Class::Lower], 5_000);
    e.exclude_lookalike = true;
    e.extra = "l".into();
    assert!(gen_text(&e).contains('l'));
}

#[test]
fn fea02_03_extra_characters() {
    // Deduplicated within extra: equal weights.
    let mut o = opts(&[], 3_000);
    o.extra = "aab".into();
    let c = counts([gen_text(&o).as_str()]);
    assert_eq!(c.keys().copied().collect::<String>(), "ab");
    assert!(
        c[&'a'].abs_diff(1_500) <= 134 && c[&'b'].abs_diff(1_500) <= 134,
        "{c:?}"
    );
    // A character in a class and in extra has double weight.
    let mut d = opts(&[Class::Lower], 1);
    d.extra = "a".into();
    let c = counts([gen_long(&d, 270_000).as_str()]);
    assert!(c[&'a'].abs_diff(20_000) <= 666, "a: {}", c[&'a']);
    assert!(c[&'b'].abs_diff(10_000) <= 480, "b: {}", c[&'b']);
    // Extra alone.
    let mut x = opts(&[], 2_000);
    x.extra = "abc".into();
    assert!(gen_text(&x).chars().all(|c| "abc".contains(c)));
    // The extra group is added even when its characters are in a class.
    let mut dup = opts(&[Class::Digits], 4);
    dup.extra = "12".into();
    assert_eq!(password::groups(&dup).unwrap().len(), 2);
}

#[test]
fn fea02_04_excluded_characters() {
    let mut o = opts(&[Class::Lower, Class::Upper], 1);
    o.excluded = "xyzXYZ".into();
    let out = gen_long(&o, 20_000);
    assert!(!out.chars().any(|c| "xyzXYZ".contains(c)));
    // Excluded wins over extra.
    let mut e = opts(&[Class::Digits], 5_000);
    e.extra = "#".into();
    e.excluded = "#5".into();
    let out = gen_text(&e);
    assert!(!out.contains('#') && !out.contains('5'));
    // Repeats change nothing; an emptied group is dropped.
    let mut r = opts(&[Class::Digits, Class::Lower], 4);
    r.excluded = "00112233445566778899".into();
    assert_eq!(password::groups(&r).unwrap().len(), 1);
}

#[test]
fn fea02_05_validity_checks_in_order() {
    assert_eq!(invalid(&opts(&[], 32)), Some(Invalid::NoCharacters));
    let mut all = opts(&[Class::Digits], 32);
    all.excluded = "0123456789".into();
    assert_eq!(invalid(&all), Some(Invalid::NoCharacters));
    let mut short = opts(&[Class::Lower, Class::Upper], 1);
    short.every_group = true;
    assert_eq!(invalid(&short), Some(Invalid::TooShortForEveryGroup(2)));
    // An emptied group does not count.
    let mut two = opts(&[Class::Lower, Class::Upper, Class::Digits], 2);
    two.every_group = true;
    two.excluded = "0123456789".into();
    for _ in 0..50 {
        let p = gen_text(&two);
        assert!(
            p.chars().any(|c| c.is_ascii_lowercase()) && p.chars().any(|c| c.is_ascii_uppercase())
        );
    }
    // The extra group counts.
    let mut extra = opts(&[Class::Lower, Class::Upper, Class::Digits], 3);
    extra.every_group = true;
    extra.extra = "012345".into();
    assert_eq!(invalid(&extra), Some(Invalid::TooShortForEveryGroup(4)));
    extra.length = 4;
    assert!(generate(&extra).is_ok());
    // Length first: 0 beats no characters.
    let zero = Options {
        length: 0,
        ..Options::default()
    };
    assert_eq!(invalid(&zero), Some(Invalid::LengthOutOfRange));
    assert_eq!(invalid(&opts(&[], 0)), Some(Invalid::LengthOutOfRange));
}

#[test]
fn fea02_06_os_source_without_bias() {
    // Real source: values come back; the scripted rejection and fail-closed
    // cases are unit tests (password.rs, app-crypto random.rs).
    let a = gen_text(&Options::fallback());
    let b = gen_text(&Options::fallback());
    assert_eq!(a.chars().count(), 32);
    assert_ne!(a, b, "two draws of 32 characters from 53 never repeat");
}

#[test]
fn fea02_06_no_random_source_outside_app_crypto() {
    // AT-B04: the generator and the rest of app-core call only
    // app_crypto::random.
    let mut dirs = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    ))];
    let mut scanned = 0;
    while let Some(dir) = dirs.pop() {
        for f in std::fs::read_dir(dir).unwrap() {
            let p = f.unwrap().path();
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
            if p.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for banned in [
                "rand::",
                "getrandom",
                "OsRng",
                "thread_rng",
                "SystemTime",
                "rand_core",
            ] {
                assert!(!src.contains(banned), "{}: {banned}", p.display());
            }
            scanned += 1;
        }
    }
    assert!(scanned > 20);
    let toml = include_str!("../Cargo.toml");
    assert!(!toml.contains("rand") && !toml.contains("getrandom"));
}

#[test]
fn fea02_07_uniform_picks() {
    // Digits: 10,000 × 100, chi-square below 44.81 (9 df).
    let o = opts(&[Class::Digits], 100);
    let texts: Vec<String> = (0..10_000).map(|_| gen_text(&o)).collect();
    let c = counts(texts.iter().map(String::as_str));
    let chi = chi_square(&c, 10);
    assert!(chi < 44.81, "digits chi-square {chi}");
    // The full ASCII set: 10,000 × 94, all seen, below 172.75 (93 df).
    let full = opts(
        &[
            Class::Upper,
            Class::Lower,
            Class::Digits,
            Class::Brackets,
            Class::Punctuation,
            Class::Quotes,
            Class::Dashes,
            Class::Math,
            Class::Signs,
        ],
        94,
    );
    let texts: Vec<String> = (0..10_000).map(|_| gen_text(&full)).collect();
    let c = counts(texts.iter().map(String::as_str));
    assert_eq!(c.len(), 94);
    let chi = chi_square(&c, 94);
    assert!(chi < 172.75, "full set chi-square {chi}");
    // Extended with look-alike on: exactly 93 seen, below 171.40 (92 df).
    let mut ext = opts(&[Class::Extended], 93);
    ext.exclude_lookalike = true;
    let texts: Vec<String> = (0..10_000).map(|_| gen_text(&ext)).collect();
    let c = counts(texts.iter().map(String::as_str));
    assert_eq!(c.len(), 93);
    let chi = chi_square(&c, 93);
    assert!(chi < 171.40, "extended chi-square {chi}");
}

#[test]
fn fea02_08_every_group_exact_distribution() {
    // Digits plus `x`, length 2: only digit+x and x+digit, uniform over 20
    // (chi-square below 63.68, 19 df).
    let mut o = opts(&[Class::Digits], 2);
    o.extra = "x".into();
    o.every_group = true;
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    for _ in 0..200_000 {
        *seen.entry(gen_text(&o)).or_insert(0) += 1;
    }
    assert_eq!(seen.len(), 20, "{:?}", seen.keys().collect::<Vec<_>>());
    assert!(
        seen.keys()
            .all(|p| p.contains('x') && p.chars().any(|c| c.is_ascii_digit()))
    );
    let exp = 10_000.0;
    let chi: f64 = seen.values().map(|&v| (v as f64 - exp).powi(2) / exp).sum();
    assert!(chi < 63.68, "chi-square {chi}");
}

#[test]
fn fea02_09_every_group_consequences() {
    // Digits plus `x`, length 3, 330,000: `x` at each position 4/11, two
    // `x` 1/11.
    let mut o = opts(&[Class::Digits], 3);
    o.extra = "x".into();
    o.every_group = true;
    let mut at = [0u64; 3];
    let mut two = 0u64;
    for _ in 0..330_000 {
        let p = gen_text(&o);
        assert!(p.contains('x') && p.chars().any(|c| c.is_ascii_digit()));
        for (i, c) in p.chars().enumerate() {
            if c == 'x' {
                at[i] += 1;
            }
        }
        if p.matches('x').count() == 2 {
            two += 1;
        }
    }
    for (i, n) in at.iter().enumerate() {
        assert!(n.abs_diff(120_000) <= 1_352, "position {i}: {n}");
    }
    assert!(two.abs_diff(30_000) <= 808, "two x: {two}");
    // Small groups are more common: fallback, mean digit count 4.283.
    let f = Options::fallback();
    let total: usize = (0..20_000)
        .map(|_| gen_text(&f).chars().filter(char::is_ascii_digit).count())
        .sum();
    let mean = total as f64 / 20_000.0;
    assert!((mean - 4.283).abs() <= 0.06, "mean digits {mean}");
}

#[test]
fn fea02_10_length_limits() {
    // D-02-4: core 1 to 10,000; the screen field 1 to 999.
    assert_eq!(MAX_LENGTH, 10_000);
    assert_eq!(SCREEN_MAX_LENGTH, 999);
    assert_eq!(
        gen_text(&opts(&[Class::Lower], 10_000)).chars().count(),
        10_000
    );
    assert_eq!(gen_text(&opts(&[Class::Lower], 1)).chars().count(), 1);
    assert_eq!(
        invalid(&opts(&[Class::Lower], 10_001)),
        Some(Invalid::LengthOutOfRange)
    );
    assert_eq!(
        invalid(&opts(&[Class::Lower], u32::MAX)),
        Some(Invalid::LengthOutOfRange)
    );
    // Extra and excluded at most 1,024 characters; control characters are
    // dropped from extra.
    let mut long = opts(&[Class::Lower], 8);
    long.extra = "é".repeat(1_024);
    assert!(generate(&long).is_ok());
    long.extra.push('é');
    assert_eq!(invalid(&long), Some(Invalid::TextTooLong));
    let mut ex = opts(&[Class::Lower], 8);
    ex.excluded = "a".repeat(1_025);
    assert_eq!(invalid(&ex), Some(Invalid::TextTooLong));
    let mut ctl = opts(&[], 8);
    ctl.extra = "\u{0}\u{1f}\u{7f}\u{9f}".into();
    assert_eq!(invalid(&ctl), Some(Invalid::NoCharacters));
    ctl.extra.push('z');
    assert_eq!(gen_text(&ctl), "zzzzzzzz");
}

#[test]
fn fea02_11_defaults() {
    let d = Options::default();
    assert_eq!(d.length, 20);
    for c in [Class::Upper, Class::Lower, Class::Digits, Class::Special] {
        assert!(d.classes.contains(&c));
    }
    assert!(!d.classes.contains(&Class::Extended));
    assert!(d.exclude_lookalike && d.every_group && d.extra.is_empty() && d.excluded.is_empty());
    // App screen pool: 84 characters in 4 groups.
    let g = password::groups(&d).unwrap();
    assert_eq!(g.iter().map(Vec::len).collect::<Vec<_>>(), [25, 22, 6, 31]);
    // Built-in fallback: 32 characters, 53-character pool, 3 groups.
    let f = Options::fallback();
    assert_eq!(f.length, 32);
    let g = password::groups(&f).unwrap();
    assert_eq!(g.iter().map(Vec::len).sum::<usize>(), 53);
    // Command line with no options: 300 × 32 give exactly the 53.
    let cli = Options::command_line(32, &[], None, "", false, false);
    assert_eq!(cli, f);
    let texts: Vec<String> = (0..300).map(|_| gen_text(&cli)).collect();
    for t in &texts {
        assert_eq!(t.chars().count(), 32);
        assert!(t.chars().any(|c| c.is_ascii_lowercase()));
        assert!(t.chars().any(|c| c.is_ascii_uppercase()));
        assert!(t.chars().any(|c| c.is_ascii_digit()));
    }
    let pool: BTreeSet<char> = g.iter().flatten().copied().collect();
    assert_eq!(
        counts(texts.iter().map(String::as_str))
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        pool
    );
}

#[test]
fn fea02_12_app_simple_view() {
    // App defaults, length 4: one lower, upper, digit and symbol each.
    let d = Options {
        length: 4,
        ..Options::default()
    };
    for _ in 0..10_000 {
        let p = gen_text(&d.simple_view());
        assert!(p.chars().any(|c| c.is_ascii_lowercase()), "{p}");
        assert!(p.chars().any(|c| c.is_ascii_uppercase()), "{p}");
        assert!(p.chars().any(|c| c.is_ascii_digit()), "{p}");
        assert!(p.chars().any(|c| SYMBOLS32.contains(c)), "{p}");
        assert!(!p.chars().any(|c| "lBGIO0168|".contains(c)), "{p}");
    }
    // Hidden advanced options are not applied.
    let mut adv = Options {
        extra: "€".into(),
        excluded: "a".into(),
        length: 50,
        ..Options::default()
    };
    adv.classes.push(Class::Brackets);
    let simple = adv.simple_view();
    assert!(!simple.classes.contains(&Class::Brackets));
    let out: String = (0..2_000).map(|_| gen_text(&simple)).collect();
    assert!(!out.contains('€') && out.contains('a'));
}

#[test]
fn fea02_13_hex_preset() {
    // D-02-6: exactly `0-9 A-F`, extra cleared, look-alike off.
    let mut o = Options {
        extra: "xyz".into(),
        ..Options::default()
    };
    o.hex();
    assert!(o.extra.is_empty() && !o.exclude_lookalike);
    o.length = 2_000;
    let seen: BTreeSet<char> = gen_text(&o).chars().collect();
    assert_eq!(seen, "0123456789ABCDEF".chars().collect());
}

#[test]
fn fea02_15_strength_levels() {
    // FEA-02.15 bands (FEA-05.4 levels); the bits are E4-S11's estimate.
    for (bits, want) in [
        (0.0, Level::Bad),
        (0.99, Level::Bad),
        (1.0, Level::Poor),
        (39.99, Level::Poor),
        (40.0, Level::Weak),
        (74.99, Level::Weak),
        (75.0, Level::Good),
        (99.99, Level::Good),
        (100.0, Level::Excellent),
        (200.0, Level::Excellent),
        (f64::NAN, Level::Bad),
    ] {
        assert_eq!(level(bits), want, "{bits}");
    }
}

#[test]
fn fea02_17_popup_start_length() {
    assert_eq!(password::start_length("abcdefghijkl", 20), 12);
    assert_eq!(password::start_length("", 20), 20);
    assert_eq!(password::start_length(&"x".repeat(1_500), 20), 999);
    assert_eq!(password::start_length("\u{1f600}é", 20), 2);
}

#[test]
fn fea02_19_new_entry_password() {
    // Saved options valid: they are used.
    let saved = opts(&[Class::Upper], 16);
    let p = password::for_new_entry(&saved).unwrap();
    assert_eq!(p.expose().chars().count(), 16);
    assert!(p.expose().chars().all(|c| c.is_ascii_uppercase()));
    // Invalid saved options: the built-in fallback.
    let pool: BTreeSet<char> = password::groups(&Options::fallback())
        .unwrap()
        .into_iter()
        .flatten()
        .collect();
    for _ in 0..20 {
        let p = password::for_new_entry(&opts(&[], 20)).unwrap();
        let p = p.expose();
        assert_eq!(p.chars().count(), 32);
        assert!(p.chars().all(|c| pool.contains(&c)));
        assert!(
            p.chars().any(|c| c.is_ascii_lowercase()) && p.chars().any(|c| c.is_ascii_uppercase())
        );
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }
}

#[test]
fn fea02_21_command_line_options() {
    // `--exclude-similar -L 1`: valid, every group off.
    let one = Options::command_line(1, &[], None, "", true, false);
    assert!(one.exclude_lookalike && !one.every_group);
    assert_eq!(gen_text(&one).chars().count(), 1);
    // `--every-group -L 1`: invalid (3 groups).
    let every = Options::command_line(1, &[], None, "", false, true);
    assert_eq!(invalid(&every), Some(Invalid::TooShortForEveryGroup(3)));
    // `-c abc -L 10`: custom alone.
    let c = Options::command_line(10, &[], Some("abc"), "", false, false);
    assert!(gen_text(&c).chars().all(|ch| "abc".contains(ch)));
    // `-c ""`: invalid generator.
    let empty = Options::command_line(10, &[], Some(""), "", false, false);
    assert_eq!(invalid(&empty), Some(Invalid::NoCharacters));
    // `-s --every-group -L 6`: one from each of the six symbol classes.
    let six = [
        Class::Brackets,
        Class::Punctuation,
        Class::Quotes,
        Class::Dashes,
        Class::Math,
        Class::Signs,
    ];
    let s = Options::command_line(6, &six, None, "", false, true);
    let mut bar = false;
    for _ in 0..1_000 {
        let p = gen_text(&s);
        for class in six {
            let set = class.chars();
            assert_eq!(p.chars().filter(|c| set.contains(c)).count(), 1, "{p}");
        }
        bar |= p.contains('|');
    }
    assert!(bar, "U+007C appears");
    // `-x`.
    let x = Options::command_line(500, &[Class::Digits], None, "0", false, false);
    assert!(!gen_text(&x).contains('0'));
}

#[test]
fn fea02_22_unicode_scalar_values() {
    let mut o = opts(&[], 1_000);
    o.extra = "\u{1f600}a".into();
    let p = gen_text(&o);
    assert_eq!(p.chars().count(), 1_000);
    assert!(p.chars().all(|c| c == '\u{1f600}' || c == 'a'));
    assert!(p.contains('\u{1f600}'));
    // A combining mark is its own character.
    let mut m = opts(&[], 4);
    m.extra = "e\u{301}".into();
    assert_eq!(password::groups(&m).unwrap()[0].len(), 2);
}

#[test]
fn fea02_23_output_is_a_secret_string() {
    let s: app_crypto::secret::SecretString = generate(&Options::default()).unwrap();
    let debug = format!("{s:?}");
    assert!(!debug.contains(s.expose()), "{debug}");
}
