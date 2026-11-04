//! Story E4-S9, card FEA-03: passphrases and the word list; parity rows
//! SG-01 and SG-03. One test per rule (`fea03_NN_…`) with the card's cases.
//!
//! The scripted cases (FEA-03.4, .5, .8 "order", fail closed) are unit
//! tests in `src/generator/passphrase.rs`. Screen-only rules belong to
//! E5-S6: managing lists in the folder (FEA-03.14), restoring the tab
//! (FEA-03.15); the attribution in About is E14-S2 (owner decision D2).
//! D-03-7 (the estimate of edited text) is FEA-05, E4-S11.

use app_core::generator::passphrase::{self, Case, Error, MAX_WORDS, Options, entropy, generate};
use app_core::generator::wordlist::{self, ListError, MAX_ENTRIES, WordList, builtin, parse};
use app_core::generator::{Level, level};
use std::collections::BTreeMap;

const LIST_A: &str = "alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n";

fn list(text: &str) -> WordList {
    parse(text.as_bytes()).unwrap()
}

fn words(l: &WordList) -> Vec<&str> {
    l.words().collect()
}

fn phrase(o: &Options, l: &WordList) -> String {
    generate(o, l).unwrap().expose().to_owned()
}

fn bits(n: u32, l: &WordList) -> String {
    format!("{:.2}", entropy(n, l))
}

#[test]
fn fea03_01_builtin_list_facts() {
    let l = builtin();
    assert_eq!(l.len(), 7_776);
    assert_eq!((l.get(0), l.get(7_775)), (Some("abacus"), Some("zoom")));
    for w in ["drop-down", "felt-tip", "t-shirt", "yo-yo"] {
        assert!(l.words().any(|x| x == w), "{w}");
    }
    assert_eq!(l.words().filter(|w| w.contains('-')).count(), 4);
    assert!(
        l.words()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
    );
    let mut by_len: BTreeMap<usize, usize> = BTreeMap::new();
    for w in l.words() {
        *by_len.entry(w.len()).or_insert(0) += 1;
    }
    assert_eq!(
        by_len.into_iter().collect::<Vec<_>>(),
        [
            (3, 82),
            (4, 467),
            (5, 928),
            (6, 1_372),
            (7, 1_591),
            (8, 1_779),
            (9, 1_557)
        ]
    );
    // The check value of FEA-03.1 (D-03-1).
    let mut joined = Vec::new();
    for w in l.words() {
        joined.extend_from_slice(w.as_bytes());
        joined.push(b'\n');
    }
    let digest = app_crypto::hash::sha256(&[&joined]);
    let hex: String = digest.expose().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
    );
    // The compiled file is EFF's: dice codes 11111 to 66666 in order.
    let file = include_str!("../src/generator/eff_large_wordlist.txt");
    let codes: Vec<&str> = file
        .lines()
        .map(|l| l.split('\t').next().unwrap())
        .collect();
    assert_eq!(codes.len(), 7_776);
    let mut want = Vec::new();
    for n in 0..7_776u32 {
        let digits: String = (0..5)
            .rev()
            .map(|i| char::from(b'1' + (n / 6u32.pow(i) % 6) as u8))
            .collect();
        want.push(digits);
    }
    assert_eq!(codes, want);
    assert!(!l.is_small());
}

#[test]
fn fea03_01_source_and_license_in_the_file_header() {
    let src = include_str!("../src/generator/wordlist.rs");
    let header: String = src
        .lines()
        .take_while(|l| l.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "EFF Large Wordlist for Passphrases",
        "Electronic Frontier Foundation",
        "https://www.eff.org/dice",
        "Creative Commons Attribution",
        "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522",
    ] {
        assert!(header.replace("\n//! ", " ").contains(needle), "{needle}");
    }
}

#[test]
fn fea03_02_bits_per_word() {
    assert_eq!(bits(6, builtin()), "77.55");
    assert_eq!(level(entropy(6, builtin())), Level::Good);
    assert_eq!(bits(8, builtin()), "103.40");
    assert!((entropy(1, builtin()) - 12.925).abs() < 0.001);
}

#[test]
fn fea03_03_word_count_and_defaults() {
    let d = Options::default();
    assert_eq!(
        (d.words, d.separator.as_str(), d.case),
        (7, " ", Case::Lower)
    );
    let p = phrase(&d, builtin());
    let parts: Vec<&str> = p.split(' ').collect();
    assert_eq!(parts.len(), 7, "{p}");
    assert!(parts.iter().all(|w| builtin().words().any(|x| x == *w)));
    assert_eq!(bits(7, builtin()), "90.47");
    assert_eq!(level(entropy(7, builtin())), Level::Good);
    // D-03-5: 1 to 1,000 words in the core.
    assert_eq!(MAX_WORDS, 1_000);
    for bad in [0, 1_001, u32::MAX] {
        let o = Options {
            words: bad,
            ..Options::default()
        };
        assert_eq!(
            generate(&o, builtin()).err(),
            Some(Error::CountOutOfRange),
            "{bad}"
        );
    }
    let big = Options {
        words: 1_000,
        ..Options::default()
    };
    assert_eq!(phrase(&big, builtin()).split(' ').count(), 1_000);
}

#[test]
fn fea03_04_separator() {
    let a = list(LIST_A);
    let o = Options {
        words: 4,
        separator: "-".into(),
        case: Case::Lower,
    };
    for _ in 0..100 {
        let p = phrase(&o, &a);
        assert_eq!(p.matches('-').count(), 3, "{p}");
        assert!(!p.starts_with('-') && !p.ends_with('-'));
    }
    // Not trimmed; empty allowed; at most 64 characters (D-03-5).
    let spaced = Options {
        words: 2,
        separator: "  ".into(),
        case: Case::Lower,
    };
    assert_eq!(phrase(&spaced, &a).matches("  ").count(), 1);
    let none = Options {
        words: 3,
        separator: String::new(),
        case: Case::Lower,
    };
    assert!(phrase(&none, &a).chars().all(|c| c.is_ascii_lowercase()));
    let max = Options {
        words: 2,
        separator: "é".repeat(64),
        case: Case::Lower,
    };
    assert!(generate(&max, &a).is_ok());
    let over = Options {
        words: 2,
        separator: "é".repeat(65),
        case: Case::Lower,
    };
    assert_eq!(generate(&over, &a).err(), Some(Error::SeparatorTooLong));
}

#[test]
fn fea03_05_word_case() {
    let a = list(LIST_A);
    let o = |case| Options {
        words: 4,
        separator: " ".into(),
        case,
    };
    for _ in 0..50 {
        let up = phrase(&o(Case::Upper), &a);
        assert!(
            up.chars().all(|c| c.is_ascii_uppercase() || c == ' '),
            "{up}"
        );
        let title = phrase(&o(Case::Title), &a);
        for w in title.split(' ') {
            let mut cs = w.chars();
            assert!(
                cs.next().unwrap().is_ascii_uppercase() && cs.all(|c| c.is_ascii_lowercase()),
                "{title}"
            );
        }
        let mixed = phrase(&o(Case::Mixed), &a);
        let upper = mixed
            .split(' ')
            .filter(|w| w.chars().all(|c| c.is_ascii_uppercase()))
            .count();
        assert_eq!(upper, 1, "{mixed}");
    }
    // Full Unicode mapping, first scalar value.
    let s = list("\u{df}\n");
    assert_eq!(
        phrase(
            &Options {
                words: 1,
                separator: " ".into(),
                case: Case::Upper
            },
            &s
        ),
        "SS"
    );
    let t = list("\u{e9}t\u{c9}\n");
    assert_eq!(
        phrase(
            &Options {
                words: 1,
                separator: " ".into(),
                case: Case::Title
            },
            &t
        ),
        "\u{c9}t\u{e9}"
    );
}

#[test]
fn fea03_06_uniform_picks_with_replacement() {
    // List A, 1 word, 600,000: chi-square below 35.89 (5 df).
    let a = list(LIST_A);
    let o = Options {
        words: 1,
        ..Options::default()
    };
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    for _ in 0..600_000 {
        *seen.entry(phrase(&o, &a)).or_insert(0) += 1;
    }
    assert_eq!(seen.len(), 6);
    let chi: f64 = seen
        .values()
        .map(|&v| (v as f64 - 100_000.0).powi(2) / 100_000.0)
        .sum();
    assert!(chi < 35.89, "chi-square {chi}");
    // Built-in, 7 words, 100,000: a repeated word 270 ± 80 times.
    let seven = Options::default();
    let mut repeats = 0;
    for _ in 0..100_000 {
        let p = phrase(&seven, builtin());
        let mut ws: Vec<&str> = p.split(' ').collect();
        ws.sort_unstable();
        ws.dedup();
        if ws.len() < 7 {
            repeats += 1;
        }
    }
    assert!((190..=350).contains(&repeats), "repeats {repeats}");
    // Mixed position: list A, 4 words, 400,000: each position 100,000 ±
    // 1,340.
    let mixed = Options {
        words: 4,
        separator: " ".into(),
        case: Case::Mixed,
    };
    let mut at = [0u64; 4];
    for _ in 0..400_000 {
        let p = phrase(&mixed, &a);
        let ups: Vec<usize> = p
            .split(' ')
            .enumerate()
            .filter(|(_, w)| w.chars().all(|c| c.is_ascii_uppercase()))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(ups.len(), 1, "{p}");
        at[ups[0]] += 1;
    }
    for (i, n) in at.iter().enumerate() {
        assert!(n.abs_diff(100_000) <= 1_340, "position {i}: {n}");
    }
}

#[test]
fn fea03_07_entropy_formula() {
    let a = list(LIST_A);
    assert_eq!(bits(3, &a), "7.75");
    assert_eq!(level(entropy(3, &a)), Level::Poor);
    for (n, want, lv) in [
        (3, "38.77", Level::Poor),
        (5, "64.62", Level::Weak),
        (7, "90.47", Level::Good),
        (8, "103.40", Level::Excellent),
    ] {
        assert_eq!(bits(n, builtin()), want);
        assert_eq!(level(entropy(n, builtin())), lv);
    }
    // Not adjusted for case or separator: the formula has no such input.
    assert_eq!(bits(7, builtin()), "90.47");
    // Empty list: 0.00; one entry: 0.00.
    assert_eq!(bits(7, &list("")), "0.00");
    assert_eq!(bits(7, &list("solo\n")), "0.00");
}

#[test]
fn fea03_08_reading_a_word_list_file() {
    let l = list(
        "11111\talpha\n11112 bravo\n1-1-1-2-1   charlie\n  delta  \n\necho echo\nAlpha\nalpha\n",
    );
    assert_eq!(
        words(&l),
        ["alpha", "bravo", "charlie", "delta", "echo echo"]
    );
    assert_eq!(bits(1, &l), "2.32");
    // Non-dice lines.
    let n = list("11111 two words\n2nd\n11111\n123 456\n");
    assert_eq!(words(&n), ["11111 two words", "2nd", "11111", "456"]);
    // Unicode white space trimmed; inner U+00A0 is not a dice separator.
    let w = list("alpha\n\u{2003}bravo\u{a0}\n\tcharlie\t\n11111\u{a0}delta\n1--2 echo\n-1 golf\n");
    assert_eq!(
        words(&w),
        [
            "alpha",
            "bravo",
            "charlie",
            "11111\u{a0}delta",
            "1--2 echo",
            "-1 golf"
        ]
    );
    // Byte order marks: UTF-8, UTF-16 big-endian and little-endian; CRLF.
    let mut utf8 = vec![0xef, 0xbb, 0xbf];
    utf8.extend_from_slice(b"alpha\r\nbravo\r\n");
    assert_eq!(words(&parse(&utf8).unwrap()), ["alpha", "bravo"]);
    let text = "alpha\nbravo\n";
    let mut be = vec![0xfe, 0xff];
    let mut le = vec![0xff, 0xfe];
    for u in text.encode_utf16() {
        be.extend_from_slice(&u.to_be_bytes());
        le.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(words(&parse(&be).unwrap()), ["alpha", "bravo"]);
    assert_eq!(words(&parse(&le).unwrap()), ["alpha", "bravo"]);
    // File order kept.
    assert_eq!(list(LIST_A).get(3), Some("delta"));
}

#[test]
fn fea03_09_signed_lists() {
    let l = list(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n11111 one\n- two\n- -three\nfour\n-----BEGIN PGP SIGNATURE-----\nsigword\n",
    );
    assert_eq!(words(&l), ["one", "two", "-three", "four"]);
    // Not signed: the dash stays.
    assert_eq!(words(&list("- two\nalpha\n")), ["- two", "alpha"]);
    // Signed without the signature line: read to the end.
    let open = list("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nalpha\nbravo\n");
    assert_eq!(words(&open), ["alpha", "bravo"]);
}

#[test]
fn fea03_10_unique_after_lower_casing() {
    let l = list("Apple\napple\nAPPLE\npear\n");
    assert_eq!(words(&l), ["apple", "pear"]);
    assert_eq!(bits(1, &l), "1.00");
}

#[test]
fn fea03_11_bad_text_and_limits() {
    // D-03-3: not UTF-8 is refused.
    assert_eq!(parse(b"caf\xe9\nbravo\n").err(), Some(ListError::NotUtf8));
    assert_eq!(
        parse(&[0xfe, 0xff, 0xd8, 0x00]).err(),
        Some(ListError::NotUtf8),
        "lone surrogate"
    );
    assert_eq!(
        parse(&[0xfe, 0xff, 0x00]).err(),
        Some(ListError::NotUtf8),
        "odd length"
    );
    // A lone CR ends a line.
    assert_eq!(
        words(&list("alpha\rbravo\rcharlie\r")),
        ["alpha", "bravo", "charlie"]
    );
    // Too big: over 4 MiB, an entry over 256 characters, over 500,000
    // unique entries.
    // Exactly 4 MiB is still read; one byte more is refused.
    let mut exact = b"a\n".repeat(wordlist::MAX_FILE / 2);
    assert_eq!(exact.len(), wordlist::MAX_FILE);
    assert_eq!(parse(&exact).unwrap().len(), 1);
    exact.push(b'b');
    assert_eq!(parse(&exact).err(), Some(ListError::TooBig));
    let five = vec![b'a'; 5 * 1024 * 1024];
    assert_eq!(parse(&five).err(), Some(ListError::TooBig));
    assert_eq!(
        parse("x".repeat(300).as_bytes()).err(),
        Some(ListError::TooBig)
    );
    assert!(parse("é".repeat(256).as_bytes()).is_ok());
    let mut many = String::new();
    for i in 0..=MAX_ENTRIES {
        many.push_str(&format!("{i:x}\n"));
    }
    assert!(many.len() <= wordlist::MAX_FILE);
    assert_eq!(parse(many.as_bytes()).err(), Some(ListError::TooBig));
    let exact: String = (0..MAX_ENTRIES).map(|i| format!("{i:x}\n")).collect();
    assert_eq!(parse(exact.as_bytes()).unwrap().len(), MAX_ENTRIES);
}

#[test]
fn fea03_12_small_list_warning() {
    let make = |n: usize| (1..=n).map(|i| format!("w{i}\n")).collect::<String>();
    let small = list(&make(1_295));
    let ok = list(&make(1_296));
    assert!(small.is_small() && !ok.is_small());
    for l in [&small, &ok] {
        assert_eq!(phrase(&Options::default(), l).split(' ').count(), 7);
    }
}

#[test]
fn fea03_13_empty_list() {
    // D-03-4: `MSG-PP-LIST-EMPTY`, no output.
    let empty = list("\n\n  \n");
    assert!(empty.is_empty() && empty.is_small());
    assert_eq!(
        generate(&Options::default(), &empty).err(),
        Some(Error::EmptyWordList)
    );
    // Count and separator are checked first.
    let o = Options {
        words: 0,
        ..Options::default()
    };
    assert_eq!(generate(&o, &empty).err(), Some(Error::CountOutOfRange));
}

#[test]
fn fea03_16_command_line_passphrase() {
    let o = passphrase::Options::command_line(7);
    assert_eq!(
        (o.words, o.separator.as_str(), o.case),
        (7, " ", Case::Lower)
    );
    for _ in 0..100 {
        let p = phrase(&o, builtin());
        assert_eq!(p.split(' ').count(), 7);
        assert!(
            p.chars()
                .all(|c| c.is_ascii_lowercase() || c == ' ' || c == '-')
        );
    }
    let a = list(LIST_A);
    for _ in 0..60 {
        let p = phrase(&passphrase::Options::command_line(1), &a);
        assert!(a.words().any(|w| w == p));
    }
}

#[test]
fn fea03_17_passphrase_is_a_secret_string() {
    let s: app_crypto::secret::SecretString = generate(&Options::default(), builtin()).unwrap();
    assert!(!format!("{s:?}").contains(s.expose()));
}
