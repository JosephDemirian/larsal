//! Larsal's own code in the patched `zxcvbn` copy (vendor/zxcvbn, LD-136,
//! story E0-S7 step 3a): the reference year from the standard library
//! (change 8) and the hand-written matchers that took the place of the
//! `regex` and `fancy-regex` patterns (change 9). The expected matches were
//! read from the copy before the change, which ran the patterns.

use larsal_model::Time;
use larsal_model::times::Civil;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zxcvbn::matching::omnimatch;
use zxcvbn::matching::patterns::MatchPattern;
use zxcvbn::utc_year;

/// Unix seconds as a system time, before 1970 too.
fn at(secs: i64) -> SystemTime {
    let d = Duration::from_secs(secs.unsigned_abs());
    if secs < 0 {
        UNIX_EPOCH - d
    } else {
        UNIX_EPOCH + d
    }
}

/// Larsal's own calendar (larsal-model `Time`): Unix seconds of a date at 00:00:00.
fn unix(year: i64, month: u32, day: u32) -> i64 {
    let civil = Civil {
        year,
        month,
        day,
        hour: 0,
        minute: 0,
        second: 0,
    };
    Time::from_civil(civil).unwrap().0 - Time::from_unix(0).unwrap().0
}

#[test]
fn ld136_8_utc_year_around_1_january() {
    for (secs, year) in [
        (-2_208_988_801, 1899),
        (-2_208_988_800, 1900),
        (-1, 1969),
        (0, 1970),
        (946_684_799, 1999),
        (946_684_800, 2000),
        (978_307_199, 2000), // 2000-12-31T23:59:59Z, day 366
        (978_307_200, 2001),
        (1_767_225_599, 2025),
        (1_767_225_600, 2026),
        (4_102_444_799, 2099),
        (4_102_444_800, 2100),
    ] {
        assert_eq!(utc_year(at(secs)), year, "{secs}");
    }
    // A part of a second before 1970 is still 1969.
    assert_eq!(utc_year(UNIX_EPOCH - Duration::from_nanos(1)), 1969);
    // Every 1 January and every 1 March from 1601 to 2400 against Larsal's own
    // calendar: the second before is the old year (or, for March, the same
    // year, past a 28 or 29 February).
    for year in 1601..=2400 {
        let y = i32::try_from(year).unwrap();
        let jan = unix(year, 1, 1);
        assert_eq!(utc_year(at(jan)), y, "{year}-01-01");
        assert_eq!(utc_year(at(jan - 1)), y - 1, "{year}-01-01 minus 1 s");
        let mar = unix(year, 3, 1);
        assert_eq!(utc_year(at(mar)), y, "{year}-03-01");
        assert_eq!(utc_year(at(mar - 1)), y, "{year}-03-01 minus 1 s");
    }
    // The clock's year, as Larsal's calendar reads the same instant.
    let now = SystemTime::now();
    let secs = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    let civil = Time::from_unix(secs).unwrap().to_civil().unwrap();
    assert_eq!(i64::from(utc_year(now)), civil.year);
}

type Repeat = (usize, usize, &'static str, usize);
type Year = (usize, usize, &'static str);
type Date = (usize, usize, i32, i8, i8, &'static str);
/// A password and what the copy with the patterns found in it.
type Case = (
    &'static str,
    &'static [Repeat],
    &'static [Year],
    &'static [Date],
);

#[test]
fn ld136_9_hand_written_matchers_find_what_the_patterns_found() {
    // (password, repeats (i, j, base, count), recent years (i, j, token),
    // dates (i, j, year, month, day, separator)), as the copy with the
    // patterns found them.
    let cases: &[Case] = &[
        ("aabaab", &[(0, 5, "aab", 2)], &[], &[]),
        ("aaaaa", &[(0, 4, "a", 5)], &[], &[]),
        ("aabaabaabaab", &[(0, 11, "aab", 4)], &[], &[]),
        ("abababab", &[(0, 7, "ab", 4)], &[], &[]),
        ("x🐱🐶🐱🐶", &[(1, 4, "🐱🐶", 2)], &[], &[]),
        ("y4@&&&&&u%7", &[(3, 7, "&", 5)], &[], &[]),
        (
            "BBB1111aaaaa@@@@@@",
            &[
                (0, 2, "B", 3),
                (3, 6, "1", 4),
                (7, 11, "a", 5),
                (12, 17, "@", 6),
            ],
            &[],
            &[(3, 6, 2011, 1, 1, "")],
        ),
        // `.` is any character but a line feed.
        ("ab\nab\nab", &[], &[], &[]),
        ("aa\naa", &[(0, 1, "a", 2), (3, 4, "a", 2)], &[], &[]),
        ("abcabcab", &[(0, 5, "abc", 2)], &[], &[]),
        ("zzabzabzab!", &[(0, 1, "z", 2), (2, 7, "abz", 2)], &[], &[]),
        (
            "201990",
            &[(3, 4, "9", 2)],
            &[(0, 3, "2019")],
            &[(0, 4, 1999, 1, 2, ""), (1, 5, 1990, 9, 1, "")],
        ),
        (
            "19991999",
            &[(0, 7, "1999", 2)],
            &[(0, 3, "1999"), (4, 7, "1999")],
            &[(0, 6, 1999, 9, 19, ""), (2, 7, 1999, 9, 9, "")],
        ),
        ("x2050y", &[], &[(1, 4, "2050")], &[(1, 4, 2000, 5, 20, "")]),
        ("1899", &[(2, 3, "9", 2)], &[], &[(0, 3, 2009, 9, 18, "")]),
        // Full-width digits are not digits to the patterns.
        ("１９９９", &[(1, 3, "９", 3)], &[], &[]),
        (
            "020192021",
            &[],
            &[(1, 4, "2019"), (5, 8, "2021")],
            &[
                (0, 5, 1992, 1, 2, ""),
                (1, 7, 2019, 2, 2, ""),
                (2, 8, 2021, 9, 1, ""),
            ],
        ),
        (
            "13 2 1921",
            &[],
            &[(5, 8, "1921")],
            &[(0, 8, 1921, 2, 13, " ")],
        ),
        (
            "1/1/91",
            &[(0, 3, "1/", 2)],
            &[],
            &[(0, 5, 1991, 1, 1, "/")],
        ),
        // Any Unicode white space separates; a zero-width space does not.
        (
            "1\u{3000}1\u{3000}91",
            &[(0, 3, "1\u{3000}", 2)],
            &[],
            &[(0, 5, 1991, 1, 1, "\u{3000}")],
        ),
        (
            "1\u{a0}1\u{a0}91",
            &[(0, 3, "1\u{a0}", 2)],
            &[],
            &[(0, 5, 1991, 1, 1, "\u{a0}")],
        ),
        ("1\u{200b}1\u{200b}91", &[(0, 3, "1\u{200b}", 2)], &[], &[]),
        ("1/1-91", &[], &[], &[]),
        // The middle number has 1 or 2 digits, the others 1 to 4.
        ("1/012/91", &[], &[], &[]),
        (
            "1/1/12345",
            &[(0, 3, "1/", 2)],
            &[],
            &[(0, 7, 1234, 1, 1, "/"), (4, 8, 2045, 1, 23, "")],
        ),
        (
            "1/1/01991",
            &[(0, 3, "1/", 2), (6, 7, "9", 2)],
            &[(5, 8, "1991")],
            &[(0, 6, 2019, 1, 1, "/"), (4, 8, 1991, 9, 1, "")],
        ),
        (
            "12345/1/1",
            &[(5, 8, "/1", 2)],
            &[],
            &[(0, 4, 2045, 1, 23, ""), (3, 8, 2045, 1, 1, "/")],
        ),
        (
            "11/11/1991x",
            &[(0, 5, "11/", 2), (7, 8, "9", 2)],
            &[(6, 9, "1991")],
            &[(0, 9, 1991, 11, 11, "/")],
        ),
        (
            "02/02/02",
            &[(0, 5, "02/", 2)],
            &[],
            &[(0, 7, 2002, 2, 2, "/")],
        ),
        (
            "a1/1/91!",
            &[(1, 4, "1/", 2)],
            &[],
            &[(1, 6, 1991, 1, 1, "/")],
        ),
        (
            "12/20/1991.12.20",
            &[(7, 8, "9", 2)],
            &[(6, 9, "1991")],
            &[(0, 9, 1991, 12, 20, "/"), (6, 15, 1991, 12, 20, ".")],
        ),
        (
            "1\\1\\91",
            &[(0, 3, "1\\", 2)],
            &[],
            &[(0, 5, 1991, 1, 1, "\\")],
        ),
        (
            "1_1_91",
            &[(0, 3, "1_", 2)],
            &[],
            &[(0, 5, 1991, 1, 1, "_")],
        ),
        (
            "111504",
            &[(0, 2, "1", 3)],
            &[],
            &[(0, 5, 2004, 11, 15, "")],
        ),
        ("1115", &[(0, 2, "1", 3)], &[], &[(0, 3, 2015, 1, 1, "")]),
        (
            "08märz2010",
            &[],
            &[(6, 9, "2010")],
            &[(6, 9, 2000, 1, 20, "")],
        ),
    ];
    let empty = HashMap::new();
    for &(pw, repeats, years, dates) in cases {
        let (mut r, mut y, mut d) = (Vec::new(), Vec::new(), Vec::new());
        for m in omnimatch(pw, &empty) {
            match m.pattern {
                MatchPattern::Repeat(p) => r.push((m.i, m.j, p.base_token, p.repeat_count)),
                MatchPattern::Regex(p) => {
                    assert_eq!(p.regex_name, "recent_year", "{pw:?}");
                    assert_eq!(p.regex_match, std::slice::from_ref(&m.token), "{pw:?}");
                    y.push((m.i, m.j, m.token));
                }
                MatchPattern::Date(p) => d.push((m.i, m.j, p.year, p.month, p.day, p.separator)),
                _ => {}
            }
        }
        let want_r: Vec<_> = repeats
            .iter()
            .map(|&(i, j, b, n)| (i, j, b.to_owned(), n))
            .collect();
        let want_y: Vec<_> = years
            .iter()
            .map(|&(i, j, t)| (i, j, t.to_owned()))
            .collect();
        let want_d: Vec<_> = dates
            .iter()
            .map(|&(i, j, a, b, c, s)| (i, j, a, b, c, s.to_owned()))
            .collect();
        assert_eq!(r, want_r, "repeats of {pw:?}");
        assert_eq!(y, want_y, "years of {pw:?}");
        assert_eq!(d, want_d, "dates of {pw:?}");
    }
}
