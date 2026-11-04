//! E4-S6: writes the seed corpus of the `references` fuzz target in
//! fuzz/corpus/references/ from the MOD-08 test vault R8 and the card's
//! test texts, so no seed is made by hand. E4-S5 adds `icon_decode`; E4-S8
//! and E4-S10 add `search_query` and `totp_link` from the FEA-01 and
//! FEA-04 test cases. Ignored by default because it
//! writes files; run it once after the card's cases or the target change:
//! `cargo test -p larsal-core --test fuzz_seeds -- --ignored`
//!
//! Seed format (see fuzz/fuzz_targets/references.rs): the text, then
//! records separated by 0x1E, each an entry byte, a field code and a value.

mod common;

use std::path::PathBuf;

/// R8 as records: entry index, field code, value (`S` is `name=value`).
fn r8() -> Vec<(u8, u8, String)> {
    let hx = |n: u8| format!("{n:02x}").repeat(16);
    vec![
        (0, b'T', "Probe".into()),
        (0, b'U', "probe-user".into()),
        (0, b'P', "{PASSWORD}".into()),
        (
            0,
            b'A',
            "https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag".into(),
        ),
        (0, b'S', "Custom1=cval".into()),
        (1, b'T', "Alpha".into()),
        (1, b'U', "alice".into()),
        (1, b'P', "pw-A".into()),
        (1, b'A', "https://alpha.example".into()),
        (1, b'N', "note-A".into()),
        (1, b'S', "Mixed=x{TITLE}y{USERNAME}z".into()),
        (2, b'T', format!("{{REF:T@I:{}}}", hx(4))),
        (3, b'T', format!("{{REF:T@I:{}}}", hx(3))),
        (4, b'U', "{URL:PORT}|{URL:HOST}|{URL:SCM}".into()),
        (4, b'A', "example.org/x".into()),
        (5, b'U', format!("{{REF:U@I:{}}}-{{S:Extra}}", hx(2))),
        (5, b'S', "Extra={TITLE}".into()),
        (6, b'U', "{USERNAME}{USERNAME}{USERNAME}{USERNAME}".into()),
        (7, b'U', "{T-CONV:/{USERNAME}/upper/}".into()),
        (8, b'T', "{REF:T@T:{TITLE}}".into()),
        (12, b'T', "Dup".into()),
        (12, b'U', "sub".into()),
    ]
}

const TEXTS: [&str; 22] = [
    "{TITLE}{title}{UUID}",
    "\\{TITLE\\}",
    "a\\{TITLE\\}b",
    "{ {TITLE} }{{TITLE}}{FOO}{}",
    "{S:Custom1}{s:Custom1}{S:Missing}",
    "{URL:RMVSCM}|{URL:HOST}|{URL:PORT}|{URL:USERINFO}",
    "{REF:U@T:Dup}{REF:T@O:cval}",
    "{REF:T@I:{UUID}}",
    "{REF:U@T:Al{S:SB}}",
    "{{{{{{TITLE}}}}}}",
    "{T-CONV:/{USERNAME}/upper/}{T-CONV:/abc/base64/}",
    "{T-CONV:/a%20b%zz/uri-dec/}{T-CONV:/straße/l/}",
    "{T-REPLACE-RX:/abc/(b)/[$1]/}",
    "{DT_SIMPLE}{DT_UTC_YEAR}{DB_DIR}{TOTP}",
    "!https://h.example/?p={PASSWORD}",
    "{a{b}c}}{{",
    "{REF:T@I: 0a0a-0a0a }",
    "{USERNAME}{USERNAME}{USERNAME}{USERNAME}{USERNAME}{USERNAME}{USERNAME}{USERNAME}",
    "{URL:HOST}",
    "x{T-CONV:/abc/junk/}y",
    "{T-REPLACE-RX:/{NOTES}/(a+)+$/X/}",
    "{URL:HOST}{T-REPLACE-RX:/{NOTES}/(?:[a-z]{1,40}){1,40}x/X/}",
];

#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_fuzz_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/references"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let records: Vec<u8> = r8()
        .into_iter()
        .flat_map(|(e, f, v)| [vec![0x1E, e, f], v.into_bytes()].concat())
        .chain([0x1E, 0, b'N', b'*', 0xFF, b'a'])
        .collect();
    for (i, text) in TEXTS.iter().enumerate() {
        let seed = [text.as_bytes(), &records].concat();
        std::fs::write(dir.join(format!("seed-{i:02}")), seed).unwrap();
    }
}

/// Seeds of the `icon_decode` target: real PNGs in every colour type and
/// bit depth `png` writes, and ICOs with BMP and PNG images inside.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_icon_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/icon_decode"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let png = |w: u32, h: u32, color: png::ColorType, depth: png::BitDepth, data: Vec<u8>| {
        let mut out = Vec::new();
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(color);
        e.set_depth(depth);
        if color == png::ColorType::Indexed {
            e.set_palette(vec![255, 0, 0, 0, 0, 255]);
        }
        let mut wr = e.write_header().unwrap();
        wr.write_image_data(&data).unwrap();
        wr.finish().unwrap();
        out
    };
    use png::{BitDepth as D, ColorType as C};
    let seeds = [
        png(16, 16, C::Rgba, D::Eight, [255, 0, 0, 255].repeat(256)),
        png(8, 4, C::Rgb, D::Eight, [0, 255, 0].repeat(32)),
        png(5, 5, C::Grayscale, D::Eight, vec![128; 25]),
        png(5, 5, C::GrayscaleAlpha, D::Eight, [200, 100].repeat(25)),
        png(4, 4, C::Indexed, D::Eight, [0, 1].repeat(8)),
        png(3, 3, C::Rgba, D::Sixteen, vec![7; 72]),
        png(200, 50, C::Rgb, D::Eight, vec![9; 200 * 50 * 3]),
    ];
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-png-{i}")), s).unwrap();
    }
    let ico = |sizes: &[u32]| {
        let pixels: Vec<Vec<u8>> = sizes
            .iter()
            .map(|&s| [10, 20, 30, 255].repeat((s * s) as usize))
            .collect();
        let images: Vec<common::ico::Image> = sizes
            .iter()
            .zip(&pixels)
            .map(|(&s, p)| (s, s, p.as_slice()))
            .collect();
        common::ico::ico(&images)
    };
    for (i, sizes) in [&[16u32][..], &[16, 32][..], &[128][..]].iter().enumerate() {
        std::fs::write(dir.join(format!("seed-ico-{i}")), ico(sizes)).unwrap();
    }
}

/// Seeds of the `search_query` target (E4-S8): a flag byte, then a query
/// from the FEA-01 test cases.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_search_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/search_query"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let queries = [
        "github",
        "git hub",
        "*",
        "pw:hunter2",
        "u:alex",
        "_UserName:alex",
        "_otp:JBSWY",
        "+t:Gmail|Big",
        "+-t:Gmail",
        "tag:wor*",
        "attr:blue",
        "a:pdf",
        "g:/Vault/Banking",
        "g:\"Dev & Ops\"",
        "is:expired-7",
        "i:EXPIRED",
        "is:weak",
        "!has:totp",
        "uuid:1414",
        "-*t:[",
        r"*u:^\w+$",
        "*t:(a+)+$",
        "*t:(?=Git)G",
        r"*t:\p{L}",
        "\"PIN is\" \"git\" \"hub\"",
        "\"abc\"def ghi",
        r#""a\"b c" "a\b""#,
        "t:G?tHub url:github?com",
        "n:account*recovery",
        "foo:github https://github.com 12:30",
        "t:Emoji???key 🔑",
        "c++ -5 \"-5\"",
        "*(?:[a-z]{1,30}){1,30}[0-9]",
        "work,dev",
        "say \"hi\",a\\",
    ];
    // Inputs the target once failed on (fea01.rs FUZZ_REGRESSIONS), kept
    // as seeds with their own flag byte.
    let regressions: [&[u8]; 1] = [b"-*(:?[a-z]{1,30}){1,30}`0-9]"];
    for (i, r) in regressions.iter().enumerate() {
        std::fs::write(dir.join(format!("regression-{i:02}")), r).unwrap();
    }
    for (i, q) in queries.iter().enumerate() {
        let flags = (i % 8) as u8;
        std::fs::write(
            dir.join(format!("seed-{i:02}")),
            [&[flags][..], q.as_bytes()].concat(),
        )
        .unwrap();
    }
}

/// Seeds of the `totp_link` target (E4-S10): a presence byte, then the
/// field values of the FEA-04 test cases separated by 0x1E.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_totp_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/totp_link"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    const R: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    // (presence bits, [otp, seed, settings, T secret, T algorithm, T length, T period])
    let seeds: Vec<(u8, [String; 7])> = vec![
        (
            1,
            [
                format!("otpauth://totp/a:b?secret={R}&digits=8"),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                format!("OTPAUTH://totp/Demo:alice?secret={R}&encoder=steam"),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                format!("otpauth://hotp/Demo:alice?secret={R}&counter=5"),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                format!("key={R}&size=8&step=60&otpHashMode=Sha256"),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                "key=GEZDGNBVGY3TQOJQ%3d&size=6".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                "otpauth://totp/x?secret=GEZDGNBV%2BGY3TQOJQ&digits=%208&period=+30".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            6,
            [
                "".into(),
                R.into(),
                "60;S".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            6,
            [
                "".into(),
                "gezd gnbv gy3t qojq".into(),
                "30;8".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            0b111_1000,
            [
                "".into(),
                "".into(),
                "".into(),
                R.into(),
                "HMAC-SHA-512".into(),
                "12".into(),
                "4000000000".into(),
            ],
        ),
        (
            0b111_1001,
            [
                "".into(),
                "".into(),
                "".into(),
                "ABC".into(),
                "SHA256".into(),
                "0".into(),
                "0".into(),
            ],
        ),
        (
            1,
            [
                "otpauth:secret=X".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
        (
            1,
            [
                format!("otpauth://totp/a?secret={R}&algorithm=sha512&digits=10&period=86400"),
                "jbsw y3dp".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            ],
        ),
    ];
    for (i, (bits, values)) in seeds.iter().enumerate() {
        let body = values.join("\u{1e}");
        std::fs::write(
            dir.join(format!("seed-{i:02}")),
            [&[*bits][..], body.as_bytes()].concat(),
        )
        .unwrap();
    }
}

/// Seeds of the `word_list` target (E4-S9, D-03-3): the FEA-03 test files.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_word_list_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/word_list"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let builtin: String = include_str!("../src/generator/eff_large_wordlist.txt")
        .lines()
        .take(64)
        .map(|l| format!("{l}\n"))
        .collect();
    let mut utf16 = vec![0xfe, 0xff];
    for u in "alpha\nbravo\n".encode_utf16() {
        utf16.extend_from_slice(&u.to_be_bytes());
    }
    let seeds: Vec<Vec<u8>> = vec![
        b"alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n".to_vec(),
        b"11111\talpha\n11112 bravo\n1-1-1-2-1   charlie\n  delta  \n\necho echo\nAlpha\nalpha\n".to_vec(),
        b"11111 two words\n2nd\n11111\n123 456\n".to_vec(),
        "alpha\n\u{2003}bravo\u{a0}\n\tcharlie\t\n".as_bytes().to_vec(),
        [&[0xef, 0xbb, 0xbf][..], b"alpha\r\nbravo\r\n"].concat(),
        utf16,
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n11111 one\n- two\n- -three\nfour\n-----BEGIN PGP SIGNATURE-----\nsigword\n".to_vec(),
        b"Apple\napple\nAPPLE\npear\n".to_vec(),
        b"caf\xe9\nbravo\n".to_vec(),
        b"alpha\rbravo\rcharlie\r".to_vec(),
        "\u{df}ig\nzeta\naPPle\n".as_bytes().to_vec(),
        builtin.into_bytes(),
    ];
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

/// Seeds of the `breach_lines` target (E4-S11): the FEA-06 range answers
/// (06-04 to 06-07) and hash files (06-19 to 06-28).
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_breach_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/breach_lines"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pw = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
    let six = "7C4A8D09CA3762AF61E59520943DC26494F8941B";
    let seeds: Vec<String> = vec![
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n"
            .into(),
        "0018A45C4D1DEF81644B54AB7F969B88D65:12\r\nD09CA3762AF61E59520943DC26494F8941B:0\r\n"
            .into(),
        "1e4c9b93f3f0682250b6cf8331b7ee68fd8:7\n".into(),
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:x\r\n".into(),
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8: 12 \r\n".into(),
        format!(
            "{six}:37359195\n{}:10434004\r\nDA39A3EE5E6B4B0D3255BFEF95601890AFD80709:5\nF424452A9673918C6F09B0CDD35B20BE8E6AE7D7:0\n",
            pw.to_ascii_lowercase()
        ),
        format!("{six}:37359195\n{pw}:10"),
        format!("{six}:37359195\n\n\n{pw}:+10\n"),
        format!("{six}37359195\n"),
        format!("{six} :1\n"),
        format!("{six}:\n"),
        format!("{six}:12\r{pw}:3\r\n"),
        String::new(),
        format!("{}Z:9\n", &six[..39]),
        format!("{pw}:4294967297\n"),
        format!("{pw}:99999999999999999999999\n"),
    ];
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

/// Seeds of the `strength_estimate` target (E4-S11, LD-134): the FEA-05.19
/// sample, the long keyboard walks that panic with overflow checks on, the
/// long user-input match, LD-44's inputs and odd text. Format (see
/// fuzz/fuzz_targets/strength_estimate.rs): the number of inputs, each
/// input as a 2-byte little-endian length and its bytes, then the password;
/// each seed with inputs also comes with bit 2 set (the entry path). The
/// corpus also keeps `slow-unit`, the Checker's slowest fuzz unit (LD-137
/// (3)), as found; this writer leaves it alone.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_strength_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/strength_estimate"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seed = |inputs: &[&str], password: &str| {
        let mut out = vec![u8::try_from(inputs.len()).unwrap()];
        for i in inputs {
            out.extend_from_slice(&u16::try_from(i.len()).unwrap().to_le_bytes());
            out.extend_from_slice(i.as_bytes());
        }
        out.extend_from_slice(password.as_bytes());
        out
    };
    let walk = |pair: &str, n: usize| pair.chars().cycle().take(n).collect::<String>();
    let alphabet: String = "abcdefghijklmnopqrstuvwxyz"
        .chars()
        .cycle()
        .take(100)
        .collect();
    let mixed: String = alphabet
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    let mut seeds: Vec<Vec<u8>> = [
        "password",
        "P@ssw0rd",
        "abc123",
        "hunter2",
        "Summer2024!",
        "demo-pass-1",
        "Zm4#Lp9",
        "Tr0ub4dor&3",
        "correcthorsebatterystaple",
        "x9!Lq#4vTz",
        "Zm4#Lp9qW2xR7v",
        "4v8Nq2LmZ7rT1xKc9WbP",
        "",
        "     ",
        "ßøæþðłŋħĸŧ",
        "🔑🔑🔑🔑",
        "\t\t\t\u{7}",
    ]
    .iter()
    .map(|p| seed(&[], p))
    .collect();
    seeds.extend([
        seed(&[], &walk("kT7#pQ2vZ9mW4xR8", 300)),
        seed(&[], &walk("12", 30)),
        seed(&[], &walk("qw", 33)),
        seed(&[], &walk("Qw", 100)),
        seed(&[], &walk("aS", 100)),
        seed(&[&alphabet], &mixed),
        seed(
            &["alice", "alice", "https://login.example.com/x"],
            "alice2024",
        ),
        seed(&["", "", ""], "1988-07-14"),
        seed(&[], &"a".repeat(5_000)),
        seed(&[&"T1tle".repeat(200)], &"t1tle".repeat(20)),
    ]);
    let entry_path: Vec<Vec<u8>> = seeds
        .iter()
        .filter(|s| s[0] > 0)
        .map(|s| [&[s[0] | 4][..], &s[1..]].concat())
        .collect();
    seeds.extend(entry_path);
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

/// Seeds of the `csv_import` target (E4-S13): the FEA-08 CSV cases 08-13
/// to 08-27 and the FEA-09.3 header. Format (see
/// fuzz/fuzz_targets/csv_import.rs): an option byte, a separator and
/// comment byte, then the file.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_csv_import_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/csv_import"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Option bits: 0-1 encoding, 2-4 qualifier index, 5 backslash, 6 names.
    let names = 64u8;
    let colon = 2u8 << 2;
    let x = 0u8; // qualifier `"`
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend("č,d\r\ne,f".encode_utf16().flat_map(u16::to_le_bytes));
    let files: Vec<(u8, u8, Vec<u8>)> = vec![
        (names, 0, b"\xEF\xBB\xBFa,b".to_vec()),
        (names, 0, utf16),
        (1, 0, b"\x80,\x9f\x81".to_vec()),
        (0, 0, b"  #one\n \t # two\nuseful,text #1!\nA,,B\"".to_vec()),
        (0, 0, b"ro,w,\"end, of \"\"\"\"\"\"row\"\"\"\"\"\n2".to_vec()),
        (colon, 0, b":1\r\n2a::b:,:3\r4:".to_vec()),
        (colon, 0, b"A,B,C\n:BM::,1,:2:".to_vec()),
        (colon | names, 0, b"A,B\n:BM,1".to_vec()),
        (x | 32, 0, b"\"one\\\"\\\\t\\\\\\\"w\no\"".to_vec()),
        (0, 0, b"1,2\n,,,,,,,,,a\na,b,c,d\n\"\"\n\"\n\"".to_vec()),
        (names, 0, b"title,USERNAME,,Pass\nT,U,x,P".to_vec()),
        (names | 128, 0, b"# c\nTitle\n\nT1\nT2".to_vec()),
        (names, 0, b"Group,Title\nPasswords/Work,a\npasswords/Home,b\nPasswords,c\n".to_vec()),
        (names, 0, b"Group,Title\nPersonal/Work,a\nPersonal/Work/Sub,b\nPersonal,c\nX//B/,d\n".to_vec()),
        (
            names,
            0,
            b"Title,Tags,TOTP,Notes\n T ,\"b, a;a\",JBSWY3DPEHPK3PXP,\"two\nlines\"\nSite,,otpauth://totp/x?secret=JBSWY3DP&digits=8,\n".to_vec(),
        ),
        (names, 0, b"Title,Icon\na,5\nb,69\nc,-1\nd,x\n".to_vec()),
        (
            names,
            0,
            b"Title,Last Modified,Created\n1,1700000000,\n2,1700000000000,\n3,2147483648,\n4,2024-03-10T12:00:00+02:00,\n5,20240101,\n6,soon,2024-01-15 08:00\n7,2024-03-10T24:00,99999999999999999999\n".to_vec(),
        ),
        (
            names,
            0,
            b"\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\"Passwords/Work\",\"Mail\",\"alice2\",\"demo-secret-1\",\"https://example.com\",\"line1\nline2 \"\"quoted\"\", comma\",\"\",\"0\",\"2026-10-24T22:53:25Z\",\"2026-10-24T22:53:24Z\"\n".to_vec(),
        ),
        (names, 0x11, b"a;b;c\n@ comment\nd;e;f".to_vec()),
        (names | (4 << 2), 5, b"|x|\t|y||z|\n1\t2".to_vec()),
    ];
    for (i, (a, b, file)) in files.iter().enumerate() {
        let mut seed = vec![*a, *b];
        seed.extend(file);
        std::fs::write(dir.join(format!("seed-{i:02}")), seed).unwrap();
    }
}

/// Seeds of the `json_import` target (E4-S13): plain Bitwarden exports
/// in the shape of FEA-08 cases 08-40 to 08-42, both protected demo
/// files of tests/data/, Proton Pass exports in the shape of 08-46 and
/// 08-47, and hostile shapes of 08-61 and 08-63. Format: the file.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_json_import_seeds() {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/json_import"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seeds: Vec<String> = vec![
        r#"{"items":[{"name":"x"}]}"#.into(),
        r#"{"folders":[{"id":"1","name":"A/B"},{"id":"2","name":"A//B"},{"id":"3","name":"/C"}],"items":[{"name":"i1","folderId":"1"},{"name":"i2","folderId":"2"},{"name":"i3","folderId":"3"}]}"#.into(),
        r#"{"collections":[{"id":"c","name":"Team"}],"items":[{"name":"t","folderId":null,"collectionIds":["c"]}]}"#.into(),
        r#"{"folders":[{"id":"f1","name":"My Folder"}],"items":[{"id":"1","folderId":"f1","type":1,"name":"Login Name","favorite":true,"login":{"username":"u@example.com","password":"demo-pass-1","totp":"JBSWY3DP","uris":[{"uri":"https://example.com"},{"uri":"https://example.org"}]},"fields":[{"name":"PIN","value":"1","type":1},{"name":"PIN","value":"2","type":0},{"name":"b","value":"true","type":2},{"name":"l","value":"x","type":3}],"creationDate":"2024-12-01T12:00:00.000Z","revisionDate":"2024-12-25T12:00:00.000Z","passwordHistory":[{"lastUsedDate":"2024-12-01T12:00:00.000Z","password":"old"}]}]}"#.into(),
        r#"{"folders":[],"items":[{"name":"My Identity","identity":{"title":"Mx","firstName":"Demo","lastName":"Person","address1":" 1 Demo Street ","city":"Demo City","state":"DC","postalCode":"00000","country":"Demoland","ssn":"000","username":"id"}},{"name":"Card","card":{"cardholderName":"Demo","number":"4111","code":"123"}}]}"#.into(),
        r#"{"folders":[],"items":[{"name":"P","login":{"fido2Credentials":[{"credentialId":"6f1c1a2e-0d3b-4c5a-9e8f-1a2b3c4d5e6f","keyValue":"MIGHAgEAERERERERERERERERERERERERERE","rpId":"example.com","userName":"demo-user","userHandle":"ZGVtby1oYW5kbGU"}]}}]}"#.into(),
        include_str!("data/bw-encrypted-pbkdf2.json").into(),
        include_str!("data/bw-encrypted-argon2.json").into(),
        r#"{"encrypted":true,"salt":"c2FsdA==","kdfType":0,"kdfIterations":5000,"encKeyValidation_DO_NOT_EDIT":"1.AA==|AA==|AA==","data":"2.x"}"#.into(),
        r#"{"version":"1.0","encrypted":false,"vaults":{"b":{"name":"Test","items":[{"data":{"metadata":{"name":"n","note":""},"type":"note","content":{}},"state":2}]},"a":{"name":"Personal","description":"d","items":[{"data":{"metadata":{"name":"Test Login","note":"x"},"extraFields":[{"fieldName":"hidden field","type":"hidden","data":{"content":"h"}},{"fieldName":"t","type":"totp","data":{"totpUri":"TOTPCODE"}}],"type":"login","content":{"itemEmail":"e@example.com","password":"pw","urls":["https://example.com/","https://example2.com/"],"totpUri":"otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP","itemUsername":"Username"}},"state":1,"createTime":1700000000,"modifyTime":1700000200,"pinned":true}]}}}"#.into(),
        r#"{"vaults":{"a":{"name":"P","items":[{"data":{"metadata":{"name":"c"},"type":"creditCard","content":{"number":"1","verificationNumber":"2","pin":"3"}}},{"data":{"metadata":{"name":"w"},"type":"wifi","content":{"ssid":"s","security":"WPA2"}}},{"data":{"metadata":{"name":"k"},"type":"sshKey","content":{"privateKey":"a","publicKey":"b"}}},{"data":{"metadata":{"name":"u","note":"o"},"type":"future","content":{"z":"1","a":2}}}]}}}"#.into(),
        r#"{"encrypted":true}"#.into(),
        r#"{"folders":"x","collections":[{"id":1,"name":5}],"items":[{"name":7,"login":"no","fields":{"a":1},"passwordHistory":3},5,null]}"#.into(),
        format!("{{\"items\":{}{}}}", "[".repeat(40), "]".repeat(40)),
        r#"["😀é\n", -1.5e3, true, false, null, {"a":{}}]"#.into(),
    ];
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

/// Seeds of the `json_reader` target (E0-S7 R12): Larsal's own JSON as its
/// settings and export files, a vault's saved searches and browser items
/// and the instance lines hold it, the edges of the reader's own tests, and
/// some it refuses. Format: the bytes.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_json_reader_seeds() {
    use larsal_model::json::{self, Map, Value};
    let keys = Map::from([("/a".to_owned(), Value::from("/k"))]);
    let settings = larsal_model::json!({
        "clipboard.clear.seconds": 45,
        "X-99": true,
        "state.recent": ["/a", "/b"],
        "ssh.socket_override": "/x",
        "state.key_files": keys
    });
    let export = larsal_model::json!({"format": "larsal-settings", "version": 1, "settings": settings.clone()});
    let saved = larsal_model::json!({"Work stuff": "tag:work", "\u{1f600}": "b", "\u{ff5e}": "a"});
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let seeds: Vec<String> = vec![
        json::to_string_pretty(&settings),
        json::to_string_pretty(&export),
        json::to_string_pretty(&saved),
        r#"{"Allow":["a.example","b.example"],"Deny":["c.example"],"Realm":""}"#.into(),
        json::to_string(&larsal_model::json!({"Probe": "2026-10-30T12:00:00Z"})),
        r#"{"v":1,"cmd":"open","paths":["/tmp/a.larsalvault"]}"#.into(),
        r#"{"v":1,"cmd":"activate","paths":null}"#.into(),
        r#"{"v":1,"v":1,"cmd":"lock"}"#.into(),
        r#""q\"b\\\/\n\r\t\b\f\u0001\u00e9\uD83D\uDE00""#.into(),
        "[0,-0,12,-12,1.5,1e5,1E-5,-0.0e+0,1e-400,9223372036854775808,18446744073709551616]".into(),
        deep(json::MAX_DEPTH),
        deep(json::MAX_DEPTH + 1),
        " \t\r\n{ \"a\" : [ null , true , false ] } \n".into(),
        "[1,]".into(),
        r#"{"a":1,}"#.into(),
        r#""\uD83D""#.into(),
        "1e400".into(),
        r#"{"a" 1}"#.into(),
    ];
    let seeds: Vec<Vec<u8>> = seeds.into_iter().map(String::into_bytes).collect();
    write_seeds("json_reader", &seeds);
}

fn test_data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn write_seeds(target: &str, seeds: &[Vec<u8>]) {
    let dir = PathBuf::from(format!(
        "{}/../../fuzz/corpus/{target}",
        env!("CARGO_MANIFEST_DIR")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, s) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}")), s).unwrap();
    }
}

fn joined(mode: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![mode];
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(0x1E);
        }
        out.extend(*p);
    }
    out
}

/// Seeds of the `onepux_import` target (E4-S13): the demo .1pux of FEA-08
/// cases 08-29 and 08-30 as a file, and its kinds of content zipped by the
/// target. Format: see fuzz/fuzz_targets/onepux_import.rs.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_onepux_seeds() {
    let export = br#"{"accounts":[{"attrs":{"name":"Demo"},"vaults":[{"attrs":{"name":"Personal","avatar":"avatar.png"},"items":[
      {"favIndex":1,"createdAt":1700000000,"updatedAt":1700000100,"state":"archived","overview":{"title":"Login","url":"https://example.com/","urls":[{"url":"https://example.org/"}],"tags":["work"]},
       "details":{"loginFields":[{"value":"u","designation":"username"},{"value":"p","designation":"password"}],"notesPlain":"n","password":"x",
        "sections":[{"title":"","fields":[{"title":"otp","id":"t1","value":{"totp":"otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP"}},{"title":"two","id":"t2","value":{"totp":"JBSWY3DP"}},{"id":"pin","value":{"concealed":"1234"}}]},
         {"title":"More","fields":[{"title":"born","value":{"date":1700000000}},{"title":"mail","value":{"email":{"email_address":"a@example.com"}}},{"title":"home","value":{"address":{"street":"s","city":"c","state":"st","zip":"z","country":"co"}}},{"title":"m","value":{"monthYear":202206}},{"title":"doc","value":{"file":{"documentId":"doc1","fileName":"note.txt"}}}]}],
        "documentAttributes":{"documentId":"doc2","fileName":"note.txt"}}}]},{"attrs":{"name":"Shared"},"items":[]}]}]}"#;
    write_seeds(
        "onepux_import",
        &[
            joined(0, &[&test_data("demo.1pux")]),
            joined(1, &[export, b"\x89PNG\r\n\x1a\nicon", b"attachment one\n", b"attachment two\n"]),
            joined(3, &[export, b"\x89PNG", b"one"]),
            joined(1, &[b"{bad"]),
            joined(1, &[br#"{"accounts":[{"vaults":[{"attrs":5,"items":{}},{"attrs":{"name":7},"items":[1,null,{"overview":[],"details":"x"}]}]}]}"#]),
        ],
    );
}

/// Seeds of the `opvault_import` target (E4-S13): the demo OPVault files of
/// FEA-08 cases 08-31 to 08-39, and item, folder and attachment plaintexts
/// in their shapes. Format: see fuzz/fuzz_targets/opvault_import.rs.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_opvault_seeds() {
    let dir = format!(
        "{}/tests/data/demo.opvault/default",
        env!("CARGO_MANIFEST_DIR")
    );
    let file = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
    let attachment =
        file("00000000000000000000000000000001_AAAABBBBCCCCDDDDEEEEFFFF00001111.attachment");
    let o = br#"{"title":"Demo login","url":"https://example.com","URLs":[{"u":"https://example.com"},{"u":"https://example.org"}],"tags":["demo"]}"#;
    let d = br#"{"notesPlain":"n","password":"p","fields":[{"designation":"username","value":"u"},{"designation":"password","value":"q"}],"sections":[
      {"title":"","fields":[{"n":"TOTP_a","k":"concealed","t":"x","v":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8"},{"n":"TOTP_b","k":"concealed","t":"y","v":"JBSWY3DP"},{"n":"password","k":"concealed","t":"","v":"s3"},{"n":"url","k":"string","t":"website","v":"https://x"},{"n":"e","k":"monthYear","t":"expiry date","v":202506}]},
      {"title":"Extra","fields":[{"n":"pin","k":"string","t":"PIN","v":"1"},{"n":"born","k":"date","t":"born","v":"1700000000"},{"n":"home","k":"address","t":"home","v":{"street":"s","city":"c"}},{"n":"addressx","k":"concealed","t":"z","v":5}]}]}"#;
    let meta = br#"{"itemUUID":"00000000000000000000000000000001","trashed":false}"#;
    write_seeds(
        "opvault_import",
        &[
            joined(
                0,
                &[
                    &file("profile.js"),
                    &file("folders.js"),
                    &file("band_0.js"),
                    &file("band_5.js"),
                    &attachment,
                ],
            ),
            joined(1, &[o, d, br#"{"title":"F"}"#, meta, b"attachment"]),
            joined(
                1 | 2 | 16 | 32,
                &[
                    o,
                    br#"{"sections":[{"title":"","fields":[{"n":"TOTP_1","v":"x"}]}]}"#,
                    b"{}",
                    br#"{"trashed":true}"#,
                    b"",
                ],
            ),
            joined(1 | 4 | 8, &[b"[]", b"{bad", b"{}", b"{bad", b"c"]),
            joined(
                0,
                &[
                    b"var profile={\"salt\":\"AAAA\",\"iterations\":1};",
                    b"loadFolders({});",
                    b"ld({});",
                ],
            ),
        ],
    );
}

/// Seeds of the `v1_import` target (E4-S13): every version 1 demo file of
/// FEA-08 cases 08-48 to 08-56, and records in their shapes for the built
/// mode (the meta records come from the target, whose markers are hex
/// only). Format: see fuzz/fuzz_targets/v1_import.rs.
#[test]
#[ignore = "writes the fuzz seed corpus; run on purpose"]
fn write_v1_seeds() {
    fn field(r: &mut Vec<u8>, kind: u16, data: &[u8]) {
        r.extend(kind.to_le_bytes());
        r.extend(u32::try_from(data.len()).unwrap().to_le_bytes());
        r.extend(data);
    }
    let text = |t: &str| [t.as_bytes(), &[0]].concat();
    let t0 = [0x1F, 0x70, 0x42, 0x30, 0x45];
    let group = |id: u32, name: &str, level: u16| {
        let mut r = Vec::new();
        field(&mut r, 1, &id.to_le_bytes());
        field(&mut r, 2, &text(name));
        for k in 3..=5 {
            field(&mut r, k, &t0);
        }
        field(&mut r, 7, &1u32.to_le_bytes());
        field(&mut r, 8, &level.to_le_bytes());
        field(&mut r, 0xFFFF, &[]);
        r
    };
    let entry = |fid: u8, gid: u32, title: &str, notes: &str, att: Option<(&str, &[u8])>| {
        let mut r = Vec::new();
        field(&mut r, 1, &[fid; 16]);
        field(&mut r, 2, &gid.to_le_bytes());
        field(&mut r, 3, &0u32.to_le_bytes());
        for (k, v) in [
            (4, title),
            (5, "http://example.com/"),
            (6, "user"),
            (7, "pw"),
            (8, notes),
        ] {
            field(&mut r, k, &text(v));
        }
        field(&mut r, 12, &[0x1F, 0x71, 0x52, 0xA8, 0x00]);
        if let Some((name, data)) = att {
            field(&mut r, 13, &text(name));
            field(&mut r, 14, data);
        }
        field(&mut r, 0xFFFF, &[]);
        r
    };
    let records = [
        group(1, "Internet", 0),
        group(2, "Subgroup 1", 1),
        group(3, "Unexpanded", 2),
        group(5, "Backup", 0),
        entry(0x0A, 1, "Test entry", "Lorem ipsum\ndolor", Some(("attachment.txt", b"hello world\n"))),
        entry(0x0C, 1, "Custom Icon", "", None),
        entry(0x0D, 2, "Auto", "Auto-Type: {USERNAME}\r\nAuto-Type-Window: W0\nAuto-Type-1: x\nAuto-Type-Window-1: W1\n\nlast", None),
    ]
    .concat();
    let png = b"\x89PNG\r\n\x1a\nicon";
    let mut icons = Vec::new();
    for n in [1u32, 1, 1, u32::try_from(png.len()).unwrap()] {
        icons.extend(n.to_le_bytes());
    }
    icons.extend(png);
    icons.extend([0x0C; 16]);
    icons.extend(0u32.to_le_bytes());
    icons.extend(5u32.to_le_bytes());
    icons.extend(0u32.to_le_bytes());
    let mut tree = 2u32.to_le_bytes().to_vec();
    tree.extend([1, 0, 0, 0, 1, 3, 0, 0, 0, 0]);
    let mut seeds: Vec<Vec<u8>> = [
        "v1-aes.bin",
        "v1-keyfile-hex.bin",
        "v1-composite.bin",
        "v1-cp1252.bin",
    ]
    .iter()
    .map(|n| joined(0, &[&test_data(n)]))
    .collect();
    seeds.push([&[1u8, 4, 3][..], &records].concat());
    seeds.push([&[3u8, 4, 3][..], &records].concat());
    let mut with_meta = vec![5u8, 4, 3];
    with_meta.extend(&records);
    with_meta.push(0x1E);
    with_meta.extend(&icons);
    with_meta.push(0x1E);
    with_meta.extend(&tree);
    seeds.push(with_meta);
    seeds.push(vec![
        1, 2, 0, 1, 0, 4, 0, 0, 0, 7, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0,
    ]);
    let dir = PathBuf::from(format!(
        "{}/../../fuzz/corpus/v1_import",
        env!("CARGO_MANIFEST_DIR")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    write_seeds("v1_import", &seeds);
}
