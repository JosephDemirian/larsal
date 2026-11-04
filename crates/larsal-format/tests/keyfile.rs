//! Card FMT-18 test rows for the key file reader (story E3-S3). Each test is
//! named after its row. Where the card gives a digest of a Hashed file, the
//! test checks both `F = SHA256(file)` and that digest, which proves the test
//! built the card's exact bytes.

use larsal_crypto::hash::sha256;
use larsal_format::error::{Error, KeyFileReason};
use larsal_format::keyfile::{KeyFileKind, create_key_file, read_key_file, xml2_layout};
use larsal_format::limits::{Limit, Limits};
use std::io::{Cursor, Read, Seek, SeekFrom};

use KeyFileKind::{Hashed, Hex64, Raw32, Xml1, Xml2};

// ---------- helpers ----------

fn read(b: &[u8]) -> Result<(KeyFileKind, Vec<u8>), Error> {
    read_key_file(Cursor::new(b), &Limits::DEFAULT).map(|k| (k.kind(), k.key().expose().to_vec()))
}

fn hex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn pad32(b: &[u8]) -> Vec<u8> {
    let mut f = b.to_vec();
    f.resize(32, 0);
    f.truncate(32);
    f
}

fn d60() -> [u8; 32] {
    std::array::from_fn(|i| 0x60 + i as u8)
}

const HEX_D60: &str = "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F";
const V2: &str = "<Meta><Version>2.0</Version></Meta>";
const B: &str = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=";

fn k2() -> String {
    format!("<Key><Data Hash=\"4D8D274F\">{HEX_D60}</Data></Key>")
}
fn r(body: &str) -> String {
    format!("<KeyFile>{body}</KeyFile>")
}
fn rvk() -> String {
    r(&format!("{V2}{}", k2()))
}
fn rv(t: &str) -> String {
    r(&format!("<Meta><Version>{t}</Version></Meta>{}", k2()))
}
fn x2(d: &[u8; 32]) -> Vec<u8> {
    xml2_layout(d).expose().to_vec()
}
fn x2s() -> String {
    String::from_utf8(x2(&d60())).unwrap()
}
fn x1(b: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>1.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data>{b}</Data>\n\t</Key>\n</KeyFile>\n"
    )
}
fn x40() -> Vec<u8> {
    (0x40..=0x5f).collect()
}

fn le16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn be16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}
fn le32(s: &str) -> Vec<u8> {
    s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect()
}
fn be32(s: &str) -> Vec<u8> {
    s.chars().flat_map(|c| (c as u32).to_be_bytes()).collect()
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[track_caller]
fn assert_d60(b: &[u8]) {
    assert_eq!(read(b).unwrap(), (Xml2, d60().to_vec()));
}
#[track_caller]
fn assert_hashed(b: &[u8]) {
    assert_eq!(read(b).unwrap(), (Hashed, sha256(&[b]).expose().to_vec()));
}
#[track_caller]
fn assert_hashed_as(b: &[u8], digest: &str) {
    assert_hashed(b);
    assert_eq!(
        sha256(&[b]).expose(),
        hex(digest).as_slice(),
        "test input differs from the card"
    );
}
#[track_caller]
fn assert_reason(b: &[u8], reason: KeyFileReason) {
    assert_eq!(read(b).unwrap_err(), Error::KeyFile(reason));
}
/// The card's version text as the error carries it: kept only when it is
/// at most 16 characters of digits and dots, else empty (LD-87).
#[track_caller]
fn assert_version(b: &[u8], text: &str) {
    let plain = text.chars().count() <= 16 && text.chars().all(|c| c.is_ascii_digit() || c == '.');
    let shown = if plain { text } else { "" };
    assert_reason(b, KeyFileReason::UnsupportedVersion(shown.to_owned()));
}

/// A read-and-seek source of `len` zero bytes that allocates nothing.
struct Zeros {
    len: u64,
    pos: u64,
}
impl Read for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.len - self.pos).min(buf.len() as u64) as usize;
        buf[..n].fill(0);
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for Zeros {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => (self.len as i64 + d) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
        };
        Ok(self.pos)
    }
}

// ---------- FMT-18.1 to FMT-18.5 ----------

#[test]
fn fmt_18_1_a() {
    let b: Vec<u8> = (0..32).collect();
    assert_eq!(read(&b).unwrap(), (Raw32, b.clone()));
    assert!(Raw32.old_format());
}

#[test]
fn fmt_18_1_b() {
    let b = b"00112233445566778899aabbccddeeff";
    assert_eq!(
        read(b).unwrap(),
        (
            Raw32,
            hex("3030313132323333343435353636373738383939616162626363646465656666")
        )
    );
}

#[test]
fn fmt_18_1_c() {
    let b = b"<KeyFile><Meta></Meta></KeyFile>";
    assert_eq!(
        read(b).unwrap(),
        (
            Raw32,
            hex("3c4b657946696c653e3c4d6574613e3c2f4d6574613e3c2f4b657946696c653e")
        )
    );
}

#[test]
fn fmt_18_1_d() {
    let b: Vec<u8> = (0..64).collect();
    assert_hashed_as(
        &b,
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
    );
}

#[test]
fn fmt_18_1_f() {
    assert_version(b"<KeyFile><Meta><Version>xx</Vers", "xx");
}

#[test]
fn fmt_18_2_a() {
    assert_reason(b"", KeyFileReason::Empty);
}

#[test]
fn fmt_18_3_a() {
    assert_eq!(read(&[0xff; 32]).unwrap(), (Raw32, vec![0xff; 32]));
}

const HEX64: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

#[test]
fn fmt_18_4_a() {
    assert_eq!(
        read(HEX64.as_bytes()).unwrap(),
        (Hex64, (0x20..=0x3f).collect())
    );
}

#[test]
fn fmt_18_4_b() {
    assert_eq!(
        read(HEX64.to_uppercase().as_bytes()).unwrap(),
        (Hex64, (0x20..=0x3f).collect())
    );
}

#[test]
fn fmt_18_4_c() {
    assert_hashed_as(
        format!("{HEX64}\n").as_bytes(),
        "e2bf16773f10c925edc43bf60328412e8d8608b178da81b3f6bd599384f89706",
    );
}

#[test]
fn fmt_18_4_d() {
    let s = format!("{}g", &HEX64[..63]);
    assert_hashed_as(
        s.as_bytes(),
        "d5715c3d5b44604c3f3563cf48960ed3f5bd262b764d3d4c482e283b1049c76a",
    );
}

#[test]
fn fmt_18_4_e() {
    let b = cat(&[&[0xEF, 0xBB, 0xBF], HEX64.as_bytes()]);
    assert_hashed_as(
        &b,
        "4eb2f8046e821b270c7b5245eb58f26c3bf8804e69ba025fc8c436397435cc0c",
    );
}

#[test]
fn fmt_18_5_a() {
    let b = b"Larsal demo key file for the hashed kind.\n";
    assert_hashed_as(
        b,
        "e31742b2095b0ee4303149e3cd1889cdb04ee0e01539f3a9798948f593974091",
    );
    assert!(!Hashed.old_format());
}

/// 1 GiB of zero bytes, streamed from a source that holds no buffer: the
/// reader's own memory is a 16 KiB piece plus one 8 KiB block.
#[test]
fn fmt_18_5_b() {
    let k = read_key_file(
        Zeros {
            len: 1 << 30,
            pos: 0,
        },
        &Limits::DEFAULT,
    )
    .unwrap();
    assert_eq!(k.kind(), Hashed);
    assert_eq!(
        k.key().expose(),
        hex("49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14").as_slice()
    );
}

// ---------- FMT-18.6 parse problems ----------

#[test]
fn fmt_18_6_a() {
    let s = x2s().replace("    </Key>\n", "");
    assert_hashed(s.as_bytes());
}

#[test]
fn fmt_18_6_b() {
    let s = rvk().replace("</KeyFile>", "");
    assert_hashed(s.as_bytes());
}

#[test]
fn fmt_18_6_c() {
    assert_version(b"<KeyFile><Meta><Version>2.0", "");
    assert_version(b"<KeyFile><Meta><Version>9.9", "");
}

#[test]
fn fmt_18_6_d() {
    assert_version(b"<KeyFile><Meta><Version>9.9</Vers", "9.9");
}

#[test]
fn fmt_18_6_e() {
    assert_version(
        r(&format!("<Meta><Version>3.0<b/></Version></Meta>{}", k2())).as_bytes(),
        "3.0",
    );
}

#[test]
fn fmt_18_6_f() {
    for (t, want) in [
        ("3.0&bogus;", "3.0"),
        ("3.0\u{1}", "3.0"),
        ("3.0 < 4", "3.0 "),
    ] {
        assert_version(
            r(&format!("<Meta><Version>{t}</Version></Meta>{}", k2())).as_bytes(),
            want,
        );
    }
}

#[test]
fn fmt_18_6_g() {
    let a = format!("<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">60616263646566");
    let b = format!("<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">");
    assert_eq!((a.len(), b.len()), (85, 71));
    assert_reason(a.as_bytes(), KeyFileReason::CheckValueMismatch);
    assert_reason(b.as_bytes(), KeyFileReason::CheckValueMismatch);
}

#[test]
fn fmt_18_6_h() {
    let a = format!("<KeyFile>{V2}<Key><Data Hash=\"E3B0C442\">60616263646566");
    assert_hashed_as(
        a.as_bytes(),
        "815fbedb3f7f5dc419907e7d1e17990afe6601b871f07cb84dc111136bb11fab",
    );
}

#[test]
fn fmt_18_6_i() {
    let mk = |h: &str| {
        r(&format!(
            "{V2}<Key><Data Hash=\"{h}\">60616263<b/>{}</Data></Key>",
            &HEX_D60[8..]
        ))
    };
    assert_eq!(mk("4D8D274F").len(), 162);
    assert_reason(mk("4D8D274F").as_bytes(), KeyFileReason::CheckValueMismatch);
    assert_hashed_as(
        mk("0A32F3FF").as_bytes(),
        "3687ef849f6929833f97aeee7c83a54213e6bffe9763235fc607a5cae8416d65",
    );
}

#[test]
fn fmt_18_6_j() {
    let a = r(&format!(
        "{V2}<Key><Data Hash=\"4D8D274F\">{HEX_D60}</Dat></Key>"
    ));
    let b = format!("<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">{HEX_D60}</Da");
    assert_eq!((a.len(), b.len()), (157, 139));
    assert_hashed_as(
        a.as_bytes(),
        "7b5a16b74864239aa11461d2a305aedec90ed7731a564eabd4622f0ac9b6bdd3",
    );
    assert_hashed_as(
        b.as_bytes(),
        "ddc47b8523d9b46a92e11f2d5f43a171cb90286ebf4ff11086b1828aee3ebd50",
    );
}

#[test]
fn fmt_18_6_k() {
    let vk = format!("{V2}{}", k2());
    let root_attr = |a: &str| format!("<KeyFile {a}>{vk}</KeyFile>");
    let mut files: Vec<(String, usize)> = vec![
        (r(&format!("<!-- a -- b -->{vk}")), 173),
        (r(&format!("<!-- a --->{vk}")), 169),
        (format!("<!-- a -- b -->{}", r(&vk)), 173),
        (
            r(&format!("<Meta><Version>2.0</ Version></Meta>{}", k2())),
            159,
        ),
        (
            r(&format!("< Meta><Version>2.0</Version></Meta>{}", k2())),
            159,
        ),
        (format!("<KeyFile\u{a0}a=\"1\">{vk}</KeyFile>"), 165),
        (
            format!("<x:KeyFile xmlns:x=\"urn:u\" xmlns:y=\"urn:u\">{vk}</y:KeyFile>"),
            194,
        ),
        (r(&format!("<? ?>{vk}")), 163),
        (r(&format!("<?a:b c?>{vk}")), 167),
        (format!("x{}", r(&vk)), 159),
        (r(&format!("]]>{vk}")), 161),
        (r(&format!("<!--\u{1}-->{vk}")), 166),
        (r(&format!("<!--\u{fffe}-->{vk}")), 168),
        (r(&format!("<?p \u{1}?>{vk}")), 165),
        (format!("<KeyFile a=\"\u{1}\">{vk}</KeyFile>"), 164),
        (r(&format!("\u{1}{vk}")), 159),
        (format!("<!--\u{1}-->{}", r(&vk)), 166),
        (r(&format!("<![CDATA[\u{1}]]>{vk}")), 171),
    ];
    for (e, n) in [
        ("<1x/>", 163),
        ("<a$b/>", 164),
        ("<-a/>", 163),
        ("<\u{b7}a/>", 164),
        ("<a\u{d7}b/>", 165),
        ("<\u{300}a/>", 164),
        ("<a:b:c/>", 166),
        ("<:a/>", 163),
        ("<xmlns:a/>", 168),
    ] {
        files.push((r(&format!("{vk}{e}")), n));
    }
    for (a, n) in [
        ("a=\"<\"", 164),
        ("a=b", 162),
        ("a", 160),
        ("a=\"1\"b=\"2\"", 169),
        ("a=\"&\"", 164),
        ("a=\"1\" a=\"1\"", 170),
        ("y:z=\"1\"", 166),
        ("xmlns:xml=\"urn:other\"", 180),
        ("xmlns:xmlns=\"urn:a\"", 178),
        ("xmlns:x=\"http://www.w3.org/XML/1998/namespace\"", 205),
        ("xmlns:x=\"http://www.w3.org/2000/xmlns/\"", 198),
        ("xmlns=\"http://www.w3.org/XML/1998/namespace\"", 203),
        ("xmlns=\"http://www.w3.org/2000/xmlns/\"", 196),
        ("xmlns:x=\"\"", 169),
        (
            "xmlns:a=\"urn:x\" xmlns:b=\"urn:x\" a:z=\"1\" b:z=\"2\"",
            206,
        ),
    ] {
        files.push((root_attr(a), n));
    }
    for (f, n) in &files {
        assert_eq!(f.len(), *n, "{f}");
        assert_hashed(f.as_bytes());
    }
    assert_hashed_as(
        files[0].0.as_bytes(),
        "2263765e499c0096191605c00818d0483b6580907afe1e56b2ec2a968c6dabf6",
    );
    assert_hashed_as(
        r(&format!("{vk}<1x/>")).as_bytes(),
        "d6c2532f4bd9b850145894dcd0b1865441c11a5a34386f27c0a8975ef45c925c",
    );
    assert_hashed_as(
        format!("x{}", r(&vk)).as_bytes(),
        "4d4754bad67b61151368d7338ff84a652a31bc40a4979573ba600b48faf4d9a9",
    );
}

#[test]
fn fmt_18_6_l() {
    let k = k2();
    let files = [
        (
            format!("<KeyFile xmlns:x=\"urn:a\" xmlns:x=\"urn:b\">{V2}{k}</KeyFile>"),
            190,
        ),
        (
            format!("<KeyFile xmlns=\"urn:a\" xmlns=\"urn:b\">{V2}{k}</KeyFile>"),
            186,
        ),
        (
            format!("<KeyFile xmlns:x=\"urn:a\" x:z=\"1\" xmlns:x=\"urn:a\">{V2}{k}</KeyFile>"),
            198,
        ),
        (
            format!(
                "<KeyFile xmlns:x=\"urn:a\" xmlns:x=\"urn:b\"><x:Meta><Version>2.0</Version></x:Meta>{k}</KeyFile>"
            ),
            194,
        ),
        (
            r(&format!(
                "{V2}<Key><Data Hash=\"4D8D274F\" xmlns:x=\"urn:a\" xmlns:x=\"urn:a\">{HEX_D60}</Data></Key>"
            )),
            190,
        ),
    ];
    for (f, n) in &files {
        assert_eq!(f.len(), *n);
        assert_d60(f.as_bytes());
    }
}

#[test]
fn fmt_18_6_m() {
    let vk = format!("{V2}{}", k2());
    let dc00: &[u8] = &[0x00, 0xDC];
    let d800: &[u8] = &[0x00, 0xD8];
    let files = [
        cat(&[
            &le16("<KeyFile><!--"),
            dc00,
            &le16(&format!("-->{vk}</KeyFile>")),
        ]),
        cat(&[
            &le16("<KeyFile><!--"),
            d800,
            &le16(&format!("-->{vk}</KeyFile>")),
        ]),
        cat(&[
            &le16("<KeyFile><?p "),
            dc00,
            &le16(&format!("?>{vk}</KeyFile>")),
        ]),
        cat(&[
            &le16("<KeyFile a=\""),
            dc00,
            &le16(&format!("\">{vk}</KeyFile>")),
        ]),
        cat(&[&le16("<KeyFile>"), dc00, &le16(&format!("{vk}</KeyFile>"))]),
        cat(&[&le16("<KeyFile>"), d800, &le16(&format!("{vk}</KeyFile>"))]),
        cat(&[
            &le16("<KeyFile>"),
            d800,
            d800,
            &le16(&format!(" {vk}</KeyFile>")),
        ]),
    ];
    let sizes = [332, 332, 330, 328, 318, 318, 322];
    for (f, n) in files.iter().zip(sizes) {
        assert_eq!(f.len(), n);
        assert_d60(f);
    }
}

#[test]
fn fmt_18_6_n() {
    let vk = format!("{V2}{}", k2());
    let files = [
        (r(&format!("{vk}<\u{e9}/>")), 163),
        (r(&format!("{vk}<a\u{b7}b/>")), 165),
        (r(&format!("{vk}<xml:a/>")), 166),
        (
            r(&format!("<Meta><Version>2.0</Version ></Meta>{}", k2())),
            159,
        ),
        (format!("<KeyFile xml:lang=\"en\">{vk}</KeyFile>"), 172),
        (
            format!("<KeyFile xmlns:xml=\"http://www.w3.org/XML/1998/namespace\">{vk}</KeyFile>"),
            207,
        ),
        (format!("<KeyFile a=\"&lt;\">{vk}</KeyFile>"), 167),
    ];
    for (f, n) in &files {
        assert_eq!(f.len(), *n);
        assert_d60(f.as_bytes());
    }
}

#[test]
fn fmt_18_6_o() {
    let dc00: &[u8] = &[0x00, 0xDC];
    let d800: &[u8] = &[0x00, 0xD8];
    let a = cat(&[
        &le16(&format!("<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">")),
        dc00,
        &le16(&format!("{HEX_D60}</Data></Key></KeyFile>")),
    ]);
    let b = cat(&[
        &le16(&format!(
            "<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">{HEX_D60}"
        )),
        d800,
        &le16("</Data></Key></KeyFile>"),
    ]);
    let c = cat(&[
        &le16("<KeyFile><Meta><Version>2.0"),
        dc00,
        &le16(&format!("</Version></Meta>{}</KeyFile>", k2())),
    ]);
    let d = cat(&[
        &le16("<KeyFile><Meta><Version>2.0"),
        d800,
        &le16(&format!("x</Version></Meta>{}</KeyFile>", k2())),
    ]);
    let e = cat(&[
        &le16("<KeyFile><Meta><Version>1.0"),
        dc00,
        &le16(&format!(
            "</Version></Meta><Key><Data>{B}</Data></Key></KeyFile>"
        )),
    ]);
    assert_eq!(
        [a.len(), b.len(), c.len(), d.len(), e.len()],
        [318, 318, 318, 320, 246]
    );
    assert_reason(&a, KeyFileReason::DataUnreadable);
    assert_reason(&b, KeyFileReason::DataUnreadable);
    // The error text is a Rust string: the unpaired surrogate shows as U+FFFD.
    assert_version(&c, "2.0\u{fffd}");
    assert_version(&d, "2.0\u{fffd}x");
    assert_eq!(read(&e).unwrap(), (Xml1, x40()));
}

// ---------- FMT-18.7 encodings ----------

const DECL16: &str = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>";

#[test]
fn fmt_18_7_a() {
    assert_d60(&cat(&[&[0xEF, 0xBB, 0xBF], &x2(&d60())]));
}

#[test]
fn fmt_18_7_b() {
    let s = x2s().replace("encoding=\"UTF-8\"", "encoding=\"UTF-16\"");
    assert_d60(&cat(&[&[0xFF, 0xFE], &le16(&s)]));
}

#[test]
fn fmt_18_7_c() {
    assert_d60(&cat(&[&[0xFE, 0xFF], &be16(&format!("{DECL16}{}", rvk()))]));
}

#[test]
fn fmt_18_7_d() {
    assert_d60(&le16(&format!("{DECL16}{}", rvk())));
}

#[test]
fn fmt_18_7_e() {
    assert_d60(format!("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{}", rvk()).as_bytes());
}

#[test]
fn fmt_18_7_f() {
    assert_hashed(
        format!(
            "<?xml version=\"1.0\" encoding=\"x-unknown-enc\"?>{}",
            rvk()
        )
        .as_bytes(),
    );
}

#[test]
fn fmt_18_7_g() {
    assert_hashed(format!("\n  {}", x2s()).as_bytes());
}

#[test]
fn fmt_18_7_h() {
    let s = x2s();
    assert_d60(s.split_once('\n').unwrap().1.as_bytes());
}

#[test]
fn fmt_18_7_i() {
    let f = format!("<?xml version=\"1.0\" encoding=\"windows-1252\"?>{}", rvk());
    assert_eq!(f.len(), 203);
    assert_hashed_as(
        f.as_bytes(),
        "d6d5676158a61414c82e87538711e233d76a764b6d69dc3ea79ab8aaf0a93ad5",
    );
}

#[test]
fn fmt_18_7_j() {
    assert_d60(&cat(&[&[0xFF, 0xFE, 0, 0], &le32(&rvk())]));
    assert_d60(&cat(&[
        &[0xFF, 0xFE, 0, 0],
        &le32(&format!(
            "<?xml version=\"1.0\" encoding=\"UTF-32\"?>{}",
            rvk()
        )),
    ]));
    assert_d60(&cat(&[&[0, 0, 0xFE, 0xFF], &be32(&rvk())]));
}

#[test]
fn fmt_18_7_k() {
    assert_d60(&be16(&rvk()));
    assert_d60(&le32(&rvk()));
    assert_d60(&be32(&rvk()));
}

#[test]
fn fmt_18_7_l() {
    let f = format!("<?xml version=\"1.0\" encoding=\"US-ASCII\"?>{}", rvk());
    assert_eq!(f.len(), 199);
    assert_hashed_as(
        f.as_bytes(),
        "bda3ce7c6f32a7567169a55b93f283ba18c1405bbafd1f4682a4afde30a390d2",
    );
    assert_hashed(format!("<?xml version=\"1.0\" encoding=\"ASCII\"?>{}", rvk()).as_bytes());
}

#[test]
fn fmt_18_7_m() {
    let a = cat(&[
        &[0xEF, 0xBB, 0xBF],
        format!("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{}", rvk()).as_bytes(),
    ]);
    let b = format!("{DECL16}{}", rvk());
    assert_eq!((a.len(), b.len()), (204, 197));
    assert_hashed_as(
        &a,
        "35bc52fd8204a9fc052ba3606cbb64302f4ae185ec283e2f92a998c0b1931ec2",
    );
    assert_hashed_as(
        b.as_bytes(),
        "e5f8d9a700789ff2922bfe60078be70dcc22f450a2b1102cd5b45712495efdca",
    );
}

#[test]
fn fmt_18_7_n() {
    let a = be16(&format!("{DECL16}{}", rvk()));
    assert_eq!(a.len(), 394);
    assert_hashed_as(
        &a,
        "d793a1c27ddccaa54a11466b1b0d5601695b82ca6dc2a7e99ace5ea635609921",
    );
    assert_d60(&be16(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?>{}",
        rvk()
    )));
}

#[test]
fn fmt_18_7_o() {
    for n in [
        "utf8",
        "u-t_f.8",
        "iso_8859-1",
        "ISO8859-1",
        "latin1",
        "Latin-1",
    ] {
        assert_d60(format!("<?xml version=\"1.0\" encoding=\"{n}\"?>{}", rvk()).as_bytes());
    }
}

/// `R(V2 <Key><Data Hash="4D8D274F">60616263` + `bad` + the last 56 digits + `</Data></Key>)`.
fn data_with(bad: &[u8]) -> Vec<u8> {
    cat(&[
        format!("<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">60616263").as_bytes(),
        bad,
        format!("{}</Data></Key></KeyFile>", &HEX_D60[8..]).as_bytes(),
    ])
}

#[test]
fn fmt_18_7_p() {
    let f = data_with(&[0xFF]);
    assert_eq!(f.len(), 159);
    assert_hashed_as(
        &f,
        "a282ee4bc1b886c8372467c64f1e7e47fbc8203f6da19814f01a78b6067b50b7",
    );
}

#[test]
fn fmt_18_7_q() {
    let a = cat(&[rvk().as_bytes(), &[0xFF]]);
    assert_hashed_as(
        &a,
        "dc54c6f7a52360577fbbe5eb5edb12548a0775e1f66f78b66efee898c8f205c9",
    );
    let b = cat(&[&x2(&d60()), &[b' '; 7913], &[0xFF]]);
    assert_eq!(b.len(), 8192);
    assert_hashed_as(
        &b,
        "2709185d882938ac5bb64befea11d667b4b702f6f5fd02702f8d8536a2eaae88",
    );
    let c = cat(&[&x2(&d60()), &[b' '; 7914], &[0xFF]]);
    assert_eq!(c.len(), 8193);
    assert_d60(&c);
}

#[test]
fn fmt_18_7_r() {
    let mk = |n: usize| {
        let key = data_with(&[0xFF]);
        let key = &key[9 + V2.len()..key.len() - 10]; // just the Key element
        cat(&[
            format!(
                "<KeyFile><Meta><Version>3.0</Version></Meta><!--{}-->",
                "p".repeat(n)
            )
            .as_bytes(),
            key,
            b"</KeyFile>",
        ])
    };
    assert_hashed(&mk(5000));
    assert_version(&mk(9000), "3.0");
}

#[test]
fn fmt_18_7_s() {
    assert_hashed(&cat(&[rvk().as_bytes(), &[0xC0, 0xAF]]));
    assert_hashed(&cat(&[rvk().as_bytes(), &[0xED, 0xA0, 0x80]]));
    assert_d60(&cat(&[rvk().as_bytes(), &[0xE2, 0x82]]));
}

#[test]
fn fmt_18_7_t() {
    let f = cat(&[
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>",
        &data_with(&[0xE9]),
    ]);
    assert_reason(&f, KeyFileReason::DataUnreadable);
}

#[test]
fn fmt_18_7_u() {
    assert_d60(&cat(&[b" \n", rvk().as_bytes()]));
    assert_hashed(&le16(&format!(" {}", rvk())));
}

#[test]
fn fmt_18_7_v() {
    let decls = [
        (
            "<?xml version=\"1.1\"?>",
            Some((
                179,
                "4f64208c5f480627d0e33d5ded2900222c3d18a98f212e667679a091d81be9bc",
            )),
        ),
        (
            "<?xml version=\"1.00\"?>",
            Some((
                180,
                "a8b07d9f919ca91b3b59d6a28f2f158458a292bd070678f7c75ddf28a67feba6",
            )),
        ),
        ("<?xml version=\"1.0 \"?>", None),
        (
            "<?xml encoding=\"UTF-8\" version=\"1.0\"?>",
            Some((
                196,
                "608e35b3ddabf213e868466f5adfbb03b82565405b68fba2fd72557abb7e0f34",
            )),
        ),
        ("<?xml encoding=\"UTF-8\"?>", None),
        ("<?xml?>", None),
        ("<?xml version=\"1.0\" version=\"1.0\"?>", None),
        (
            "<?xml version=\"1.0\" standalone=\"yes\" encoding=\"UTF-8\"?>",
            None,
        ),
        (
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" encoding=\"UTF-8\"?>",
            Some((
                230,
                "218ecb00e08332656b118dc820f74c189c5d6bdebda20560525b196bcd5feffa",
            )),
        ),
        ("<?xml version=\"1.0\" standalone=\"maybe\"?>", None),
        ("<?xml version=\"1.0\" standalone=\"YES\"?>", None),
        ("<?xml version=\"1.0\" foo=\"bar\"?>", None),
        ("<?xml version=\"1.0\" Encoding=\"UTF-8\"?>", None),
        ("<?xml version=\"1.0\" x:encoding=\"UTF-8\"?>", None),
        (
            "<?XML version=\"1.0\"?>",
            Some((
                179,
                "e05c571fc6a5b4ff2ba3127c3e66832af09e5a9c4bce6810a02df5f748f204cb",
            )),
        ),
        ("<?Xml version=\"1.0\"?>", None),
        (
            "<?xml version=\"1.0\"encoding=\"UTF-8\"?>",
            Some((
                195,
                "06ee09112d95ce7a7ec3ba79555495b83ba6ab728c513822ba58e8858a31a804",
            )),
        ),
        ("<?xml version=\"1.0' encoding=\"UTF-8\"?>", None),
        ("<?xml version=1.0?>", None),
    ];
    for (d, check) in decls {
        let f = format!("{d}{}", rvk());
        assert_hashed(f.as_bytes());
        if let Some((n, digest)) = check {
            assert_eq!(f.len(), n, "{d}");
            assert_hashed_as(f.as_bytes(), digest);
        }
    }
}

#[test]
fn fmt_18_7_w() {
    for (n, digest) in [
        (
            "_utf8",
            Some("291efd19ac92e8ea6edd4ebb16ae8ca94b54d583ca4d49a6431d33384d7fb09e"),
        ),
        (
            "UTF+8",
            Some("dd7bdfdf4e341626755e338c101c4c3833ba212316bca318390fd5e69e98c447"),
        ),
        (
            "utf 8",
            Some("ca0ea40201e18e6c91d30115e611f87475e8833e284bfa483c8bf939ae8519e8"),
        ),
        ("8utf", None),
        (".utf8", None),
        ("-utf8", None),
        ("", None),
    ] {
        let f = format!("<?xml version=\"1.0\" encoding=\"{n}\"?>{}", rvk());
        assert_hashed(f.as_bytes());
        if let Some(d) = digest {
            assert_eq!(f.len(), 196);
            assert_hashed_as(f.as_bytes(), d);
        }
    }
}

#[test]
fn fmt_18_7_x() {
    let vk = format!("{V2}{}", k2());
    let a = format!("<!--c--><?xml version=\"1.0\"?>{}", rvk());
    assert_eq!(a.len(), 187);
    assert_hashed_as(
        a.as_bytes(),
        "e3f30f9810cdf8bcd981b7dca89cf86a08adac1552bc805db7505e9e090d9171",
    );
    assert_hashed(format!("<?xml version=\"1.0\"?><?xml version=\"1.0\"?>{}", rvk()).as_bytes());
    let c = r(&format!("{V2}<?xml version=\"1.0\"?>{}", k2()));
    assert_eq!(c.len(), 179);
    assert_hashed_as(
        c.as_bytes(),
        "25d348573074cd8aac72f971b30a59ae7104e3dc694293f206a5abfc4c66f105",
    );
    assert_hashed(r(&format!("{V2}<?XML version=\"1.0\"?>{}", k2())).as_bytes());
    assert_hashed(r(&format!("{V2}<?xMl a?>{}", k2())).as_bytes());
    assert_d60(r(&format!("{V2}<?xmlfoo bar?>{}", k2())).as_bytes());
    let g = format!("{}<?xml version=\"1.0\"?>", r(&vk));
    assert_eq!(g.len(), 179);
    assert_d60(g.as_bytes());
}

#[test]
fn fmt_18_7_y() {
    for d in [
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>",
        "<?xml version=\"1.0\" standalone=\"no\"?>",
        "<?xml\tversion=\"1.0\"\nencoding=\"UTF-8\"\r\n?>",
        "<?xml  version = \"1.0\"  encoding = \"UTF-8\" ?>",
        "<?xml version=\"1.0\" standalone=\"yes\" standalone=\"no\"?>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\" encoding=\"u-t_f.8\"?>",
        "<?xml-stylesheet type=\"text/xsl\" href=\"a.xsl\"?>",
    ] {
        assert_d60(format!("{d}{}", rvk()).as_bytes());
    }
}

#[test]
fn fmt_18_7_z() {
    let mk = |e1: &str, e2: &str| {
        cat(&[
            format!("<?xml version=\"1.0\" encoding=\"{e1}\" encoding=\"{e2}\"?>").as_bytes(),
            &data_with(&[0xE9]),
        ])
    };
    let a = mk("ISO-8859-1", "UTF-8");
    assert_eq!(a.len(), 219);
    assert_hashed_as(
        &a,
        "5fa515ec710cac8991d1c348038261f2c1520649485fb9f02c8f727e65668485",
    );
    assert_reason(&mk("UTF-8", "ISO-8859-1"), KeyFileReason::DataUnreadable);
    for (e1, e2) in [
        ("UTF-8", "x-unknown-enc"),
        ("x-unknown-enc", "UTF-8"),
        ("UTF-8", "UTF-16"),
        ("UTF-8", "_utf8"),
    ] {
        assert_hashed(
            format!(
                "<?xml version=\"1.0\" encoding=\"{e1}\" encoding=\"{e2}\"?>{}",
                rvk()
            )
            .as_bytes(),
        );
    }
}

#[test]
fn fmt_18_7_aa() {
    let decl = "<?xml version=\"1.0\" encoding=\"UTF-16LE\"?>";
    assert_eq!(decl.len(), 41);
    let mk = |k: usize| cat(&[decl.as_bytes(), &vec![b'x'; k], &le16(&rvk())]);
    assert_d60(&mk(41));
    assert_hashed_as(
        &mk(39),
        "4ba55ee8fb18bfcafac445574b2cffea571603185099111ed82f50cf976d0a0b",
    );
    assert_hashed_as(
        &mk(40),
        "3bf79ee17ac5a635aacbacd0f2038094fadb995f7ed625423a1e8c89f5cca6eb",
    );
    assert_hashed_as(
        &mk(42),
        "0033c424347a4ca019ed66262aa83e223fa0bf8a30b38542de9369a82da4f1fe",
    );
    assert_hashed_as(
        &mk(43),
        "b0972f994411080edb45304e85c8f3edb86e210035185256dedf584fd336241b",
    );
}

#[test]
fn fmt_18_7_ab() {
    let f = cat(&[
        DECL16.as_bytes(),
        b" ",
        &[0x20, 0x00].repeat(40),
        &le16(&rvk()),
    ]);
    assert_eq!(f.len(), 436);
    assert_d60(&f);
}

#[test]
fn fmt_18_7_ac() {
    let mk = |n: usize| {
        cat(&[
            &[0xEF, 0xBB, 0xBF],
            b"<?xml version=\"1.0\" encoding=\"UTF-16LE\"?>",
            &vec![b'x'; n],
            &le16(&rvk()),
        ])
    };
    assert_d60(&mk(38));
    assert_hashed_as(
        &mk(37),
        "ced23665f4aa7e6b45db34ce780f965e47ea4aa7511796ee338cd0434c4b1c2d",
    );
    assert_hashed_as(
        &mk(39),
        "ae3add10a59781ada80f86767ef07c6c0e795fe342b67c83c668762bcd6dee8e",
    );
}

#[test]
fn fmt_18_7_ad() {
    let f = cat(&[&be16(DECL16), &le16(&rvk())]);
    assert_eq!(f.len(), 394);
    assert_d60(&f);
}

#[test]
fn fmt_18_7_ae() {
    let a = cat(&[
        b"<?xml version=\"1.0\" encoding=\"UTF-32LE\"?>",
        &[b'x'; 123],
        &le32(&rvk()),
    ]);
    assert_eq!(a.len(), 796);
    assert_hashed_as(
        &a,
        "8c97a938198b89b47405bbe0b62d1a0601a4da3bb006e1407ef015b1e8d34792",
    );
    let iso = |tail: &str| {
        cat(&[
            &[0xEF, 0xBB, 0xBF],
            format!(
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{tail}{}",
                rvk()
            )
            .as_bytes(),
        ])
    };
    assert_eq!(iso("   ").len(), 207);
    assert_hashed_as(
        &iso("   "),
        "7d2e3c99c8f39f6975fb69d8e0ef9dcf7d24b74a638996f133fdaf8487948c94",
    );
    assert_hashed_as(
        &iso("        "),
        "546806974f1e199c7420139a8c170a65aa5ed474ebad1431285837b77273b569",
    );
    assert_hashed_as(
        &iso("\n"),
        "58394062d503f5498adc0e81d1366a8cd64a0f34fd4b529413fad8c4101947d2",
    );
}

#[test]
fn fmt_18_7_af() {
    let d = |e: &str| format!("<?xml version=\"1.0\" encoding=\"{e}\"?>");
    let files = [
        cat(&[&[0xFF, 0xFE], &le16(&format!("{}{}", d("UTF-16LE"), rvk()))]),
        cat(&[
            &[0xFF, 0xFE],
            &le16(&format!("{}  {}", d("UTF-16LE"), rvk())),
        ]),
        cat(&[&[0xFE, 0xFF], &be16(&format!("{}{}", d("UTF-16BE"), rvk()))]),
        cat(&[
            &[0xFF, 0xFE, 0, 0],
            &le32(&format!("{}{}", d("UTF-32LE"), rvk())),
        ]),
        cat(&[
            &[0, 0, 0xFE, 0xFF],
            &be32(&format!("{}{}", d("UTF-32BE"), rvk())),
        ]),
    ];
    for (f, n) in files.iter().zip([400, 404, 400, 800, 800]) {
        assert_eq!(f.len(), n);
        assert_d60(f);
    }
}

#[test]
fn fmt_18_7_ag() {
    let doc = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}", rvk());
    for f in [le16(&doc), be16(&doc), le32(&doc), be32(&doc)] {
        assert_d60(&f);
    }
    assert_hashed_as(
        &cat(&[&[0xFF, 0xFE], &le16(&doc)]),
        "9b552c3b800adc5a75071cbc6e6a6cc4f881631ccf25e6930b9ebf0fe35e0afc",
    );
    let with = |c: &str| le16(&doc.replacen("?>", &format!("?>{c}"), 1));
    let long = with(&format!("<!--{}-->", "p".repeat(4200)));
    assert_eq!(long.len(), 8806);
    assert_hashed_as(
        &long,
        "d0428748962d35140606f9cbd0324d21c456d6052d046f7f5e52def4441366c6",
    );
    let short = with(&format!("<!--{}-->", "p".repeat(3000)));
    assert_eq!(short.len(), 6406);
    assert_d60(&short);
    let e9 = with("<!--\u{e9}-->");
    assert_eq!(e9.len(), 408);
    assert_hashed_as(
        &e9,
        "df8c5570c8e0228124a78c505a6afc0a5bde3e9d0509ede6e54b9e66e003e64d",
    );
}

#[test]
fn fmt_18_7_ah() {
    let iso_utf8 = format!(
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" encoding=\"UTF-8\"?>{}",
        rvk()
    );
    let a = cat(&[&[0xEF, 0xBB, 0xBF], iso_utf8.as_bytes()]);
    assert_eq!(a.len(), 221);
    assert_hashed_as(
        &a,
        "109dbfd11df5dabd88f030c074823da330a93dc4d41b9cfa4a16c7e60f406145",
    );
    assert_eq!(iso_utf8.len(), 218);
    assert_d60(iso_utf8.as_bytes());
    let c = le16(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\" encoding=\"UTF-8\"?>{}",
        rvk()
    ));
    assert_eq!(c.len(), 428);
    assert_d60(&c);
    let d = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-32\" encoding=\"ISO-8859-1\"?>{}",
        rvk()
    );
    assert_eq!(d.len(), 219);
    assert_d60(d.as_bytes());
    let e = format!(
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" encoding=\"UTF-32\"?>{}",
        rvk()
    );
    assert_hashed_as(
        e.as_bytes(),
        "91d6c7d64257746b2c4b8750bd81758a88f74d0accbe89d338c4d22803b69b20",
    );
    let f = le16(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" encoding=\"UTF-16LE\"?><!--\u{e9}-->{}",
        rvk()
    ));
    assert_eq!(f.len(), 448);
    assert_d60(&f);
}

#[test]
fn fmt_18_7_ai() {
    let doc = format!("<?xml version=\"1.0\" encoding=\"UTF-32\"?>{}", rvk());
    assert_eq!(le32(&doc).len(), 788);
    assert_d60(&le32(&doc));
    assert_hashed_as(
        &be32(&doc),
        "75c420c02fee9c1052a460a5aafd0af2eeeb620b9772ad07c37647ae7b8db1ff",
    );
}

#[test]
fn fmt_18_7_aj() {
    let f = |n: &str| format!("<?xml version=\"1.0\" encoding=\"{n}\"?>{}", rvk());
    assert_hashed_as(
        f("CP819").as_bytes(),
        "b0f8770d3a451f5dc53b3403547ec42f9a9711b144c2ebb1fa39979b415aae58",
    );
    for (n, len) in [
        ("CP819", 196),
        ("IBM819", 197),
        ("csISOLatin1", 202),
        ("iso-ir-100", 201),
        ("l1", 193),
    ] {
        assert_eq!(f(n).len(), len);
        assert_hashed(f(n).as_bytes());
    }
    assert_hashed_as(
        f("l1").as_bytes(),
        "bc5193504a9802d41cd91470a9b41b0ec8ff7e4789dc30d320960f51a3187603",
    );
    let ucs2 = cat(&[&[0xFF, 0xFE], &le16(&f("ISO-10646-UCS-2"))]);
    let ucs4 = cat(&[&[0xFF, 0xFE, 0, 0], &le32(&f("ISO-10646-UCS-4"))]);
    assert_eq!((ucs2.len(), ucs4.len()), (414, 828));
    assert_hashed_as(
        &ucs2,
        "fca8f7cf71a0d6d144abce245315acfeb45c62948c823577ef5fd9973b99c999",
    );
    assert_hashed_as(
        &ucs4,
        "a6851913ede9f730de7408796ef7f3f85d28152ac2391bab1db5efa3d0cb8d76",
    );
}

#[test]
fn fmt_18_7_ak() {
    let l = |e: &str| format!("<?xml version=\"1.0\"{}{e}?>", " ".repeat(8200));
    let files = [
        (format!("{}{}", l(""), rvk()), 8379),
        (format!("{}{}", l(" encoding=\"UTF-8\""), rvk()), 8396),
        (format!("{}{}", l(" encoding=\"ISO-8859-1\""), rvk()), 8401),
    ];
    for (f, n) in &files {
        assert_eq!(f.len(), *n);
        assert_d60(f.as_bytes());
    }
    let u16le = format!("{}{}", l(" encoding=\"UTF-16LE\""), rvk());
    assert_eq!(u16le.len(), 8399);
    assert_hashed_as(
        u16le.as_bytes(),
        "29b005fd6fd56654d5480c7626d0f48daebc9e8feb78eb71334f9e5c7c8610ec",
    );
    let iso_e9 = cat(&[
        l(" encoding=\"ISO-8859-1\"").as_bytes(),
        &data_with(&[0xE9]),
    ]);
    assert_eq!(iso_e9.len(), 8402);
    assert_reason(&iso_e9, KeyFileReason::DataUnreadable);
    let utf8_e9 = cat(&[l("").as_bytes(), &data_with(&[0xE9])]);
    assert_eq!(utf8_e9.len(), 8380);
    assert_hashed_as(
        &utf8_e9,
        "b2efaae67916c5c8357d649c4d69c3cb6ccf4f8fefb8a024b366cabac885cec9",
    );
}

#[test]
fn fmt_18_7_al() {
    let d = cat(&[b"<?xml version=\"1.0\" encoding=\"UTF-32LE\"?>", &[0, 0, 0]]);
    let body = le32(&rvk());
    let a = cat(&[&d, &[0x20, 0x00, 0x01, 0x00].repeat(10), &body]);
    let b = cat(&[&d, &[0x20, 0, 0, 0].repeat(20), &body]);
    let c = cat(&[
        &d,
        &[0x20, 0, 0, 0].repeat(19),
        &[0x20, 0x00, 0x01, 0x00],
        &body,
    ]);
    assert_eq!([a.len(), b.len(), c.len()], [716, 756, 756]);
    assert_d60(&a);
    assert_d60(&b);
    assert_hashed_as(
        &c,
        "9637c6b083b720c741f8c4333bfe556adb3c045b3561e2875d71cd5b359f7516",
    );
}

#[test]
fn fmt_18_7_am() {
    let u = le16(&rvk());
    assert_eq!(u.len(), 316);
    let u32le = le32(&rvk());
    assert_eq!(u32le.len(), 632);
    for f in [
        cat(&[&u, &[0x00, 0xD8, 0x20, 0x00]]),
        cat(&[&u, &[0x00, 0xDC, 0x20, 0x00]]),
        cat(&[&u, &[0x00, 0xD8]]),
        cat(&[&u, &[0x20]]),
        cat(&[&u, &[0x00, 0xD8, 0x00, 0xD8, 0x20, 0x00]]),
        cat(&[&be16(&rvk()), &[0xD8, 0x00, 0x00, 0x20]]),
        cat(&[&u32le, &[0x00, 0xD8, 0x00, 0x00]]),
        cat(&[&u32le, &[0x00, 0x00, 0x11, 0x00]]),
        cat(&[&u32le, &[0x20, 0x00]]),
    ] {
        assert_d60(&f);
    }
}

#[test]
fn fmt_18_7_an() {
    let h = format!("<KeyFile>{V2}{}", k2());
    assert_eq!(h.len(), 148);
    let end_at = |close: &str, last: usize| {
        let mut f = h.clone().into_bytes();
        f.resize(last + 1 - close.len(), b' ');
        f.extend_from_slice(close.as_bytes());
        f.resize(8192, b' ');
        f.push(0xFF);
        f
    };
    for e in [8189, 8190, 8191] {
        let f = end_at("</KeyFile>", e);
        assert_eq!((f.len(), f[e]), (8193, b'>'));
        assert_d60(&f);
    }
    let tail = end_at("<Tail/>", 8191);
    assert_d60(&tail);
    let mut cross = h.clone().into_bytes();
    cross.resize(8186, b' ');
    cross.extend_from_slice(b"</KeyFile>  \xFF");
    assert_eq!(cross.len(), 8199);
    assert_hashed_as(
        &cross,
        "6fde70c9e05dab7bd8e9b4c8572b9a5fc0c16f1db7375e38559fb5ffb04a9817",
    );
    let mut split = b"<KeyFile><!--".to_vec();
    split.resize(8191, b'p');
    split.extend_from_slice(&[0xC3, 0xA9]);
    split.extend_from_slice(format!("-->{V2}{}</KeyFile>", k2()).as_bytes());
    assert_eq!(split.len(), 8345);
    assert_d60(&split);
}

#[test]
fn fmt_18_7_ao() {
    let mk = |v: [u8; 4]| {
        cat(&[
            &le32("<KeyFile><Meta><Version>1."),
            &v,
            &le32(&format!(
                "</Version></Meta><Key><Data>{B}</Data></Key></KeyFile>"
            )),
        ])
    };
    let a = mk([0x00, 0xC0, 0xA1, 0x00]);
    assert_eq!(a.len(), 488);
    assert_eq!(read(&a).unwrap(), (Xml1, x40()));
    assert_version(&mk([0x00, 0xC4, 0xA1, 0x00]), "1.1\u{fffd}");
}

// ---------- FMT-18.8 root ----------

#[test]
fn fmt_18_8_a() {
    let f = "<?xml version=\"1.0\"?>\n<Other><Meta><Version>2.0</Version></Meta></Other>\n";
    assert_eq!(f.len(), 73);
    assert_hashed_as(
        f.as_bytes(),
        "14ecaf2da3c8f918b0b393d28a93503fd3a086afe23d0875155e66e531945cac",
    );
}

#[test]
fn fmt_18_8_b() {
    assert_hashed(x2s().replace("KeyFile", "keyfile").as_bytes());
}

#[test]
fn fmt_18_8_c() {
    assert_d60(
        x2s()
            .replace("<KeyFile>", "<KeyFile xmlns=\"urn:demo\">")
            .as_bytes(),
    );
}

#[test]
fn fmt_18_8_d() {
    assert_hashed(b"just some text that is not xml at all, long enough");
}

#[test]
fn fmt_18_8_e() {
    let a = format!("<x:KeyFile>{V2}{}</x:KeyFile>", k2());
    assert_eq!(a.len(), 162);
    assert_hashed_as(
        a.as_bytes(),
        "10496aa3763a7be7e2023f3d3e1d06cafb5f84e0328bcb5ddd171b73f53965ba",
    );
    assert_d60(format!("<x:KeyFile xmlns:x=\"urn:d\">{V2}{}</x:KeyFile>", k2()).as_bytes());
}

// ---------- FMT-18.9 the walk ----------

#[test]
fn fmt_18_9_a() {
    assert_hashed(
        r(&format!(
            "<Meta><Note>x</Note><Version>2.0</Version></Meta>{}",
            k2()
        ))
        .as_bytes(),
    );
}

#[test]
fn fmt_18_9_b() {
    assert_hashed(
        r(&format!(
            "<Meta><Version>2.0</Version><Note>x</Note></Meta>{}",
            k2()
        ))
        .as_bytes(),
    );
}

#[test]
fn fmt_18_9_c() {
    assert_hashed(
        r(&format!(
            "{V2}<Key><Other/><Data Hash=\"4D8D274F\">{HEX_D60}</Data></Key>"
        ))
        .as_bytes(),
    );
}

#[test]
fn fmt_18_9_d() {
    assert_hashed(r(&format!("<Info/>{V2}{}", k2())).as_bytes());
}

#[test]
fn fmt_18_9_e() {
    assert_d60(r(&format!("<Wrap>{V2}{}</Wrap>", k2())).as_bytes());
}

#[test]
fn fmt_18_9_f() {
    assert_d60(r(&format!("{V2}{}<Tail><X/></Tail>", k2())).as_bytes());
}

#[test]
fn fmt_18_9_g() {
    assert_d60(r(&format!("<!-- c -->{V2}<!-- d -->{}<?pi x?>", k2())).as_bytes());
}

#[test]
fn fmt_18_9_h() {
    assert_d60(&cat(&[&x2(&d60()), b"garbage after root <<<"]));
}

#[test]
fn fmt_18_9_i() {
    assert_hashed(r(&format!("<Meta><Version>2.0<b/></Version></Meta>{}", k2())).as_bytes());
}

#[test]
fn fmt_18_9_j() {
    assert_d60(
        r(&format!(
            "<Meta><Version>2.0</Version><Note/>{}</Meta>",
            k2()
        ))
        .as_bytes(),
    );
}

#[test]
fn fmt_18_9_k() {
    let f = r(&format!(
        "<Meta><Version>2<!--c-->.0</Version></Meta><Key><Data Hash=\"4D8D274F\">60616263<!-- x --><?p q?>{}</Data></Key>",
        &HEX_D60[8..]
    ));
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_9_l() {
    assert_version(
        r(&format!("{V2}{}<Meta><Version>7</Version></Meta>", k2())).as_bytes(),
        "7",
    );
}

#[test]
fn fmt_18_9_m() {
    assert_eq!(rv("2.0&#0;").len(), 162);
    for t in [
        "2.0&#0;",
        "3.0&#0;",
        "3.0&#xD800;",
        "3.0&#x110000;",
        "3.0&#65",
        "3.0&#x;",
        "3.0&;",
        "3.0&",
        "3.0&abc",
        "3.0&amp ",
    ] {
        assert_version(rv(t).as_bytes(), "");
    }
}

#[test]
fn fmt_18_9_n() {
    assert_eq!(rv("2.0]]>").len(), 161);
    assert_version(rv("2.0]]>").as_bytes(), "");
    assert_version(rv("3<!--c-->.0]]>").as_bytes(), "3");
    assert_version(rv("3.0]]").as_bytes(), "3.0]]");
}

#[test]
fn fmt_18_9_o() {
    for t in [
        "3.0&#x41;&#0;",
        "3.0&amp;&#0;",
        "3.0&lt;&#0;",
        "3.0&gt;&#0;",
        "3.0&apos;&#0;",
        "3.0&quot;&#0;",
        "3.0&#65;x&#0;",
    ] {
        assert_version(rv(t).as_bytes(), "");
    }
    for (t, want) in [
        ("3.0&amp;&bogus;", "3.0&"),
        ("3.0&#65;&bogus;", "3.0A"),
        ("3.0&#65;<b/>", "3.0A"),
        ("3.0&#65;\u{1}", "3.0A"),
        ("3.0&#65; < 4", "3.0A "),
    ] {
        assert_version(rv(t).as_bytes(), want);
    }
}

#[test]
fn fmt_18_9_p() {
    for (t, want) in [
        ("3.0<!--c-->x&#0;", "3.0"),
        ("3.0<?p q?>x&#0;", "3.0"),
        ("3.0<![CDATA[x]]>&#0;", "3.0x"),
        ("3.0<![CDATA[x]]>y&#0;", "3.0x"),
    ] {
        assert_version(rv(t).as_bytes(), want);
    }
}

#[test]
fn fmt_18_9_q() {
    let files = [
        ("<KeyFile><Meta><Version>3.0<![CDATA[4.0", 39, "3.0"),
        ("<KeyFile><Meta><Version><![CDATA[3.0", 36, ""),
        ("<KeyFile><Meta><Version>3.0&#65;</Vers", 38, "3.0A"),
        ("<KeyFile><Meta><Version>3.0&#65;", 32, ""),
    ];
    for (f, n, want) in files {
        assert_eq!(f.len(), n);
        assert_version(f.as_bytes(), want);
    }
}

#[test]
fn fmt_18_9_r() {
    let f = rv("2.0&bogus;");
    assert_eq!(f.len(), 165);
    assert_hashed_as(
        f.as_bytes(),
        "4990469e510b6856e8ffa284376351ce097e186f0a16367ace0d0723fd3a49c2",
    );
}

#[test]
fn fmt_18_9_s() {
    let f = r(&format!(
        "{V2}{}<Tail/><Meta><Version>7</Version></Meta>",
        k2()
    ));
    assert_eq!(f.len(), 198);
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_9_t() {
    let f = format!("<KeyFile>{V2}{}<Tail/><<< not xml &&& </Nope>", k2());
    assert_eq!(f.len(), 178);
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_9_u() {
    let f = r(&format!(
        "{V2}<Key><W><Data Hash=\"4D8D274F\">{HEX_D60}</Data></W></Key>"
    ));
    assert_eq!(f.len(), 165);
    assert_d60(f.as_bytes());
}

// ---------- FMT-18.10 to FMT-18.16 ----------

#[test]
fn fmt_18_10_a() {
    let f = x1(B).replace(">1.0<", ">1.00<");
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml1, x40()));
    assert!(Xml1.old_format());
}

#[test]
fn fmt_18_10_b() {
    let f = x1(B).replace(">1.0<", ">1.0.5<");
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml1, x40()));
}

#[test]
fn fmt_18_10_c() {
    assert_version(x2s().replace(">2.0<", "> 2.0<").as_bytes(), " 2.0");
}

#[test]
fn fmt_18_10_d() {
    assert_version(x2s().replace(">2.0<", ">3.0<").as_bytes(), "3.0");
}

#[test]
fn fmt_18_10_e() {
    let f = r(&format!(
        "<Meta><Version>1.0</Version></Meta><Meta><Version>2.0</Version></Meta>{}",
        k2()
    ));
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_11_a() {
    let f = r(&format!(
        "{V2}<Key><Data Hash=\"4D8D274F\">\t{}\r\n{}\t</Data></Key>",
        &HEX_D60[..32],
        &HEX_D60[32..]
    ));
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_11_b() {
    let s = x2s();
    assert_d60(s.replacen("60616263 ", "60616263\u{a0}", 1).as_bytes());
    assert_d60(
        s.replacen("60616263 ", "60616263\u{2003}", 1)
            .replacen("64656667 ", "64656667\u{3000}", 1)
            .as_bytes(),
    );
}

#[test]
fn fmt_18_11_c() {
    assert_reason(
        x2s()
            .replacen("60616263 ", "60616263\u{200b} ", 1)
            .as_bytes(),
        KeyFileReason::DataUnreadable,
    );
}

#[test]
fn fmt_18_11_d() {
    assert_d60(
        r(&format!(
            "{V2}<Key><Data Hash=\"4D8D274F\"><![CDATA[{HEX_D60}]]></Data></Key>"
        ))
        .as_bytes(),
    );
    assert_d60(
        r(&format!(
            "{V2}<Key><Data Hash=\"4D8D274F\">&#x36;{}</Data></Key>",
            &HEX_D60[1..]
        ))
        .as_bytes(),
    );
}

#[test]
fn fmt_18_12_a() {
    assert_eq!(read(x1(B).as_bytes()).unwrap(), (Xml1, x40()));
}

#[test]
fn fmt_18_12_b() {
    assert_eq!(
        read(x1("QEFCQ0RFRkdISUpLTE1OTw==").as_bytes()).unwrap(),
        (Xml1, pad32(&hex("404142434445464748494a4b4c4d4e4f")))
    );
}

#[test]
fn fmt_18_12_c() {
    let f = x1("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZw==");
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml1, x40()));
}

#[test]
fn fmt_18_12_d() {
    assert_reason(x1("QUJD=").as_bytes(), KeyFileReason::DataUnreadable);
}

#[test]
fn fmt_18_12_e() {
    assert_reason(
        x1(&B[..B.len() - 1]).as_bytes(),
        KeyFileReason::DataUnreadable,
    );
}

#[test]
fn fmt_18_12_f() {
    // Base64 of 3E 3F FB FF FE: the URL-safe alphabet gives `-` and `_`.
    assert_reason(x1("Pj_7__4=").as_bytes(), KeyFileReason::DataUnreadable);
    assert_reason(x1("Pj-7__4=").as_bytes(), KeyFileReason::DataUnreadable);
}

#[test]
fn fmt_18_12_g() {
    let f = x1("");
    assert_eq!(f.len(), 133);
    assert_hashed_as(
        f.as_bytes(),
        "c48895ba4d66614191a29343a922bc3229de708b74cc39f1a1013fac907ee6c5",
    );
}

#[test]
fn fmt_18_12_h() {
    let spaced: Vec<&str> = B
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    assert_eq!(
        read(x1(&spaced.join(" ")).as_bytes()).unwrap(),
        (Xml1, x40())
    );
}

#[test]
fn fmt_18_12_i() {
    let f = r(&format!(
        "<Meta><Version>1.0</Version></Meta><Key><Data Hash=\"00000000\">{B}</Data></Key>"
    ));
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml1, x40()));
}

#[test]
fn fmt_18_12_j() {
    assert_eq!(x1("QUJ=").len(), 137);
    assert_eq!(
        read(x1("QUJ=").as_bytes()).unwrap(),
        (Xml1, pad32(&[0x41, 0x42]))
    );
    assert_eq!(read(x1("QR==").as_bytes()).unwrap(), (Xml1, pad32(&[0x41])));
}

#[test]
fn fmt_18_13_a() {
    assert_d60(&x2(&d60()));
    assert!(!Xml2.old_format());
}

#[test]
fn fmt_18_13_b() {
    assert_d60(x2s().replace("4D8D274F", "4d 8d 27 4f").as_bytes());
}

#[test]
fn fmt_18_13_c() {
    assert_reason(
        x2s().replace(" Hash=\"4D8D274F\"", "").as_bytes(),
        KeyFileReason::CheckValueMismatch,
    );
}

#[test]
fn fmt_18_13_d() {
    assert_reason(
        x2s().replace("4D8D274F", "00000000").as_bytes(),
        KeyFileReason::CheckValueMismatch,
    );
}

#[test]
fn fmt_18_13_e() {
    for h in ["0x4D8D274F", "4D8D274F00", "D8D274F"] {
        assert_reason(
            x2s().replace("4D8D274F", h).as_bytes(),
            KeyFileReason::CheckValueMismatch,
        );
    }
}

#[test]
fn fmt_18_13_f() {
    assert_reason(
        x2s().replacen("60616263", "60616Z63", 1).as_bytes(),
        KeyFileReason::DataUnreadable,
    );
}

#[test]
fn fmt_18_13_g() {
    let d: [u8; 32] = std::array::from_fn(|i| 0x60 + i as u8);
    let mut s = String::from_utf8(x2(&d)).unwrap();
    s = s
        .replace("4D8D274F", "2ED1BAD9")
        .replace("            70717273 74757677 78797A7B 7C7D7E7F\n", "");
    assert_eq!(
        read(s.as_bytes()).unwrap(),
        (Xml2, pad32(&hex("606162636465666768696a6b6c6d6e6f")))
    );
}

#[test]
fn fmt_18_13_h() {
    let data: Vec<u8> = (0x60..=0x87).collect();
    let digits: String = data.iter().map(|b| format!("{b:02X}")).collect();
    let f = r(&format!(
        "{V2}<Key><Data Hash=\"EE33E562\">{digits}</Data></Key>"
    ));
    assert_d60(f.as_bytes());
}

#[test]
fn fmt_18_13_i() {
    let f = "<?xml version=\"1.0\"?><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"1870348E\">ABC</Data></Key></KeyFile>";
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml2, pad32(&[0x0a, 0xbc])));
}

#[test]
fn fmt_18_13_j() {
    let f = "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"E3B0C442\"></Data></Key></KeyFile>";
    assert_eq!(f.len(), 94);
    assert_hashed_as(
        f.as_bytes(),
        "d3864a36800abae1f8f9dda925a775fb80bb7d4881df54045e7eff2e05be72f4",
    );
}

#[test]
fn fmt_18_13_k() {
    assert_d60(rvk().replace(HEX_D60, &HEX_D60.to_lowercase()).as_bytes());
}

#[test]
fn fmt_18_13_l() {
    let mk = |s: &str| {
        r(&format!(
            "{V2}<Key><Data Hash=\"4D8D274F\">{HEX_D60}{s}</Data></Key>"
        ))
    };
    assert_eq!(
        (mk("&#0;").len(), mk("]]>").len(), mk("&bogus;").len()),
        (162, 161, 165)
    );
    assert_reason(mk("&#0;").as_bytes(), KeyFileReason::CheckValueMismatch);
    assert_reason(mk("]]>").as_bytes(), KeyFileReason::CheckValueMismatch);
    assert_hashed_as(
        mk("&bogus;").as_bytes(),
        "714fd346d01f3c02a3489d6c27f4ebae6587872297009e9f34025150742e642c",
    );
}

#[test]
fn fmt_18_13_m() {
    let f = format!("<KeyFile>{V2}<Key><Data Hash=\"0A32F3FF\">60616263<!--c-->64656667");
    assert_eq!(f.len(), 95);
    assert_hashed_as(
        f.as_bytes(),
        "291332590918c453ef8a90c2d7ea7e69ffb9aca6791727b4e9be6bcb437fd990",
    );
}

#[test]
fn fmt_18_13_n() {
    let mk = |a: &str| r(&format!("{V2}<Key><Data {a}>{HEX_D60}</Data></Key>"));
    assert_eq!(mk("xmlns:x=\"urn:d\" x:Hash=\"4D8D274F\"").len(), 176);
    assert_reason(
        mk("xmlns:x=\"urn:d\" x:Hash=\"4D8D274F\"").as_bytes(),
        KeyFileReason::CheckValueMismatch,
    );
    assert_reason(
        mk("hash=\"4D8D274F\"").as_bytes(),
        KeyFileReason::CheckValueMismatch,
    );
    let two = mk("Hash=\"4D8D274F\" Hash=\"4D8D274F\"");
    assert_eq!(two.len(), 174);
    assert_hashed_as(
        two.as_bytes(),
        "55ae66f478061dad2ef02d99127b21d4a7d8382d18769ab98b882f9831a078f6",
    );
}

#[test]
fn fmt_18_14_a() {
    let f = format!(
        "<KeyFile><Key><Data Hash=\"4D8D274F\">{}</Data></Key><Meta><Version>2.0</Version></Meta></KeyFile>",
        HEX_D60.to_lowercase()
    );
    assert_reason(f.as_bytes(), KeyFileReason::DataUnreadable);
}

#[test]
fn fmt_18_14_b() {
    assert_reason(
        r(&format!("<Meta></Meta>{}", k2())).as_bytes(),
        KeyFileReason::DataUnreadable,
    );
}

#[test]
fn fmt_18_15_a() {
    let second = "<Data Hash=\"630DCD29\">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data>";
    let f = x2s().replace("        </Data>\n", &format!("        </Data>\n{second}\n"));
    assert_eq!(read(f.as_bytes()).unwrap(), (Xml2, (0..32).collect()));
}

#[test]
fn fmt_18_16_a() {
    let f = "<?xml version=\"1.0\"?>\n<KeyFile>\n<Meta><Version>2.0</Version></Meta>\n</KeyFile>\n";
    assert_eq!(f.len(), 79);
    assert_hashed_as(
        f.as_bytes(),
        "44597f048b4b8c4aa2ff2c3164cfafb33dc3eb03889b6f454004b555f6fa1385",
    );
}

#[test]
fn fmt_18_16_b() {
    let first = r(&format!("{V2}{}<Meta><Version>1.0</Version></Meta>", k2()));
    assert_eq!(read(first.as_bytes()).unwrap(), (Xml1, d60().to_vec()));
    assert!(read(first.as_bytes()).unwrap().0.old_format());
    assert_eq!(read(rvk().as_bytes()).unwrap(), (Xml2, d60().to_vec()));
}

// ---------- FMT-18.17 DOCTYPE (LD-30) ----------

#[test]
fn fmt_18_17_a() {
    let f = x2s()
        .replace(
            "<KeyFile>",
            "<!DOCTYPE KeyFile [<!ENTITY v \"2.0\">]>\n<KeyFile>",
        )
        .replace(">2.0<", ">&v;<");
    assert_reason(f.as_bytes(), KeyFileReason::Dtd);
}

#[test]
fn fmt_18_17_b() {
    let f = format!(
        "<!DOCTYPE KeyFile [<!ENTITY v SYSTEM \"file:///tmp/ver.txt\">]>{}",
        r(&format!("<Meta><Version>&v;</Version></Meta>{}", k2()))
    );
    assert_reason(f.as_bytes(), KeyFileReason::Dtd);
}

#[test]
fn fmt_18_17_c() {
    let f = "<?xml version=\"1.0\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"/>\n";
    assert_eq!(f.len(), 184);
    assert_hashed_as(
        f.as_bytes(),
        "a757419118e07b0cd8d1433e4885aa374abe4060677f8d46e10d1d820520514a",
    );
}

#[test]
fn fmt_18_17_d() {
    let f = "<!DOCTYPE KeyFile><KeyFile><Meta><Version>2.0</Version></Meta></KeyFile>";
    assert_eq!(f.len(), 72);
    // The reference reads it as Hashed (f3bc2ae6...); Larsal refuses it (LD-30).
    assert_eq!(
        sha256(&[f.as_bytes()]).expose(),
        hex("f3bc2ae64fd984694a1ada09fd741e5b6f7b6bb3c32b673b15343c26149830ca").as_slice()
    );
    assert_reason(f.as_bytes(), KeyFileReason::Dtd);
}

// ---------- FMT-18.18 to FMT-18.21 ----------

#[test]
fn fmt_18_18_a() {
    let files: [(Vec<u8>, bool); 5] = [
        ((0..32).collect(), true),
        (HEX64.as_bytes().to_vec(), true),
        (x1(B).into_bytes(), true),
        (x2(&d60()), false),
        (
            b"Larsal demo key file for the hashed kind.\n".to_vec(),
            false,
        ),
    ];
    for (f, warn) in files {
        assert_eq!(read(&f).unwrap().0.old_format(), warn);
    }
}

struct Failing;
impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}
impl Seek for Failing {
    fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
        Ok(100)
    }
}

/// The path and permission cases are larsal-core's (it opens the file); here:
/// a source that cannot be read gives `KeyFile` with reason I/O, not `Io`.
#[test]
fn fmt_18_19_a() {
    let e = read_key_file(Failing, &Limits::DEFAULT).unwrap_err();
    assert_eq!(
        e,
        Error::KeyFile(KeyFileReason::Io(std::io::ErrorKind::PermissionDenied))
    );
}

#[test]
fn fmt_18_19_c() {
    let long = r(&format!(
        "{V2}<Key><Data Hash=\"4D8D274F\">{}</Data></Key>",
        "0".repeat((1 << 20) + 2)
    ));
    assert_reason(long.as_bytes(), KeyFileReason::TooLarge(Limit::KeyFileText));
    let deep = r(&format!(
        "{V2}<Key>{}<Data Hash=\"4D8D274F\">{HEX_D60}</Data>{}</Key>",
        "<W>".repeat(255),
        "</W>".repeat(255)
    ));
    assert_reason(
        deep.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileDepth),
    );
    // One level less passes: the depth limit is 256 with the root at 1.
    let ok = r(&format!(
        "{V2}<Key>{}<Data Hash=\"4D8D274F\">{HEX_D60}</Data>{}</Key>",
        "<W>".repeat(253),
        "</W>".repeat(253)
    ));
    assert_d60(ok.as_bytes());
    // A Hash attribute over the limit is fatal too.
    let hash = r(&format!(
        "{V2}<Key><Data Hash=\"{}\">{HEX_D60}</Data></Key>",
        "0".repeat((1 << 20) + 1)
    ));
    assert_reason(hash.as_bytes(), KeyFileReason::TooLarge(Limit::KeyFileText));
}

#[test]
fn fmt_18_19_d() {
    let a = r(&format!(
        "{V2}{}<Data>{}</Data>",
        k2(),
        "0".repeat((1 << 20) + 2)
    ));
    assert_eq!(a.len(), 1_048_749);
    assert_d60(a.as_bytes());
    let b = r(&format!(
        "{V2}{}<Tail/>{}{}",
        k2(),
        "<W>".repeat(300),
        "</W>".repeat(300)
    ));
    assert_eq!(b.len(), 2265);
    assert_d60(b.as_bytes());
}

#[test]
fn fmt_18_20_a() {
    let f = x2(&d60());
    assert_eq!(f.len(), 278);
    assert_eq!(
        sha256(&[&f]).expose(),
        hex("378592c853a2da62195e983e7442b76230c475c1044f862a4a60ae30484196e3").as_slice()
    );
    let s = String::from_utf8(f).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 12);
    assert_eq!(lines[6], "        <Data Hash=\"4D8D274F\">");
    assert_eq!(lines[7], "            60616263 64656667 68696A6B 6C6D6E6F");
    assert_eq!(lines[8], "            70717273 74757677 78797A7B 7C7D7E7F");
    assert!(s.ends_with("</KeyFile>\n") && !s.contains('\r'));
}

/// The layout part of FMT-18.21-a (file names are larsal-core's): every created
/// file is XML 2.0 in the FMT-18.20 layout, reads back without a warning,
/// and the data differs between files.
#[test]
fn fmt_18_21_a() {
    let mut seen = Vec::new();
    for _ in 0..3 {
        let f = create_key_file().unwrap();
        assert_eq!(f.len(), 278);
        let (kind, key) = read(f.expose()).unwrap();
        assert_eq!(kind, Xml2);
        assert!(!kind.old_format());
        assert_eq!(
            f.expose(),
            xml2_layout(&key.clone().try_into().unwrap()).expose()
        );
        assert!(!seen.contains(&key));
        seen.push(key);
    }
}

// ---------- testdata key files ----------

fn testdata(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../testdata/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The text between `<Data...>` and `</Data>`, whitespace removed.
fn data_text(file: &[u8]) -> String {
    let s = std::str::from_utf8(file).unwrap();
    let start = s.find("<Data").unwrap();
    let start = start + s[start..].find('>').unwrap() + 1;
    let end = s.find("</Data>").unwrap();
    s[start..end].split_whitespace().collect()
}

#[test]
fn testdata_key_files() {
    let b32 = testdata("key-binary32.larsalkey");
    assert_eq!(read(&b32).unwrap(), (Raw32, b32.clone()));
    let h64 = testdata("key-hex64.larsalkey");
    assert_eq!(
        read(&h64).unwrap(),
        (Hex64, hex(std::str::from_utf8(&h64).unwrap()))
    );
    for name in ["key-hashed.larsalkey", "key-cli-made.larsalkey"] {
        let f = testdata(name);
        assert_eq!(
            read(&f).unwrap(),
            (Hashed, sha256(&[&f]).expose().to_vec()),
            "{name}"
        );
    }
    let v1 = testdata("key-xml-v1.larsalkey");
    let want =
        larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, data_text(&v1)).unwrap();
    assert_eq!(read(&v1).unwrap(), (Xml1, pad32(&want)));
    let v2 = testdata("key-xml-v2.larsalkey");
    assert_eq!(read(&v2).unwrap(), (Xml2, pad32(&hex(&data_text(&v2)))));
}

// ---------- E3 fix pass: Checker R2-B1, R2-B2, F09, F11 ----------

/// A read-and-seek source of `head`, then `fill` repeated `n` times, then
/// `tail`, made on the fly (no allocation for the filler).
struct Gen {
    head: Vec<u8>,
    fill: u8,
    n: u64,
    tail: Vec<u8>,
    pos: u64,
}
impl Gen {
    fn new(head: &[u8], fill: u8, n: u64, tail: &[u8]) -> Self {
        Self {
            head: head.to_vec(),
            fill,
            n,
            tail: tail.to_vec(),
            pos: 0,
        }
    }
    fn len(&self) -> u64 {
        self.head.len() as u64 + self.n + self.tail.len() as u64
    }
    fn byte(&self, at: u64) -> u8 {
        let h = self.head.len() as u64;
        if at < h {
            self.head[at as usize]
        } else if at < h + self.n {
            self.fill
        } else {
            self.tail[(at - h - self.n) as usize]
        }
    }
}
impl Read for Gen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.len() - self.pos).min(buf.len() as u64) as usize;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = self.byte(self.pos + i as u64);
        }
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for Gen {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => (self.len() as i64 + d) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
        };
        Ok(self.pos)
    }
}

fn gen_read(g: Gen) -> Result<(KeyFileKind, Vec<u8>), Error> {
    read_key_file(g, &Limits::DEFAULT).map(|k| (k.kind(), k.key().expose().to_vec()))
}

/// `n` distinct attributes ` a0="" a1="" ...`.
fn attrs(n: usize) -> String {
    (0..n).map(|i| format!(" a{i}=\"\"")).collect()
}

#[test]
fn r2_b1_attributes_are_checked_in_linear_time() {
    // 80,000 attributes on a KeyFile root (0.96 MB): before, 5 s growing
    // with the square. Over the per-tag cap: fatal at once.
    let t = std::time::Instant::now();
    let big = format!("<KeyFile{}>{V2}{}</KeyFile>", attrs(80_000), k2());
    assert_reason(
        big.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    // On any other root the attributes are never read: it falls back.
    let svg = format!("<svg{}/>", attrs(80_000));
    assert_hashed(svg.as_bytes());
    // With the cap raised, 80,000 attributes are still checked in linear time.
    let wide = Limits {
        key_file_attributes: 200_000,
        ..Limits::DEFAULT
    };
    let k = read_key_file(Cursor::new(big.as_bytes()), &wide).unwrap();
    assert_eq!((k.kind(), k.key().expose()), (Xml2, &d60()[..]));
    // A repeated attribute and a repeated expanded name stay parse problems.
    let dup = format!("<KeyFile{} a5=\"\">{V2}{}</KeyFile>", attrs(50_000), k2());
    assert!(matches!(
        read_key_file(Cursor::new(dup.as_bytes()), &wide)
            .unwrap()
            .kind(),
        Hashed
    ));
    assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
}

#[test]
fn r2_b1_attribute_cap_boundary() {
    let at = format!("<KeyFile{}>{V2}{}</KeyFile>", attrs(1_024), k2());
    assert_d60(at.as_bytes());
    let over = format!("<KeyFile{}>{V2}{}</KeyFile>", attrs(1_025), k2());
    assert_reason(
        over.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    // Namespace declarations count too.
    let decls: String = (0..1_025)
        .map(|i| format!(" xmlns:p{i}=\"urn:{i}\""))
        .collect();
    assert_reason(
        format!("<KeyFile{decls}>{V2}{}</KeyFile>", k2()).as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
}

#[test]
fn r2_b1_many_prefix_bindings() {
    // 1,000 bindings in scope, each looked up by an attribute: no scan.
    let wide = Limits {
        key_file_attributes: 3_000,
        ..Limits::DEFAULT
    };
    let decls: String = (0..1_000)
        .map(|i| format!(" xmlns:p{i}=\"urn:{i}\""))
        .collect();
    let uses: String = (0..1_000).map(|i| format!(" p{i}:z=\"1\"")).collect();
    let x = format!("<KeyFile{decls}{uses}>{V2}{}</KeyFile>", k2());
    let k = read_key_file(Cursor::new(x.as_bytes()), &wide).unwrap();
    assert_eq!(k.kind(), Xml2);
    // Two prefixes bound to one namespace with the same local name: parse problem.
    let clash = "<KeyFile xmlns:a=\"urn:x\" xmlns:b=\"urn:x\" a:z=\"1\" b:z=\"2\">".to_owned()
        + V2
        + &k2()
        + "</KeyFile>";
    assert_hashed(clash.as_bytes());
}

#[test]
fn r2_b2_over_long_tokens() {
    let mib = 1 << 20;
    // Inside a KeyFile document: fatal TooLarge, never a fall-back.
    let name = format!("<KeyFile><{}/>{V2}{}</KeyFile>", "n".repeat(mib + 1), k2());
    assert_reason(
        name.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    let attr_name = format!(
        "<KeyFile {}=\"1\">{V2}{}</KeyFile>",
        "a".repeat(mib + 1),
        k2()
    );
    assert_reason(
        attr_name.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    let ns = format!(
        "<KeyFile xmlns:x=\"{}\">{V2}{}</KeyFile>",
        "u".repeat(mib + 1),
        k2()
    );
    assert_reason(
        ns.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    let entity = format!(
        "<KeyFile>{V2}<Key><Data Hash=\"4D8D274F\">&{};</Data></Key></KeyFile>",
        "e".repeat(mib + 1)
    );
    assert_reason(
        entity.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    let end_name = format!("<KeyFile>{V2}{}</{}></KeyFile>", k2(), "n".repeat(mib + 1));
    assert_reason(
        end_name.as_bytes(),
        KeyFileReason::TooLarge(Limit::KeyFileAttributes),
    );
    // Before the root is known: a parse problem, so the file falls back.
    let root = format!("<{}/>", "r".repeat(mib + 1));
    assert_hashed(root.as_bytes());
    let pi = format!("<?{} x?>{}", "t".repeat(mib + 1), rvk());
    assert_hashed(pi.as_bytes());
    let decl = format!(
        "<?xml version=\"1.0\" encoding=\"{}\"?>{}",
        "u".repeat(mib + 1),
        rvk()
    );
    assert_hashed(decl.as_bytes());
    let doctype = format!("<!DOCTYPE {}>{}", "d".repeat(mib + 1), rvk());
    assert_hashed(doctype.as_bytes());
    // Exactly at the limit is no error by itself.
    let at = format!("<KeyFile><{}/>{V2}{}</KeyFile>", "n".repeat(mib), k2());
    assert_hashed(at.as_bytes()); // the empty element ends the walk before Key
}

#[test]
fn r2_b2_long_declaration_reads_normally() {
    // 32 MiB of spaces inside the XML declaration: read as usual (FMT-18.7-ak).
    let g = Gen::new(
        b"<?xml version=\"1.0\"",
        b' ',
        32 << 20,
        format!("?>{}", rvk()).as_bytes(),
    );
    assert_eq!(gen_read(g).unwrap(), (Xml2, d60().to_vec()));
}

#[test]
fn f09_hash_on_a_data_that_does_not_count() {
    // A top-level Data counts for nothing: its Hash is never gathered, so an
    // oversized one is no error (D-18-3 applies only to what the walk takes).
    let x = format!(
        "<KeyFile>{V2}{}<Data Hash=\"{}\">x</Data></KeyFile>",
        k2(),
        "0".repeat((1 << 20) + 2)
    );
    assert_d60(x.as_bytes());
}

#[test]
fn f11_utf8_overlong_three_byte_form() {
    // E0 80..9F starts an overlong form: invalid UTF-8 in the first block.
    for second in [0x80u8, 0x9F] {
        let mut x = r(&format!("{V2}{}<!--", k2())).into_bytes();
        x.truncate(x.len() - "</KeyFile>".len());
        x.extend([0xE0, second, 0xBF]);
        x.extend(b"--></KeyFile>");
        assert_hashed(&x);
    }
    // E0 A0 80 (U+0800) is valid there.
    let mut ok = r(&format!("{V2}{}<!--", k2())).into_bytes();
    ok.truncate(ok.len() - "</KeyFile>".len());
    ok.extend([0xE0, 0xA0, 0x80]);
    ok.extend(b"--></KeyFile>");
    assert_d60(&ok);
}

// Peak memory probes (R2-B2): each runs alone under `/usr/bin/time -l`.

#[test]
#[ignore = "run by r2_b2_memory_stays_flat"]
fn mem_probe_declaration_spaces() {
    let g = Gen::new(
        b"<?xml version=\"1.0\"",
        b' ',
        32 << 20,
        format!("?>{}", rvk()).as_bytes(),
    );
    assert_eq!(gen_read(g).unwrap().0, Xml2);
}

#[test]
#[ignore = "run by r2_b2_memory_stays_flat"]
fn mem_probe_huge_element_name() {
    let g = Gen::new(b"<KeyFile><", b'n', 32 << 20, b"/></KeyFile>");
    assert_eq!(
        gen_read(g).unwrap_err(),
        Error::KeyFile(KeyFileReason::TooLarge(Limit::KeyFileAttributes))
    );
}

#[test]
#[ignore = "run by r2_b2_memory_stays_flat"]
fn mem_probe_huge_root_name() {
    let g = Gen::new(b"<", b'r', 32 << 20, b"/>");
    assert_eq!(gen_read(g).unwrap().0, Hashed);
}

#[test]
#[ignore = "run by r2_b2_memory_stays_flat"]
fn mem_probe_huge_namespace_value() {
    let g = Gen::new(b"<KeyFile xmlns:x=\"", b'u', 32 << 20, b"\"/>");
    assert_eq!(
        gen_read(g).unwrap_err(),
        Error::KeyFile(KeyFileReason::TooLarge(Limit::KeyFileAttributes))
    );
}

#[test]
#[ignore = "run by r2_b2_memory_stays_flat"]
fn mem_probe_huge_declaration_value() {
    // R3-m3: a 32 MiB encoding value is over the token cap before the root
    // is known, so the file falls back (hashed) with flat memory.
    let g = Gen::new(
        b"<?xml version=\"1.0\" encoding=\"",
        b'u',
        32 << 20,
        format!("\"?>{}", rvk()).as_bytes(),
    );
    assert_eq!(gen_read(g).unwrap().0, Hashed);
}

#[test]
fn r2_b2_memory_stays_flat() {
    // Before the fix each probe held its whole token: 64 MB or more of
    // UTF-16 units for these 32 MiB inputs (the Checker saw 1.12 GB for 128
    // MiB of spaces). After: a few MB above the test binary's own size.
    if !cfg!(target_os = "macos") {
        return;
    }
    let exe = std::env::current_exe().unwrap();
    for probe in [
        "mem_probe_declaration_spaces",
        "mem_probe_huge_element_name",
        "mem_probe_huge_root_name",
        "mem_probe_huge_namespace_value",
        "mem_probe_huge_declaration_value",
    ] {
        let out = std::process::Command::new("/usr/bin/time")
            .arg("-l")
            .arg(&exe)
            .args(["--exact", probe, "--ignored", "--test-threads=1"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{probe} failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let rss: u64 = err
            .lines()
            .find(|l| l.contains("maximum resident set size"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .expect("time -l output");
        assert!(rss < 40 << 20, "{probe}: peak {} MB", rss >> 20);
    }
}

#[test]
fn r3_m4_prefix_scope_ends_with_its_element() {
    // FMT-18.6: a prefix declared on one element is not bound on a later
    // sibling. Using it there is a parse problem, so the file falls back.
    let x = format!(
        "<KeyFile><Meta xmlns:p=\"urn:x\"><Version>2.0</Version></Meta><p:Key><Data Hash=\"4D8D274F\">{HEX_D60}</Data></p:Key></KeyFile>"
    );
    assert_hashed(x.as_bytes());
    // Control: declared on the root, the prefix is bound for both.
    let ok = format!(
        "<KeyFile xmlns:p=\"urn:x\"><Meta><Version>2.0</Version></Meta><p:Key><Data Hash=\"4D8D274F\">{HEX_D60}</Data></p:Key></KeyFile>"
    );
    assert_d60(ok.as_bytes());
    // The same after an empty element that declared it.
    let empty = format!("<KeyFile>{V2}<Key><X xmlns:p=\"urn:x\"/></Key><p:Y/></KeyFile>");
    assert_hashed(empty.as_bytes());
}
