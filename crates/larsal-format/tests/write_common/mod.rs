//! Shared helpers for the writer tests (E3-S7): read a document, write it
//! back, save and reopen whole files, and decrypt what Larsal saved.
#![allow(dead_code)]

use larsal_crypto::cipher;
use larsal_crypto::kdf::{self, Host, KdfParams, SpeedRecord, Verdict};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::stream::FieldStream;
use larsal_format::document::encode::{base64_encode, uuid_to_text};
use larsal_format::document::write::{self, SaveStamp};
use larsal_format::document::{Options, read};
use larsal_format::header::{Header, read_header};
use larsal_format::integrity::read_blocks;
use larsal_format::keys::{Credentials, TransformedKey, composite_key, final_keys, password_part};
use larsal_format::limits::Limits;
use larsal_format::{Opened, OpenedVault, Saved, SavedFile, open, save};
use larsal_model::{Kdf, Time, Uuid, Vault};

/// The document root element name (stored encoded, name rule).
pub const ROOT_NAME: &[u8] = &[
    0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6C, 0x65,
];
/// 2026-10-24T19:19:32Z, the open time of the FMT-11 rows.
pub const OPEN: Time = Time(63_928_466_372);
/// 2026-10-24T19:17:16Z, the save time of the writer rows.
pub const SAVE: Time = Time(63_928_466_236);

pub fn root_name() -> &'static str {
    std::str::from_utf8(ROOT_NAME).unwrap()
}

pub fn id(b: u8) -> Uuid {
    Uuid([b; 16])
}

pub fn idt(b: u8) -> String {
    uuid_to_text(id(b))
}

pub fn zero_key() -> Vec<u8> {
    vec![0; 64]
}

pub fn chacha(key: &[u8]) -> FieldStream {
    FieldStream::chacha20_from_stream_key(&SecretBytes::new(key.to_vec())).unwrap()
}

/// `plain` XORed with the keystream of `key` from byte `at`, as base64.
pub fn enc(key: &[u8], at: usize, plain: &[u8]) -> String {
    let mut s = chacha(key);
    s.apply(&mut vec![0; at]).unwrap();
    let mut buf = plain.to_vec();
    s.apply(&mut buf).unwrap();
    base64_encode(&buf)
}

/// base64 `b64` XORed back with the keystream of `key` from byte `at`.
pub fn dec(key: &[u8], at: usize, b64: &str) -> Vec<u8> {
    let mut buf = larsal_format::document::encode::base64_decode(b64);
    let mut s = chacha(key);
    s.apply(&mut vec![0; at]).unwrap();
    s.apply(&mut buf).unwrap();
    buf
}

/// A document with `meta` inside `Meta` and `root` inside `Root`.
pub fn doc(meta: &str, root: &str) -> String {
    let r = root_name();
    format!("<{r}><Meta>{meta}</Meta><Root>{root}</Root></{r}>")
}

/// A document whose root group, id(01) named `R`, holds `content`.
pub fn g(content: &str) -> String {
    doc(
        "",
        &format!(
            "<Group><UUID>{}</UUID><Name>R</Name>{content}</Group>",
            idt(1)
        ),
    )
}

/// An entry with id `n` holding `content`.
pub fn entry(n: u8, content: &str) -> String {
    format!("<Entry><UUID>{}</UUID>{content}</Entry>", idt(n))
}

pub fn s(key: &str, value: &str) -> String {
    format!("<String><Key>{key}</Key><Value>{value}</Value></String>")
}

/// Reads `xml` with the all-zero stream key and the given pool.
pub fn read_with(xml: &str, key: &[u8], pool: &[&[u8]]) -> Vault {
    let lim = Limits::DEFAULT;
    let opts = Options {
        open_time: OPEN,
        limits: &lim,
        v3_header: None,
    };
    read(xml.as_bytes(), &mut chacha(key), pool, &opts)
        .unwrap_or_else(|e| panic!("read failed: {e:?}"))
        .vault
}

pub fn read_doc(xml: &str) -> Vault {
    read_with(xml, &zero_key(), &[])
}

/// The fixed save stamp of the writer rows: 64 padding bytes `ab`.
pub fn stamp() -> SaveStamp {
    SaveStamp {
        padding_hex: "ab".repeat(64),
        time: SAVE,
    }
}

/// Writes `v` at the version Larsal picks, with stream key `key`.
pub fn write_with(v: &Vault, key: &[u8]) -> String {
    write_minor(v, write::minor_version(v), key)
}

/// Writes `v` as version 4.`minor`, with stream key `key`.
pub fn write_minor(v: &Vault, minor: u16, key: &[u8]) -> String {
    let w = write::write(v, minor, &mut chacha(key), &stamp()).unwrap();
    String::from_utf8(w.xml().to_vec()).unwrap()
}

pub fn write_doc(v: &Vault) -> String {
    write_with(v, &zero_key())
}

/// Read, then write, with the all-zero stream key.
pub fn rw(xml: &str) -> String {
    write_doc(&read_doc(xml))
}

/// The line of `xml` that holds `needle`, with its TABs.
pub fn line<'a>(xml: &'a str, needle: &str) -> &'a str {
    xml.lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{xml}"))
}

/// The lines of `xml` between the line holding `start` and the next line
/// holding `end`, both excluded.
pub fn between<'a>(xml: &'a str, start: &str, end: &str) -> Vec<&'a str> {
    let mut it = xml.lines().skip_while(|l| !l.contains(start));
    it.next().unwrap_or_else(|| panic!("no {start:?}"));
    it.take_while(|l| !l.contains(end)).collect()
}

/// Element names of the lines at exactly `depth` TABs, in order.
pub fn names_at(xml: &str, depth: usize) -> Vec<String> {
    xml.lines()
        .filter(|l| l.len() > depth && l.bytes().take_while(|&b| b == b'\t').count() == depth)
        .filter(|l| !l[depth..].starts_with("</"))
        .map(|l| {
            l[depth + 1..]
                .split(['>', '/', ' '])
                .next()
                .unwrap()
                .to_owned()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Whole files.

/// A host with speed records, so the cost check needs no calibration run.
pub fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        // A sane record (under 45,000 KiB per ms), so no calibration runs.
        argon2_record: Some(SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 1,
            ms: 1_000,
        }),
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

pub fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// Cheap settings for tests that save often: AES-KDF with 1 round.
pub fn cheap(v: &mut Vault) {
    v.encryption.kdf = Kdf::AesKdf { rounds: 1 };
}

/// Saves `v` with password `password`; panics on anything but a file.
pub fn save_pw(v: &Vault, password: &str) -> SavedFile {
    try_save(v, password, None).unwrap_or_else(|e| panic!("save failed: {e:?}"))
}

pub fn try_save(
    v: &Vault,
    password: &str,
    previous: Option<&TransformedKey>,
) -> Result<SavedFile, larsal_format::Error> {
    let p = pw(password);
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    match save(v, &creds, previous, &mut host(), &Limits::DEFAULT, None)? {
        Saved::File(f) => Ok(*f),
        Saved::Ask(r) => panic!("cost question {r:?}"),
    }
}

/// Opens `file` with password `password`.
pub fn open_pw(file: &[u8], password: &str) -> Box<OpenedVault> {
    let p = pw(password);
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    match open(file, &creds, &mut host(), &Limits::DEFAULT, None)
        .unwrap_or_else(|e| panic!("open failed: {e:?}"))
    {
        Opened::Vault(v) => v,
        Opened::Ask(r) => panic!("cost question {r:?}"),
    }
}

/// The parts of a saved file, decrypted with the test's own code from the
/// card formulas (FMT-04, FMT-05, FMT-06, FMT-08): the header, the raw
/// plaintext (still gzipped when the vault compresses), and U.
pub struct Parts {
    pub header: Header,
    pub raw: Vec<u8>,
    pub inner_and_doc: Vec<u8>,
}

/// Decrypts a file Larsal saved with password `password`.
pub fn parts(file: &[u8], password: &str) -> Parts {
    let header = read_header(file, &Limits::DEFAULT).unwrap();
    let composite = composite_key(Some(&password_part(&pw(password))), None, None);
    let mut h = host();
    let Verdict::Run(c) = kdf::assess(&header.kdf, &mut h, &Limits::DEFAULT.kdf, None).unwrap()
    else {
        panic!("test settings need no question")
    };
    let t = kdf::derive(&composite, &c).unwrap();
    let keys = final_keys(&header.master_seed, &t);
    let stream = &file[header.len + 64..];
    let blocks = read_blocks(stream, &keys.hmac_key, &Limits::DEFAULT).unwrap();
    let ct: Vec<u8> = blocks.concat();
    let raw = cipher::decrypt(header.cipher, &keys.cipher_key, &header.iv, &ct)
        .unwrap()
        .expose()
        .to_vec();
    let inner_and_doc = if raw.starts_with(&[0x1F, 0x8B]) {
        larsal_format::payload::gunzip(&raw, usize::MAX)
            .unwrap()
            .expose()
            .to_vec()
    } else {
        raw.clone()
    };
    Parts {
        header,
        raw,
        inner_and_doc,
    }
}

/// The inner header length of U (FMT-09): walks the fields to the end field.
pub fn inner_len(u: &[u8]) -> usize {
    let mut pos = 0;
    loop {
        let id = u[pos];
        let len = u32::from_le_bytes(u[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5 + len;
        if id == 0 {
            return pos;
        }
    }
}

/// The document text of a saved file.
pub fn saved_doc(file: &[u8], password: &str) -> String {
    let u = parts(file, password).inner_and_doc;
    String::from_utf8(u[inner_len(&u)..].to_vec()).unwrap()
}

/// The 64-byte inner stream key of a saved file (FMT-09.4).
pub fn saved_stream_key(file: &[u8], password: &str) -> Vec<u8> {
    let u = parts(file, password).inner_and_doc;
    assert_eq!(&u[9..14], &[0x02, 0x40, 0, 0, 0]);
    u[14..78].to_vec()
}

/// The KDF salt or seed in a header.
pub fn salt_of(h: &Header) -> Vec<u8> {
    match &h.kdf {
        KdfParams::AesKdf { seed, .. } => seed.clone(),
        KdfParams::Argon2 { salt, .. } => salt.clone(),
    }
}

/// A small vault read from `xml`, with cheap KDF settings for saving.
pub fn cheap_vault(xml: &str) -> Vault {
    let mut v = read_doc(xml);
    cheap(&mut v);
    v
}

/// The field 3 records of a saved file's inner header: flags and content.
pub fn saved_pool(file: &[u8], password: &str) -> Vec<(u8, Vec<u8>)> {
    let u = parts(file, password).inner_and_doc;
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let id = u[pos];
        let len = u32::from_le_bytes(u[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let data = &u[pos + 5..pos + 5 + len];
        if id == 3 {
            out.push((data[0], data[1..].to_vec()));
        }
        pos += 5 + len;
        if id == 0 {
            return out;
        }
    }
}

/// The inner header field ids of a saved file, in order.
pub fn saved_inner_ids(file: &[u8], password: &str) -> Vec<u8> {
    let u = parts(file, password).inner_and_doc;
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let id = u[pos];
        let len = u32::from_le_bytes(u[pos + 1..pos + 5].try_into().unwrap()) as usize;
        out.push(id);
        pos += 5 + len;
        if id == 0 {
            return out;
        }
    }
}

/// Opens `file` (password `demo-pass`), makes its KDF cheap, saves it, and
/// returns the saved bytes.
pub fn resave(file: &[u8]) -> Vec<u8> {
    let mut v = open_pw(file, "demo-pass").vault;
    cheap(&mut v);
    save_pw(&v, "demo-pass").bytes
}
