//! Shared helpers for the payload-layer tests: a test-only version 4 vault
//! builder (FMT-01.26 plan (d): our own crypto re-seals demo content), a
//! fixed host for the cost check (CRY-02.14 test hooks), and the demo vaults
//! in testdata/.
#![allow(dead_code)]

use larsal_crypto::cipher::{self, Cipher};
use larsal_crypto::kdf::{self, Host, SpeedRecord, Verdict};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::Error;
use larsal_format::header::{AES256_ID, CHACHA20_ID, TWOFISH_ID};
use larsal_format::integrity::{header_hmac, write_blocks};
use larsal_format::kdf_params::parse_kdf;
use larsal_format::keyfile::{KeyFileKey, read_key_file};
use larsal_format::keys::{
    Credentials, FinalKeys, SlotMode, SoftwareKey, composite_key, final_keys, password_part,
};
use larsal_format::limits::Limits;
use larsal_format::payload::{Open, Payload, open_payload};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

pub fn testdata(name: &str) -> Vec<u8> {
    let p = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata")).join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The CRY-02.14 test hooks: 16 GiB, 8 processors, fixed speed records
/// (T25: Argon2 rec_I = 10, rec_m = 65,536, rec_ms = 1,000; AES-KDF
/// 100,000,000 rounds per second), so no calibration runs.
pub fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 4,
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

/// Opens with a password only, default limits, the fixed host.
pub fn open(file: &[u8], password: &str) -> Result<Open, Error> {
    let p = pw(password);
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    open_payload(file, &creds, &mut host(), &Limits::DEFAULT, None)
}

pub fn open_lim(file: &[u8], password: &str, limits: &Limits) -> Result<Open, Error> {
    let p = pw(password);
    let creds = Credentials {
        password: Some(&p),
        ..Default::default()
    };
    open_payload(file, &creds, &mut host(), limits, None)
}

/// The opened payload, or a panic naming what came back instead.
pub fn opened(r: Result<Open, Error>) -> Box<Payload> {
    match r {
        Ok(Open::Opened(p)) => p,
        other => panic!("expected an opened payload, got {other:?}"),
    }
}

pub fn kind(r: Result<Open, Error>) -> Error {
    match r {
        Err(e) => e,
        Ok(o) => panic!("expected an error, got {o:?}"),
    }
}

// ---------------------------------------------------------------------------
// Building blocks of a version 4 file.

pub fn field(id: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![id];
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v
}

pub fn preamble(minor: u16) -> Vec<u8> {
    let mut v = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
    v.extend_from_slice(&minor.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v
}

pub const END: [u8; 9] = [0, 4, 0, 0, 0, 0x0D, 0x0A, 0x0D, 0x0A];

pub fn cipher_id(c: Cipher) -> [u8; 16] {
    match c {
        Cipher::Aes256Cbc => AES256_ID,
        Cipher::Twofish256Cbc => TWOFISH_ID,
        Cipher::ChaCha20 => CHACHA20_ID,
    }
}

/// An AES-KDF map in the reference writer's layout (FMT-03 M2).
pub fn aes_kdf_map(rounds: u64, seed: &[u8]) -> Vec<u8> {
    let mut m = vec![0x00, 0x01];
    m.extend(entry(0x42, b"$UUID", &kdf::AES_KDF_ID));
    m.extend(entry(0x05, b"R", &rounds.to_le_bytes()));
    m.extend(entry(0x42, b"S", seed));
    m.push(0);
    m
}

/// An Argon2 map in the reference writer's layout (FMT-03 M1).
pub fn argon2_map(id: [u8; 16], i: u64, m_bytes: u64, p: u32, salt: &[u8], v: u32) -> Vec<u8> {
    let mut m = vec![0x00, 0x01];
    m.extend(entry(0x42, b"$UUID", &id));
    m.extend(entry(0x05, b"I", &i.to_le_bytes()));
    m.extend(entry(0x05, b"M", &m_bytes.to_le_bytes()));
    m.extend(entry(0x04, b"P", &p.to_le_bytes()));
    m.extend(entry(0x42, b"S", salt));
    m.extend(entry(0x04, b"V", &v.to_le_bytes()));
    m.push(0);
    m
}

pub fn entry(kind: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = vec![kind];
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(&(value.len() as u32).to_le_bytes());
    v.extend_from_slice(value);
    v
}

/// The stream key S4 = 00 01 .. 3F of the FMT-09 vectors.
pub fn s4() -> Vec<u8> {
    (0u8..64).collect()
}

/// An inner header in Larsal's write order (FMT-09.4): field 1, field 2, the
/// pool items (flags, content), field 0.
pub fn inner_header(stream_id: u32, key: &[u8], pool: &[(u8, &[u8])]) -> Vec<u8> {
    let mut v = field(1, &stream_id.to_le_bytes());
    v.extend(field(2, key));
    for (flags, data) in pool {
        let mut item = vec![*flags];
        item.extend_from_slice(data);
        v.extend(field(3, &item));
    }
    v.extend([0, 0, 0, 0, 0]);
    v
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub const DEMO_XML: &[u8] =
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Demo>payload test</Demo>\n";

/// A version 4 demo vault, built by our own test code from public
/// standards (FMT-01.26 plan (d)). Every part can be changed before
/// building, and every stage can be replaced.
#[derive(Clone)]
pub struct Demo {
    /// `None`: no password part.
    pub password: Option<String>,
    /// The key file part `F`, when the vault needs one.
    pub key_file: Option<Vec<u8>>,
    /// A variable-mode HMAC-SHA1 secret, when the vault needs a hardware key.
    pub hardware: Option<Vec<u8>>,
    pub minor: u16,
    pub cipher: Cipher,
    pub gzip: bool,
    pub seed: [u8; 32],
    pub iv: Vec<u8>,
    pub kdf_map: Vec<u8>,
    /// Header fields written between field 11 and the end field.
    pub extra: Vec<Vec<u8>>,
    pub inner: Vec<u8>,
    pub xml: Vec<u8>,
    pub block: usize,
}

impl Demo {
    /// AES-256, gzip, AES-KDF with 1,000 rounds, ChaCha20 field stream with
    /// key S4, no pool items, password `demo-pass`.
    pub fn new() -> Self {
        Self {
            password: Some("demo-pass".into()),
            key_file: None,
            hardware: None,
            minor: 1,
            cipher: Cipher::Aes256Cbc,
            gzip: true,
            seed: [0x11; 32],
            iv: vec![0x22; 16],
            kdf_map: aes_kdf_map(1_000, &[0x4B; 32]),
            extra: Vec::new(),
            inner: inner_header(3, &s4(), &[]),
            xml: DEMO_XML.to_vec(),
            block: 1 << 20,
        }
    }

    pub fn with_cipher(mut self, c: Cipher) -> Self {
        self.cipher = c;
        self.iv = vec![0x22; c.iv_len()];
        self
    }

    pub fn header(&self) -> Vec<u8> {
        let mut h = preamble(self.minor);
        h.extend(field(2, &cipher_id(self.cipher)));
        h.extend(field(3, &u32::from(self.gzip).to_le_bytes()));
        h.extend(field(4, &self.seed));
        h.extend(field(7, &self.iv));
        h.extend(field(11, &self.kdf_map));
        for f in &self.extra {
            h.extend_from_slice(f);
        }
        h.extend(END);
        h
    }

    pub fn transformed(&self) -> SecretBytes {
        let p = self.password.as_deref().map(|s| password_part(&pw(s)));
        let f = self.key_file.clone().map(SecretBytes::new);
        // R = SHA256(HMAC-SHA1(secret, KDF seed)), from the card formula
        // (FMT-04.6, variable mode), not from the code under test.
        let r = self.hardware.as_ref().map(|secret| {
            let params = parse_kdf(&self.kdf_map).unwrap();
            let seed = match &params {
                kdf::KdfParams::AesKdf { seed, .. } => seed.clone(),
                kdf::KdfParams::Argon2 { salt, .. } => salt.clone(),
            };
            assert_ne!(seed.last(), Some(&(64 - seed.len() as u8)));
            let response = larsal_crypto::mac::hmac_sha1(secret, &[&seed]).unwrap();
            larsal_crypto::hash::sha256(&[response.expose()])
        });
        transformed_parts(&self.kdf_map, p.as_ref(), f.as_ref(), r.as_ref())
    }

    pub fn keys(&self) -> FinalKeys {
        final_keys(&self.seed, &self.transformed())
    }

    pub fn plaintext(&self) -> Vec<u8> {
        let u = [self.inner.as_slice(), self.xml.as_slice()].concat();
        if self.gzip { gzip(&u) } else { u }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        cipher::encrypt(self.cipher, &self.keys().cipher_key, &self.iv, plaintext).unwrap()
    }

    pub fn build(&self) -> Vec<u8> {
        self.build_with_plaintext(&self.plaintext())
    }

    pub fn build_with_plaintext(&self, plaintext: &[u8]) -> Vec<u8> {
        self.build_with_ciphertext(&self.encrypt(plaintext))
    }

    pub fn build_with_ciphertext(&self, ciphertext: &[u8]) -> Vec<u8> {
        let keys = self.keys();
        let blocks = write_blocks(ciphertext, &keys.hmac_key, self.block).unwrap();
        seal(&self.header(), &keys, &blocks)
    }
}

/// `T` for a KDF map and a password part.
pub fn transformed(kdf_map: &[u8], password: &SecretBytes) -> SecretBytes {
    transformed_parts(kdf_map, Some(password), None, None)
}

/// `T` for a KDF map and the composite of the given parts.
pub fn transformed_parts(
    kdf_map: &[u8],
    p: Option<&SecretBytes>,
    f: Option<&SecretBytes>,
    r: Option<&SecretBytes>,
) -> SecretBytes {
    let params = parse_kdf(kdf_map).unwrap();
    let composite = composite_key(p, f, r);
    let mut h = host();
    // The builder approves settings in the ask band (CRY-02.14) at once.
    let report = match kdf::assess(&params, &mut h, &Limits::DEFAULT.kdf, None).unwrap() {
        Verdict::Run(c) => return kdf::derive(&composite, &c).unwrap(),
        Verdict::Ask(report) => report,
    };
    let Verdict::Run(c) =
        kdf::assess(&params, &mut h, &Limits::DEFAULT.kdf, Some(&report)).unwrap()
    else {
        panic!("an approved report must clear its own settings")
    };
    kdf::derive(&composite, &c).unwrap()
}

/// Header bytes, their SHA-256, their HMAC, then the block stream.
pub fn seal(header: &[u8], keys: &FinalKeys, blocks: &[u8]) -> Vec<u8> {
    let mut f = header.to_vec();
    f.extend_from_slice(larsal_crypto::hash::sha256(&[header]).expose());
    f.extend_from_slice(header_hmac(&keys.hmac_key, header).expose());
    f.extend_from_slice(blocks);
    f
}

/// Replaces the header of `file` (whose header is `old_len` bytes) with
/// `header` and recomputes its SHA-256 and HMAC with `hmac_key`, keeping the
/// block stream: the re-seal of FMT-01.26 plan (d). Valid only while the
/// master seed and KDF settings, which `hmac_key` depends on, are unchanged.
pub fn reseal(file: &[u8], old_len: usize, header: &[u8], hmac_key: &SecretBytes) -> Vec<u8> {
    let mut f = header.to_vec();
    f.extend_from_slice(larsal_crypto::hash::sha256(&[header]).expose());
    f.extend_from_slice(header_hmac(hmac_key, header).expose());
    f.extend_from_slice(&file[old_len + 64..]);
    f
}

/// rich-v4.larsalvault opened once per test binary with `demo-pass-5`: its
/// file, header length, HMAC key, XML and pool (4.8 s in a debug build).
pub struct Rich {
    pub file: Vec<u8>,
    pub header_len: usize,
    pub hmac_key: larsal_format::keys::LockedKey,
    pub xml: Vec<u8>,
    pub pool: Vec<(u8, Vec<u8>)>,
    pub stream_key: Vec<u8>,
}

pub fn rich() -> &'static Rich {
    static RICH: OnceLock<Rich> = OnceLock::new();
    RICH.get_or_init(|| {
        let file = testdata("rich-v4.larsalvault");
        let p = opened(open(&file, "demo-pass-5"));
        let kdf_map = match &p.header.kdf {
            kdf::KdfParams::AesKdf { rounds, seed } => aes_kdf_map(*rounds, seed),
            other => panic!("rich-v4 uses AES-KDF, got {other:?}"),
        };
        let t = transformed(&kdf_map, &password_part(&pw("demo-pass-5")));
        Rich {
            header_len: p.header.len,
            hmac_key: final_keys(&p.header.master_seed, &t).hmac_key,
            xml: p.xml.bytes().to_vec(),
            pool: p
                .inner
                .pool
                .iter()
                .map(|i| (u8::from(i.protected), p.xml.pool_item(i).to_vec()))
                .collect(),
            stream_key: p.inner.stream_key.expose().to_vec(),
            file,
        }
    })
}

impl Demo {
    /// rich-v4's own content (its inner header and XML) under a cheap KDF:
    /// a realistic payload for sweeps that open hundreds of times.
    pub fn rich_content() -> Self {
        let r = rich();
        let pool: Vec<(u8, &[u8])> = r.pool.iter().map(|(f, d)| (*f, d.as_slice())).collect();
        Self {
            inner: inner_header(3, &r.stream_key, &pool),
            xml: r.xml.clone(),
            ..Self::new()
        }
    }
}

/// A key file component `F` from 32 raw bytes (the Raw 32 kind, FMT-18.3).
pub fn raw_key_file(f: &[u8; 32]) -> KeyFileKey {
    read_key_file(std::io::Cursor::new(f.to_vec()), &Limits::DEFAULT).unwrap()
}

/// A software hardware key in variable mode with `secret`.
pub fn soft_key(secret: &[u8]) -> SoftwareKey {
    SoftwareKey {
        secret: SecretBytes::new(secret.to_vec()),
        mode: SlotMode::Variable,
    }
}

pub fn open_creds(file: &[u8], creds: &Credentials<'_>) -> Result<Open, Error> {
    open_payload(file, creds, &mut host(), &Limits::DEFAULT, None)
}

/// Vector L4 of FMT-01 (271 bytes: header, hash, HMAC).
pub fn vector_l4() -> Vec<u8> {
    let v = hex(concat!(
        "03 D9 A2 9A 67 FB 4B B5 00 00 04 00 02 10 00 00",
        "00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A",
        "FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 A7",
        "16 30 9A 25 DE 3F 8A FE C0 28 99 E2 14 0E BC B2",
        "CD E9 F1 61 AA 40 DA BA D6 B1 F7 65 F6 9C 3C 07",
        "10 00 00 00 F5 07 28 E5 6B A1 CF 03 F0 58 E7 15",
        "43 E0 58 84 0B 5D 00 00 00 00 01 42 05 00 00 00",
        "24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44",
        "60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08",
        "00 00 00 40 42 0F 00 00 00 00 00 42 01 00 00 00",
        "53 20 00 00 00 F5 B2 EE EA 62 90 79 96 95 CE C4",
        "8F 7D 69 E7 32 9E 55 86 18 A7 2A 80 15 35 E0 CF",
        "41 89 A4 7B 20 00 00 04 00 00 00 0D 0A 0D 0A 16",
        "F1 F6 20 4B AE F1 AC 71 14 3B F9 4F 3C 71 9E BE",
        "C9 B5 EC FD 52 4D F0 84 EC 35 5A 40 3B 6E 64 D5",
        "F2 80 EF 3A C3 9C CE 7A 91 5E A7 70 2B 6E C7 11",
        "7C 96 EF 1B 60 04 55 B5 E7 DD ED 1F 50 22 5A"
    ));
    assert_eq!(v.len(), 271);
    v
}

// ---------------------------------------------------------------------------
// The test-only version 3 builder (LD-35, FMT-01.26 plan (e)): test code
// built from FMT-17, FMT-07.7, FMT-05.10 and FMT-05.12; never shipped.

pub fn field3(id: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![id];
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// A hashed block stream (FMT-07.7) with data blocks of `block` bytes.
pub fn hashed_blocks(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut index = 0u32;
    for chunk in data.chunks(block) {
        out.extend(index.to_le_bytes());
        out.extend_from_slice(larsal_crypto::hash::sha256(&[chunk]).expose());
        out.extend((chunk.len() as u32).to_le_bytes());
        out.extend_from_slice(chunk);
        index += 1;
    }
    out.extend(index.to_le_bytes());
    out.extend([0; 36]);
    out
}

#[derive(Clone)]
pub struct DemoV3 {
    pub password: Option<String>,
    pub key_file: Option<Vec<u8>>,
    /// Variable-mode HMAC-SHA1 secret; the challenge is the master seed.
    pub hardware: Option<Vec<u8>>,
    pub major: u16,
    pub minor: u16,
    pub cipher: Cipher,
    pub gzip: bool,
    pub seed: [u8; 32],
    pub transform_seed: [u8; 32],
    pub rounds: u64,
    pub iv: Vec<u8>,
    pub stream_key: Vec<u8>,
    pub start_bytes: [u8; 32],
    pub xml: Vec<u8>,
    pub block: usize,
}

impl DemoV3 {
    pub fn new() -> Self {
        Self {
            password: Some("demo-pass".into()),
            key_file: None,
            hardware: None,
            major: 3,
            minor: 1,
            cipher: Cipher::Aes256Cbc,
            gzip: true,
            seed: [0x31; 32],
            transform_seed: [0x35; 32],
            rounds: 1_000,
            iv: vec![0x37; 16],
            stream_key: vec![0x38; 32],
            start_bytes: [0x39; 32],
            xml: DEMO_XML.to_vec(),
            block: 1 << 20,
        }
    }

    pub fn with_cipher(mut self, c: Cipher) -> Self {
        self.cipher = c;
        self.iv = vec![0x37; c.iv_len()];
        self
    }

    /// Header fields in the reference writer's order 2 to 10, then 0 (FMT-17.25).
    pub fn header(&self) -> Vec<u8> {
        let mut h = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
        h.extend(self.minor.to_le_bytes());
        h.extend(self.major.to_le_bytes());
        h.extend(field3(2, &cipher_id(self.cipher)));
        h.extend(field3(3, &u32::from(self.gzip).to_le_bytes()));
        h.extend(field3(4, &self.seed));
        h.extend(field3(5, &self.transform_seed));
        h.extend(field3(6, &self.rounds.to_le_bytes()));
        h.extend(field3(7, &self.iv));
        h.extend(field3(8, &self.stream_key));
        h.extend(field3(9, &self.start_bytes));
        h.extend(field3(10, &2u32.to_le_bytes()));
        h.extend(field3(0, &[0x0D, 0x0A, 0x0D, 0x0A]));
        h
    }

    /// `K_enc = SHA256(S || [SHA256(response)] || T)`, with `T` from
    /// `C3 = SHA256([P] || [F])`: built straight from the card formula
    /// (FMT-17.9, FMT-17.10), never with the function under test (R2-B3).
    /// The variable-mode response to the padded master seed is
    /// HMAC-SHA1(secret, seed) for a seed that does not end in `20` bytes.
    pub fn key(&self) -> SecretBytes {
        let p = self.password.as_deref().map(|s| password_part(&pw(s)));
        let f = self.key_file.clone().map(SecretBytes::new);
        let map = aes_kdf_map(self.rounds, &self.transform_seed);
        let t = transformed_parts(&map, p.as_ref(), f.as_ref(), None);
        assert_ne!(
            self.seed.last(),
            Some(&0x20),
            "keep the variable-mode rule simple"
        );
        match &self.hardware {
            None => larsal_crypto::hash::sha256(&[&self.seed, t.expose()]),
            Some(secret) => {
                let response = larsal_crypto::mac::hmac_sha1(secret, &[&self.seed]).unwrap();
                let r3 = larsal_crypto::hash::sha256(&[response.expose()]);
                larsal_crypto::hash::sha256(&[&self.seed, r3.expose(), t.expose()])
            }
        }
    }

    /// The start bytes, then the hashed blocks of the (gzipped) document.
    pub fn plaintext(&self) -> Vec<u8> {
        let doc = if self.gzip {
            gzip(&self.xml)
        } else {
            self.xml.clone()
        };
        [self.start_bytes.to_vec(), hashed_blocks(&doc, self.block)].concat()
    }

    pub fn build(&self) -> Vec<u8> {
        self.build_with_plaintext(&self.plaintext())
    }

    /// Encrypts with PKCS#7 padding (CBC), as the reference writer does.
    pub fn build_with_plaintext(&self, plaintext: &[u8]) -> Vec<u8> {
        let c = cipher::encrypt(self.cipher, &self.key(), &self.iv, plaintext).unwrap();
        [self.header(), c].concat()
    }

    pub fn build_with_ciphertext(&self, ciphertext: &[u8]) -> Vec<u8> {
        [self.header(), ciphertext.to_vec()].concat()
    }
}
