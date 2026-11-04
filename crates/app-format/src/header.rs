//! The outer header (FMT-02, FMT-17.2 to FMT-17.8): detection, then the
//! fields of the version 4 or version 3 layout, read before any key is known.
//!
//! Guarantees: every check runs on untrusted bytes in the order of FMT-02.30
//! and stops at the first fault; every field's end is checked against the
//! 1 MiB header limit before its data is read, and against the input before
//! anything is copied (FMT-02.24, FMT-02.25); no default is ever filled in
//! (FMT-02.23); a version 3 rounds value is never cut (FMT-17.26).

use crate::detect;
use crate::error::Error;
use crate::kdf_params::{self, MapEntry};
use crate::limits::{Limit, Limits};
use app_crypto::cipher::Cipher;
use app_crypto::kdf::{Argon2Type, KdfParams};
use app_model::settings as model;
use app_model::{Argon2Kind, Encryption, Kdf, PublicItem};

/// Field 2 value for AES-256-CBC, in RFC 4122 byte order (FMT-02).
pub const AES256_ID: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
/// Field 2 value for Twofish-CBC with a 256-bit key.
pub const TWOFISH_ID: [u8; 16] = [
    0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C,
];
/// Field 2 value for ChaCha20 with a 256-bit key.
pub const CHACHA20_ID: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];

/// Header field ids (FMT-02 field table).
mod id {
    pub const END: u8 = 0;
    pub const CIPHER: u8 = 2;
    pub const COMPRESSION: u8 = 3;
    pub const MASTER_SEED: u8 = 4;
    pub const TRANSFORM_SEED: u8 = 5;
    pub const TRANSFORM_ROUNDS: u8 = 6;
    pub const IV: u8 = 7;
    pub const STREAM_KEY: u8 = 8;
    pub const START_BYTES: u8 = 9;
    pub const STREAM_ID: u8 = 10;
    pub const KDF: u8 = 11;
    pub const PUBLIC_CUSTOM_DATA: u8 = 12;
}

/// The payload compression of field 3 (FMT-02.9, FMT-08.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Value 0: the plaintext is used as it is.
    None,
    /// Value 1: the plaintext is one gzip member.
    Gzip,
}

/// The fields only the version 3 layout has (FMT-17.3). The field stream is
/// always Salsa20 there: field 10 absent or 2 (FMT-17.8, LD-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Fields {
    /// Field 8, the protected-field stream key: at least 1 byte (LD-23).
    /// In the clear by design of that old layout (SF-12).
    pub stream_key: Vec<u8>,
    /// Field 9, the 32 stream start bytes: the wrong-key check (FMT-17.13).
    pub start_bytes: [u8; 32],
}

/// A parsed outer header. Every value is public by design (SF-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Major version: 4, or 2 or 3 for the version 3 layout.
    pub major: u16,
    /// Minor version, any value (LD-05).
    pub minor: u16,
    /// The payload cipher (field 2).
    pub cipher: Cipher,
    /// The payload compression (field 3).
    pub compression: Compression,
    /// The 32-byte master seed `S` (field 4).
    pub master_seed: [u8; 32],
    /// The IV or nonce, of the cipher's length (field 7).
    pub iv: Vec<u8>,
    /// The KDF settings: field 11 in version 4; in version 3 always AES-KDF
    /// with the seed of field 5 and the rounds of field 6 (FMT-03.24).
    pub kdf: KdfParams,
    /// Public custom data entries as stored (field 12, version 4 only);
    /// empty when absent. Unauthenticated until the header HMAC passes
    /// (FMT-03.23).
    pub public_custom_data: Vec<MapEntry>,
    /// The version 3 fields; `None` for version 4.
    pub v3: Option<V3Fields>,
    /// `H`: the length of the raw header bytes, preamble and end field
    /// included (FMT-02.4). The header checks cover `file[..len]`.
    pub len: usize,
}

/// Highest version 3 rounds value (FMT-02.17).
const MAX_ROUNDS: u64 = 2_147_483_646;

/// Reads the outer header of `file` without any key (FMT-02.27): detection
/// and version (FMT-01.2 to FMT-01.7), then the fields of the layout the
/// major version picks (FMT-02.30 steps 1 to 4, FMT-17.2 to FMT-17.8).
/// Bytes after the end field are not read.
///
/// # Errors
/// `NotAVault`, `OldFormat`, `Unsupported`, `Corrupt` or `TooLarge`, from
/// the first fault in the order of FMT-02.30. Never `WrongKey`.
pub fn read_header(file: &[u8], limits: &Limits) -> Result<Header, Error> {
    let (major, minor) = detect::check(file)?;
    let v4 = major == 4;
    let mut pos: usize = 12;
    let mut seen: Vec<u8> = Vec::new();
    let (mut cipher, mut compression, mut seed, mut iv, mut kdf) = (None, None, None, None, None);
    let (mut transform_seed, mut rounds, mut stream_key, mut start) = (None, None, None, None);
    let mut public_custom_data = Vec::new();
    loop {
        let rest = file.get(pos..).ok_or(Error::Corrupt)?;
        let (&field, rest) = rest.split_first().ok_or(Error::Corrupt)?;
        // head: id byte plus the length field (4 bytes in version 4, 2 in 3).
        let (len, rest, head) = if v4 {
            let (len, rest) = rest.split_first_chunk::<4>().ok_or(Error::Corrupt)?;
            (u32::from_le_bytes(*len), rest, 5)
        } else {
            let (len, rest) = rest.split_first_chunk::<2>().ok_or(Error::Corrupt)?;
            (u32::from(u16::from_le_bytes(*len)), rest, 3)
        };
        let len = usize::try_from(len).map_err(|_| Error::TooLarge(Limit::Header))?;
        let end = pos
            .checked_add(head)
            .and_then(|p| p.checked_add(len))
            .ok_or(Error::TooLarge(Limit::Header))?;
        if end > limits.header {
            return Err(Error::TooLarge(Limit::Header));
        }
        let data = rest.get(..len).ok_or(Error::Corrupt)?;
        pos = end;
        if field == id::END {
            break;
        }
        if v4 && matches!(field, 5 | 6 | 8 | 9 | 10) {
            return Err(Error::Corrupt); // version 3 fields in version 4 (FMT-02.14)
        }
        let defined = if v4 {
            matches!(field, 2 | 3 | 4 | 7 | 11 | 12)
        } else {
            (2..=10).contains(&field)
        };
        if defined {
            if seen.contains(&field) {
                return Err(Error::Corrupt); // FMT-02.22, FMT-17.5
            }
            seen.push(field);
        }
        match field {
            id::CIPHER => cipher = Some(cipher_from(data)?),
            id::COMPRESSION => {
                compression = Some(match u32::from_le_bytes(fixed(data)?) {
                    0 => Compression::None,
                    1 => Compression::Gzip,
                    _ => return Err(Error::Unsupported),
                });
            }
            id::MASTER_SEED => seed = Some(fixed::<32>(data)?),
            id::IV => iv = Some(data.to_vec()),
            id::KDF if v4 => kdf = Some(kdf_params::parse_kdf(data)?),
            id::PUBLIC_CUSTOM_DATA if v4 => public_custom_data = kdf_params::parse_map(data)?,
            id::TRANSFORM_SEED => transform_seed = Some(fixed::<32>(data)?.to_vec()),
            id::TRANSFORM_ROUNDS => {
                let r = u64::from_le_bytes(fixed(data)?);
                if !(1..=MAX_ROUNDS).contains(&r) {
                    return Err(Error::Unsupported); // FMT-02.17
                }
                rounds = Some(r);
            }
            id::STREAM_KEY => stream_key = Some(data.to_vec()),
            id::START_BYTES => start = Some(fixed::<32>(data)?),
            // Only 2, Salsa20, is accepted (FMT-02.20, LD-10).
            id::STREAM_ID if u32::from_le_bytes(fixed(data)?) != 2 => {
                return Err(Error::Unsupported);
            }
            _ => {} // comment and unknown ids are skipped (FMT-02.21, FMT-17.4)
        }
    }
    // Step 3: required fields; an empty IV or stream key counts as missing
    // (FMT-02.23, FMT-17.6).
    let (Some(cipher), Some(compression), Some(master_seed), Some(iv)) =
        (cipher, compression, seed, iv.filter(|v| !v.is_empty()))
    else {
        return Err(Error::Corrupt);
    };
    let (kdf, v3) = if v4 {
        (kdf.ok_or(Error::Corrupt)?, None)
    } else {
        let (Some(seed), Some(rounds), Some(stream_key), Some(start_bytes)) = (
            transform_seed,
            rounds,
            stream_key.filter(|k| !k.is_empty()),
            start,
        ) else {
            return Err(Error::Corrupt);
        };
        (
            KdfParams::AesKdf { rounds, seed },
            Some(V3Fields {
                stream_key,
                start_bytes,
            }),
        )
    };
    // Step 4: the IV length against the cipher (FMT-02.11).
    if iv.len() != cipher.iv_len() {
        return Err(Error::Unsupported);
    }
    Ok(Header {
        major,
        minor,
        cipher,
        compression,
        master_seed,
        iv,
        kdf,
        public_custom_data,
        v3,
        len: pos,
    })
}

/// A field of exactly `N` bytes, else `Corrupt`.
fn fixed<const N: usize>(data: &[u8]) -> Result<[u8; N], Error> {
    data.try_into().map_err(|_| Error::Corrupt)
}

/// Field 2 (FMT-02.7, FMT-02.8): 16 bytes naming one of the three ciphers.
fn cipher_from(data: &[u8]) -> Result<Cipher, Error> {
    match fixed::<16>(data)? {
        AES256_ID => Ok(Cipher::Aes256Cbc),
        TWOFISH_ID => Ok(Cipher::Twofish256Cbc),
        CHACHA20_ID => Ok(Cipher::ChaCha20),
        _ => Err(Error::Unsupported),
    }
}

/// The cipher id App writes in field 2 (FMT-02.7).
#[must_use]
pub fn cipher_id(cipher: Cipher) -> [u8; 16] {
    match cipher {
        Cipher::Aes256Cbc => AES256_ID,
        Cipher::Twofish256Cbc => TWOFISH_ID,
        Cipher::ChaCha20 => CHACHA20_ID,
    }
}

/// Writes a version 4 outer header (FMT-02.6, FMT-02.29): the preamble with
/// version 4.`minor`, then fields 2, 3, 4, 7, 11, 12 (only when `public` has
/// an entry) and the end field `0D 0A 0D 0A`, all with 4-byte lengths. The
/// random values are given, so the same values give the same bytes (C09).
///
/// # Errors
/// `TooLarge(Header)` for a field over 4 GiB, which no header holds.
pub fn write_header(
    minor: u16,
    cipher: Cipher,
    compression: Compression,
    master_seed: &[u8; 32],
    iv: &[u8],
    kdf: &KdfParams,
    public: &[MapEntry],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(&detect::SIGNATURE_1);
    out.extend_from_slice(&detect::SIGNATURE_2);
    out.extend_from_slice(&minor.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    let compression = match compression {
        Compression::None => 0u32,
        Compression::Gzip => 1,
    };
    let mut fields: Vec<(u8, Vec<u8>)> = vec![
        (id::CIPHER, cipher_id(cipher).to_vec()),
        (id::COMPRESSION, compression.to_le_bytes().to_vec()),
        (id::MASTER_SEED, master_seed.to_vec()),
        (id::IV, iv.to_vec()),
        (id::KDF, kdf_params::write_kdf(kdf)?),
    ];
    if !public.is_empty() {
        fields.push((id::PUBLIC_CUSTOM_DATA, kdf_params::write_map(public)?));
    }
    fields.push((id::END, b"\r\n\r\n".to_vec()));
    for (field, data) in fields {
        let len = u32::try_from(data.len()).map_err(|_| Error::TooLarge(Limit::Header))?;
        out.push(field);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// The vault's encryption settings as the header holds them (LD-82). The
/// salt and an Argon2 version are not settings (CRY-03.3, LD-17).
#[must_use]
pub fn encryption_of(header: &Header) -> Encryption {
    let cipher = match header.cipher {
        Cipher::Aes256Cbc => model::Cipher::Aes256,
        Cipher::Twofish256Cbc => model::Cipher::Twofish256,
        Cipher::ChaCha20 => model::Cipher::ChaCha20,
    };
    let kdf = match &header.kdf {
        KdfParams::AesKdf { rounds, .. } => Kdf::AesKdf { rounds: *rounds },
        KdfParams::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
            ..
        } => Kdf::Argon2 {
            kind: match kind {
                Argon2Type::D => Argon2Kind::D,
                Argon2Type::Id => Argon2Kind::Id,
            },
            iterations: *iterations,
            memory_kib: *memory_kib,
            lanes: *lanes,
        },
    };
    let compression = match header.compression {
        Compression::None => model::Compression::None,
        Compression::Gzip => model::Compression::Gzip,
    };
    Encryption {
        cipher,
        kdf,
        compression,
    }
}

/// The header cipher, compression and KDF settings for a save of
/// `settings` with the fresh `salt` (FMT-02.29, FMT-03.21; LD-17: Argon2
/// version 0x13).
#[must_use]
pub fn header_settings(settings: &Encryption, salt: Vec<u8>) -> (Cipher, Compression, KdfParams) {
    let cipher = match settings.cipher {
        model::Cipher::Aes256 => Cipher::Aes256Cbc,
        model::Cipher::Twofish256 => Cipher::Twofish256Cbc,
        model::Cipher::ChaCha20 => Cipher::ChaCha20,
    };
    let compression = match settings.compression {
        model::Compression::None => Compression::None,
        model::Compression::Gzip => Compression::Gzip,
    };
    let kdf = match settings.kdf {
        Kdf::AesKdf { rounds } => KdfParams::AesKdf { rounds, seed: salt },
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        } => KdfParams::Argon2 {
            kind: match kind {
                Argon2Kind::D => Argon2Type::D,
                Argon2Kind::Id => Argon2Type::Id,
            },
            version: 0x13,
            iterations,
            memory_kib,
            lanes,
            salt,
        },
    };
    (cipher, compression, kdf)
}

/// Header public custom data as model items, and back (FMT-03.22).
#[must_use]
pub fn public_items(entries: &[MapEntry]) -> Vec<PublicItem> {
    entries
        .iter()
        .map(|e| PublicItem {
            kind: e.kind,
            name: e.name.clone(),
            value: e.value.clone(),
        })
        .collect()
}

/// Model public custom data as header map entries (FMT-03.22).
#[must_use]
pub fn map_entries(items: &[PublicItem]) -> Vec<MapEntry> {
    items
        .iter()
        .map(|i| MapEntry {
            kind: i.kind,
            name: i.name.clone(),
            value: i.value.clone(),
        })
        .collect()
}
