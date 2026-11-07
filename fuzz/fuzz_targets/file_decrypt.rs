//! Fuzz target `file_decrypt` (E22-S3; FIL-01, FIL-03): the file format's armor,
//! header and chunk readers and the validated flow over them, through the public
//! states, from `Snapshot::for_fuzzing` on, with demo credentials only. Must never panic,
//! hang or allocate from an unchecked length, and every failure is the one
//! generic error.
//!
//! Input: a mode byte (taken modulo 5), then the rest.
//! - 0: the rest is a whole file, opened with a demo identity.
//! - 1: the rest follows an armor BEGIN line, to reach the armor's line rules.
//! - 2: the rest is a list of up to 8 chunks, 2 bytes each, sealed here under a
//!   right header, so the reader gets past a right tag. Byte 1: bits 0 and 1 pick
//!   an empty, 1 byte, short or full chunk. Byte 2: bit 0 the last flag, bit 1
//!   skips a counter, bit 2 changes the tag. A right list must open to exactly
//!   its bytes; any other must fail. That checks the chunk rules themselves.
//! - 3: the rest is an identity list, and if UTF-8 a recipient text.
//! - 4: the rest is a whole file opened with a demo passphrase, skipped when it
//!   names a key derivation cost above 8, as that only spends the run's time.
#![no_main]

use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::Secret;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{aead, mac, wrap};
use larsal_files::limits::CHUNK;
use larsal_files::{Error, Identities, Phase, Recipient, Snapshot, Unlock, Validation};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const ID: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const PHRASE: &str = "demo passphrase";
const BOUND: usize = 1 << 20;
const NONCE: [u8; 16] = [0x33; 16];
const MAX_CHUNKS: usize = 8;

struct Fixed {
    identities: Identities,
    phrase: SecretString,
    /// A right header and nonce to the demo identity.
    head: Vec<u8>,
    payload_key: SecretBytes,
}

fn fixed() -> &'static Fixed {
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    FIXED.get_or_init(|| {
        let identities = Identities::single(&SecretString::from(ID)).unwrap();
        let id = Secret::from_bytes(SecretBytes::new((1..=32).collect())).unwrap();
        let ephemeral = Secret::from_bytes(SecretBytes::new(vec![7; 32])).unwrap();
        let share = ephemeral.public();
        let shared = ephemeral.agree(&id.public()).unwrap();
        let mut salt = share.to_vec();
        salt.extend_from_slice(&id.public());
        let key = wrap::hkdf_sha256(&salt, &shared, b"age-encryption.org/v1/X25519").unwrap();
        let file_key = SecretBytes::new(vec![0x5A; 16]);
        let mut sealed = file_key.expose().to_vec();
        let tag = aead::seal_in_place(&key, &[0; 12], b"", &mut sealed).unwrap();
        sealed.extend_from_slice(&tag);
        let mut head = format!(
            "age-encryption.org/v1\n-> X25519 {}\n{}\n---",
            base64::encode(Form::Unpadded, &share),
            base64::encode(Form::Unpadded, &sealed),
        )
        .into_bytes();
        let header_key = wrap::hkdf_sha256(&[], &file_key, b"header").unwrap();
        let tag = mac::hmac_sha256(header_key.expose(), &[&head]).unwrap();
        head.push(b' ');
        head.extend_from_slice(base64::encode(Form::Unpadded, tag.expose()).as_bytes());
        head.push(b'\n');
        head.extend_from_slice(&NONCE);
        let payload_key = wrap::hkdf_sha256(&NONCE, &file_key, b"payload").unwrap();
        Fixed {
            identities,
            phrase: SecretString::from(PHRASE),
            head,
            payload_key,
        }
    })
}

/// The whole flow, in memory, up to `BOUND` bytes of plaintext. A weak file is
/// said yes to, as a person would.
fn open_all(file: &[u8], unlock: &Unlock<'_>) -> Result<SecretBytes, Error> {
    let keep = &mut |_: Phase, _: u64| true;
    let checked = match Snapshot::for_fuzzing(file).unlock(unlock)?.validate(keep)? {
        Validation::Ready(v) => v,
        Validation::Weak(w) => w.accept(),
    };
    let len = usize::try_from(checked.plain_len())
        .ok()
        .filter(|n| *n <= BOUND)
        .ok_or(Error::Decrypt)?;
    let mut plain = SecretBytes::zeroed(len);
    let mut to: &mut [u8] = plain.expose_mut();
    checked.write_to(&mut to, keep)?;
    Ok(plain)
}

/// Opens with the demo identity. The reader's only error here is the generic one.
fn open_x(file: &[u8]) -> Result<SecretBytes, Error> {
    let result = open_all(file, &Unlock::Identities(&fixed().identities));
    if let Err(e) = result {
        assert_eq!(e, Error::Decrypt);
    }
    result
}

fn chunk_script(script: &[u8]) {
    let fixed = fixed();
    let mut file = fixed.head.clone();
    let mut plain = Vec::new();
    let ops: Vec<&[u8]> = script.chunks_exact(2).take(MAX_CHUNKS).collect();
    let mut counter = 0u64;
    let mut right = !ops.is_empty();
    for (i, op) in ops.iter().enumerate() {
        let (size, flags) = (op[0] & 3, op[1]);
        let len = match size {
            0 => 0,
            1 => 1,
            2 => 2 + usize::from(op[0] >> 2),
            _ => CHUNK,
        };
        let (last, skip, tamper) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
        let is_final = i + 1 == ops.len();
        if skip {
            counter += 1;
        }
        // The format: every chunk but the last is full, an empty one stands alone,
        // only the last has the flag, and the counter never skips.
        right &= !skip && !tamper && last == is_final;
        right &= if is_final {
            len > 0 || ops.len() == 1
        } else {
            len == CHUNK
        };

        let mut data = vec![u8::try_from(i).unwrap(); len];
        plain.extend_from_slice(&data);
        let mut nonce = [0u8; 12];
        nonce[3..11].copy_from_slice(&counter.to_be_bytes());
        nonce[11] = u8::from(last);
        let mut tag = aead::seal_in_place(&fixed.payload_key, &nonce, b"", &mut data).unwrap();
        if tamper {
            tag[0] ^= 1;
        }
        file.extend_from_slice(&data);
        file.extend_from_slice(&tag);
        counter += 1;
    }
    match open_x(&file) {
        Ok(opened) => {
            assert!(right, "a wrong list of chunks opened");
            assert_eq!(opened.expose(), &plain[..]);
        }
        Err(_) => assert!(!right, "a right list of chunks was refused"),
    }
}

/// The cost in a file's scrypt stanza, when it names one past what a run can spend.
fn costs_too_much(file: &[u8]) -> bool {
    file.split(|b| *b == b'\n')
        .filter(|line| line.starts_with(b"-> scrypt"))
        .any(|line| {
            let cost = line.rsplit(|b| *b == b' ').next().unwrap_or(b"");
            cost.len() > 1 || cost.first().is_some_and(|d| *d == b'9')
        })
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 5 {
        0 => drop(open_x(rest)),
        1 => {
            let mut armored = b"-----BEGIN AGE ENCRYPTED FILE-----\n".to_vec();
            armored.extend_from_slice(rest);
            drop(open_x(&armored));
        }
        2 => chunk_script(rest),
        3 => {
            let _ = Identities::from_list(rest);
            if let Ok(text) = std::str::from_utf8(rest) {
                let _ = Recipient::parse(text);
            }
        }
        _ => {
            if !costs_too_much(rest) {
                let unlock = Unlock::Passphrase(&fixed().phrase);
                if let Err(e) = open_all(rest, &unlock) {
                    assert_eq!(e, Error::Decrypt);
                }
            }
        }
    }
});
