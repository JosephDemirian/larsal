//! The crate's own tests, with their row names. Everything here is demo data:
//! the demo keys are the ones `testdata/make_derived.py` prints.

mod flow;
mod format;
mod limits;
mod scratch;
mod tamper;
mod vectors;
mod wipe_encrypt;

use crate::Phase;
use crate::decrypt::{
    HEADER_LABEL, PAYLOAD_LABEL, Snapshot, Unlock, Validated, Validation, X25519_LABEL,
    derive_wrap_key,
};
use crate::encrypt::{Lock, encrypt_stream_with, seal_file_key};
use crate::error::{Error, Failure};
use crate::fsio::watch::{self, Event};
use crate::keys::{Identities, Recipient};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::Secret;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{aead, mac, random, wrap};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const ID_A: &str =
    "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
pub(super) const ID_B: &str =
    "AGE-SECRET-KEY-1YY3ZXFP9YCNJS2F29VKZ6T30XQCNYVE5X5MRWWPE8GANC0F78AQQ2X9KSF";
pub(super) const REC_A: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";
/// A work factor that keeps the tests quick. Reads take it as a weak file.
pub(super) const LOW: u8 = 4;
pub(super) const PASS: &str = "demo passphrase";
pub(super) const PLAIN: &[u8] = b"demo plaintext for the file tests\n";

pub(super) fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

pub(super) fn ids(text: &str) -> Identities {
    Identities::single(&secret(text)).unwrap()
}

pub(super) fn rec(identity: &str) -> Recipient {
    Recipient(ids(identity).keys[0].public)
}

/// Bytes that do not repeat within a chunk, so a swap or a cut always shows.
pub(super) fn demo_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i ^ (i >> 8) ^ (i >> 16)).to_le_bytes()[0])
        .collect()
}

pub(super) fn keep(_: Phase, _: u64) -> bool {
    true
}

pub(super) fn seal_cost(plain: &[u8], pass: &str, log_n: u8) -> Vec<u8> {
    let phrase = secret(pass);
    let mut out = Vec::new();
    encrypt_stream_with(
        &mut random::bytes,
        log_n,
        &mut &*plain,
        &mut out,
        &Lock::Passphrase(&phrase),
        &mut keep,
    )
    .unwrap();
    out
}

pub(super) fn seal_pass(plain: &[u8], pass: &str) -> Vec<u8> {
    seal_cost(plain, pass, LOW)
}

pub(super) fn seal_to(plain: &[u8], recipients: &[Recipient]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream_with(
        &mut random::bytes,
        LOW,
        &mut &*plain,
        &mut out,
        &Lock::Recipients(recipients),
        &mut keep,
    )
    .unwrap();
    out
}

pub(super) fn snapshot(data: &[u8]) -> Snapshot<Cursor<&[u8]>> {
    Snapshot {
        src: Cursor::new(data),
    }
}

/// The checked file, with any low work factor agreed to.
pub(super) fn checked<'a>(
    data: &'a [u8],
    unlock: &Unlock<'_>,
) -> Result<Validated<Cursor<&'a [u8]>>, Failure> {
    let unwrapped = snapshot(data).unlock_inner(unlock)?;
    match unwrapped.validate_inner(&mut |_| Ok(()), &mut keep)? {
        Validation::Ready(v) => Ok(v),
        Validation::Weak(w) => Ok(w.accept()),
    }
}

/// The whole flow, with the cause kept.
pub(super) fn open(data: &[u8], unlock: &Unlock<'_>) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    checked(data, unlock)?
        .write_to(&mut out, &mut keep)
        .map_err(Failure::Other)?;
    Ok(out)
}

pub(super) fn no_output(events: &[Event]) -> bool {
    !events
        .iter()
        .any(|e| matches!(e, Event::OutputCreate | Event::OutputWrite(_)))
}

/// One refusal: the file's fault, the one public error, and not one byte out.
pub(super) fn refused(data: &[u8], unlock: &Unlock<'_>) -> Failure {
    watch::take();
    let mut out = Vec::new();
    let result =
        checked(data, unlock).and_then(|v| v.write_to(&mut out, &mut keep).map_err(Failure::Other));
    let failure = result.expect_err("this file must be refused");
    assert_eq!(Error::from(failure), Error::Decrypt);
    assert!(out.is_empty(), "plaintext came out of a refused file");
    assert!(no_output(&watch::take()));
    failure
}

// Files built without the crate's writers, to reach what those never write.

pub(super) fn demo_file_key() -> SecretBytes {
    SecretBytes::new(vec![0x5A; 16])
}

pub(super) fn b64(bytes: &[u8]) -> String {
    base64::encode(Form::Unpadded, bytes)
}

/// A stanza with any arguments and body, wrapped as the format says.
pub(super) fn raw_stanza(args: &str, body: &[u8]) -> Vec<u8> {
    let text = b64(body);
    let mut out = format!("-> {args}\n").into_bytes();
    for line in text.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    if text.len().is_multiple_of(64) {
        out.push(b'\n');
    }
    out
}

pub(super) fn x_stanza(file_key: &SecretBytes, to: &Recipient, seed: u8) -> Vec<u8> {
    let ephemeral = Secret::from_bytes(SecretBytes::new(vec![seed; 32])).unwrap();
    let share = ephemeral.public();
    let shared = ephemeral.agree(&to.0).unwrap();
    let mut salt = share.to_vec();
    salt.extend_from_slice(&to.0);
    let key = wrap::hkdf_sha256(&salt, &shared, X25519_LABEL).unwrap();
    let body = seal_file_key(&key, file_key).unwrap();
    raw_stanza(&format!("X25519 {}", b64(&share)), &body)
}

pub(super) fn s_stanza(file_key: &SecretBytes, pass: &str, log_n: u8, salt: &[u8; 16]) -> Vec<u8> {
    let key = derive_wrap_key(&secret(pass), salt, log_n).unwrap();
    let body = seal_file_key(&key, file_key).unwrap();
    raw_stanza(&format!("scrypt {} {log_n}", b64(salt)), &body)
}

pub(super) fn sealed_header(file_key: &SecretBytes, stanzas: &[u8]) -> Vec<u8> {
    let mut out = b"age-encryption.org/v1\n".to_vec();
    out.extend_from_slice(stanzas);
    out.extend_from_slice(b"---");
    let key = wrap::hkdf_sha256(&[], file_key, HEADER_LABEL).unwrap();
    let tag = mac::hmac_sha256(key.expose(), &[&out]).unwrap();
    out.push(b' ');
    out.extend_from_slice(b64(tag.expose()).as_bytes());
    out.push(b'\n');
    out
}

pub(super) fn payload_key(file_key: &SecretBytes, nonce: &[u8]) -> SecretBytes {
    wrap::hkdf_sha256(nonce, file_key, PAYLOAD_LABEL).unwrap()
}

/// One sealed chunk at any counter and flag.
pub(super) fn chunk(key: &SecretBytes, counter: u64, last: bool, plain: &[u8]) -> Vec<u8> {
    let mut out = plain.to_vec();
    let nonce = crate::payload::Counter(counter).nonce(last);
    let tag = aead::seal_in_place(key, &nonce, b"", &mut out).unwrap();
    out.extend_from_slice(&tag);
    out
}

/// The nonce and the correct chunks of `plain`.
pub(super) fn payload_of(key: &SecretBytes, nonce: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = nonce.to_vec();
    let parts: Vec<&[u8]> = if plain.is_empty() {
        vec![plain]
    } else {
        plain.chunks(crate::limits::CHUNK).collect()
    };
    for (i, part) in parts.iter().enumerate() {
        out.extend(chunk(key, i as u64, i + 1 == parts.len(), part));
    }
    out
}

pub(super) const NONCE: [u8; 16] = [0x33; 16];

/// A whole file to `ID_A`, with any stanzas after its X25519 one.
pub(super) fn craft(extra: &[u8], plain: &[u8]) -> Vec<u8> {
    let file_key = demo_file_key();
    let mut stanzas = x_stanza(&file_key, &rec(ID_A), 7);
    stanzas.extend_from_slice(extra);
    let mut out = sealed_header(&file_key, &stanzas);
    out.extend(payload_of(&payload_key(&file_key, &NONCE), &NONCE, plain));
    out
}

/// Strict armor around `data`, with the chosen line ending.
pub(super) fn armor(data: &[u8], eol: &str) -> Vec<u8> {
    let text = base64::encode(Form::Padded, data);
    let mut out = format!("-----BEGIN AGE ENCRYPTED FILE-----{eol}").into_bytes();
    for line in text.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.extend_from_slice(eol.as_bytes());
    }
    out.extend_from_slice(format!("-----END AGE ENCRYPTED FILE-----{eol}").as_bytes());
    out
}

/// The index just past a header's footer line.
pub(super) fn header_end(data: &[u8]) -> usize {
    let at = data.windows(4).position(|w| w == b"--- ").unwrap();
    at + data[at..].iter().position(|b| *b == b'\n').unwrap() + 1
}

/// A private folder under the test's temporary folder, gone after the test.
pub(super) struct Temp(pub(super) PathBuf);

impl Temp {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("larsal-files-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    pub(super) fn sub(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    pub(super) fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The crate's production source, by its path under `src/`: every file of every
/// subfolder, less the tests themselves.
pub(super) fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = format!("{prefix}{}", path.file_name().unwrap().to_string_lossy());
            if path.is_dir() {
                if name != "tests" {
                    walk(&path, &format!("{name}/"), out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((name, fs::read_to_string(path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        "",
        &mut out,
    );
    assert!(out.len() >= 11, "the source scan found too few files");
    out
}
