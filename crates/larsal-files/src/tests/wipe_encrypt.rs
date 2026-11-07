//! FIL-01-T18, Rust rule 3: the plaintext, file key, wrap key, ephemeral key,
//! passphrase and payload key of an encrypt never stay in a freed block. Inside the crate because
//! only here a test can choose the random draws, and so know the values to look
//! for; decrypts and outputs are looked at from outside, in `tests/wipe.rs`.
//!
//! This test binary runs under the probe allocator, so every block any test frees
//! is looked at. The needles here appear in no other test: other tests' frees
//! cannot count as hits.

use super::*;
use crate::encrypt::encrypt_file_with;
use crate::fsio::watch::Fault;
use crate::{OutputFolder, SourceFile};
use larsal_platform::memory::{Probe, Seen, set_needle};
use std::alloc::System;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const FILE_KEY: [u8; 16] = *b"E22-file-key-dem";
const EPHEMERAL: [u8; 32] = *b"E22-ephemeral-key-demo-demo-demo";
const SALT: [u8; 16] = *b"E22-demo-salt-16";
const THE_NONCE: [u8; 16] = *b"E22-demo-nonce16";
const PHRASE: &str = "E22-passphrase-only-for-this-test";
const PLAIN_MARK: [u8; 8] = *b"E22enplt";
/// More than one chunk, the mark in every chunk and in every read.
static MARKED: [u8; 200_000] = {
    let mut bytes = [0x20; 200_000];
    let mut i = 0;
    while i + 8 <= 200_000 {
        let mut j = 0;
        while j < 8 {
            bytes[i + j] = PLAIN_MARK[j];
            j += 1;
        }
        i += 4096;
    }
    bytes
};

/// The draws in the order a passphrase or X25519 encryption makes them.
fn draws(
    values: Vec<&'static [u8]>,
) -> impl FnMut(usize) -> Result<SecretBytes, larsal_crypto::Error> {
    let mut values = values.into_iter();
    move |n| {
        let value = values.next().unwrap();
        assert_eq!(value.len(), n);
        Ok(SecretBytes::new(value.to_vec()))
    }
}

fn encrypt_with_passphrase() -> Vec<u8> {
    let phrase = secret(PHRASE);
    let mut out = Vec::new();
    encrypt_stream_with(
        &mut draws(vec![&FILE_KEY[..], &SALT[..], &THE_NONCE[..]]),
        LOW,
        &mut &MARKED[..],
        &mut out,
        &Lock::Passphrase(&phrase),
        &mut keep,
    )
    .unwrap();
    out
}

fn encrypt_to_recipient() -> Vec<u8> {
    let to = [rec(ID_A)];
    let mut out = Vec::new();
    encrypt_stream_with(
        &mut draws(vec![&FILE_KEY[..], &EPHEMERAL[..], &THE_NONCE[..]]),
        LOW,
        &mut &MARKED[..],
        &mut out,
        &Lock::Recipients(&to),
        &mut keep,
    )
    .unwrap();
    out
}

/// The same, with the draw at `fail` failing.
fn draws_failing(
    values: Vec<&'static [u8]>,
    fail: usize,
) -> impl FnMut(usize) -> Result<SecretBytes, larsal_crypto::Error> {
    let mut at = 0;
    let mut rest = draws(values);
    move |n| {
        at += 1;
        if at > fail {
            return Err(larsal_crypto::Error::RandomSource);
        }
        rest(n)
    }
}

/// Takes this many bytes, then fails.
struct FailingWriter(usize);

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Gives these bytes, then fails.
struct FailingReader(&'static [u8]);

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let n = self.0.read(buf)?;
        Ok(n)
    }
}

/// Every other way an encrypt can end, on the stream road and the file road, with
/// each lock. Each ends with what the card says, or the walk stops.
fn every_other_ending(input: &Path, out: &Path) {
    let phrase = secret(PHRASE);
    let to = [rec(ID_A)];
    let locks: [(Lock<'_>, &'static [u8]); 2] = [
        (Lock::Passphrase(&phrase), &SALT),
        (Lock::Recipients(&to), &EPHEMERAL),
    ];
    let folder = OutputFolder::open(out).unwrap();
    for (lock, second) in &locks {
        let values = || vec![&FILE_KEY[..], *second, &THE_NONCE[..]];
        let stream = |draw: &mut dyn FnMut(usize) -> Result<SecretBytes, larsal_crypto::Error>,
                      input: &mut dyn Read,
                      output: &mut dyn Write,
                      control: crate::Control<'_>| {
            encrypt_stream_with(draw, LOW, input, output, lock, control)
        };
        // The writer fails at the header, then among the chunks.
        for takes in [0, 100_000] {
            let result = stream(
                &mut draws(values()),
                &mut &MARKED[..],
                &mut FailingWriter(takes),
                &mut keep,
            );
            assert_eq!(result, Err(Error::Io));
        }
        // The reader fails, among the chunks.
        let result = stream(
            &mut draws(values()),
            &mut FailingReader(&MARKED[..70_000]),
            &mut Vec::new(),
            &mut keep,
        );
        assert_eq!(result, Err(Error::Io));
        // A cancel, with a whole chunk read ahead.
        let result = stream(
            &mut draws(values()),
            &mut &MARKED[..],
            &mut Vec::new(),
            &mut |_, _| false,
        );
        assert_eq!(result, Err(Error::Cancelled));
        // Each draw fails.
        for fail in 0..3 {
            let result = stream(
                &mut draws_failing(values(), fail),
                &mut &MARKED[..],
                &mut Vec::new(),
                &mut keep,
            );
            assert_eq!(result, Err(Error::Io));
        }

        let file = |draw: &mut dyn FnMut(usize) -> Result<SecretBytes, larsal_crypto::Error>,
                    name: &str,
                    control: crate::Control<'_>| {
            let source = SourceFile::open(input).unwrap();
            encrypt_file_with(draw, LOW, source, &folder, name.as_ref(), lock, control)
        };
        // The whole road.
        let result = file(&mut draws(values()), "demo.age", &mut keep);
        assert_eq!(result, Ok(MARKED.len() as u64));
        fs::remove_file(out.join("demo.age")).unwrap();
        // A cancel.
        let result = file(&mut draws(values()), "demo.age", &mut |_, _| false);
        assert_eq!(result, Err(Error::Cancelled));
        // A taken name.
        assert_eq!(
            file(&mut draws(values()), "taken", &mut keep),
            Err(Error::Exists)
        );
        // The source changes as it is read.
        let mut once = true;
        let result = file(&mut draws(values()), "demo.age", &mut |_, _| {
            if once {
                once = false;
                let mut more = fs::OpenOptions::new().append(true).open(input).unwrap();
                more.write_all(b"x").unwrap();
            }
            true
        });
        assert_eq!(result, Err(Error::Changed));
        let back = fs::OpenOptions::new().write(true).open(input).unwrap();
        back.set_len(MARKED.len() as u64).unwrap();
        // The save cannot be confirmed.
        watch::inject(Fault::OutputSync);
        let result = file(&mut draws(values()), "demo.age", &mut keep);
        watch::clear_faults();
        assert_eq!(result, Err(Error::Uncertain));
        fs::remove_file(out.join("demo.age")).unwrap();
        // Each draw fails.
        for fail in 0..3 {
            assert_eq!(
                file(&mut draws_failing(values(), fail), "demo.age", &mut keep),
                Err(Error::Io)
            );
        }
    }
    // A low-order recipient comes first, with the file key already in hand.
    let low = [Recipient([0; 32]), rec(ID_A)];
    let result = encrypt_stream_with(
        &mut draws(vec![&FILE_KEY[..], &EPHEMERAL[..]]),
        LOW,
        &mut &MARKED[..],
        &mut Vec::new(),
        &Lock::Recipients(&low),
        &mut keep,
    );
    assert_eq!(result, Err(Error::Recipient));
}

fn first8(bytes: &[u8]) -> [u8; 8] {
    bytes[..8].try_into().unwrap()
}

/// How many freed blocks held `needle` while `work` ran.
fn hits(needle: [u8; 8], work: impl FnOnce()) -> usize {
    set_needle(needle);
    let before = SEEN.with_needle.load(Relaxed);
    work();
    let after = SEEN.with_needle.load(Relaxed);
    set_needle([0; 8]);
    after - before
}

#[test]
fn fil01_t18_encrypt_leaves_no_key_in_a_freed_block() {
    // The probe sees a block that was not wiped.
    assert!(
        hits(*b"E22needl", || drop(black_box(b"E22needle demo".to_vec()))) >= 1,
        "the probe saw nothing where a needle was"
    );

    // Learned from a first run of the same draws.
    let phrase = secret(PHRASE);
    let wrap = derive_wrap_key(&phrase, &SALT, LOW).unwrap();
    let key = SecretBytes::new(FILE_KEY.to_vec());
    let payload = payload_key(&key, &THE_NONCE);
    let header_key = wrap::hkdf_sha256(&[], &key, HEADER_LABEL).unwrap();
    let eph = Secret::from_bytes(SecretBytes::new(EPHEMERAL.to_vec())).unwrap();
    let to = rec(ID_A);
    let shared = eph.agree(&to.0).unwrap();
    let mut salt = eph.public().to_vec();
    salt.extend_from_slice(&to.0);
    let x_wrap = wrap::hkdf_sha256(&salt, &shared, X25519_LABEL).unwrap();

    let needles = [
        ("plaintext", PLAIN_MARK),
        ("file key", first8(&FILE_KEY)),
        ("passphrase", first8(PHRASE.as_bytes())),
        ("scrypt wrap key", first8(wrap.expose())),
        ("payload key", first8(payload.expose())),
        ("header key", first8(header_key.expose())),
        ("ephemeral key", first8(&EPHEMERAL)),
        ("shared secret", first8(shared.expose())),
        ("X25519 wrap key", first8(x_wrap.expose())),
    ];
    let t = Temp::new();
    let input = t.file("marked.bin", &MARKED);
    let out = t.sub("out");
    fs::write(out.join("taken"), b"demo").unwrap();
    for (name, needle) in needles {
        let found = hits(needle, || {
            drop(black_box(encrypt_with_passphrase()));
            drop(black_box(encrypt_to_recipient()));
            every_other_ending(&input, &out);
        });
        assert_eq!(found, 0, "{name} stayed in a freed block");
    }

    // The same check on the files themselves: the right keys were in use.
    let keys = ids(ID_A);
    assert_eq!(
        open(&encrypt_to_recipient(), &Unlock::Identities(&keys)).unwrap(),
        MARKED
    );
    assert_eq!(
        open(&encrypt_with_passphrase(), &Unlock::Passphrase(&phrase)).unwrap(),
        MARKED
    );
}
