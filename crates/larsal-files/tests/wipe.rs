//! FIL-01-T18, story check 5: after a decrypt ends in any way, no freed heap block
//! holds the passphrase, an identity, the file key, the payload key or the
//! plaintext. One test only: the probes count every block the process frees.
//! This is the Rust-owned half; the independent memory proof on both Mac targets
//! stays open, as the card says.

mod common;

use common::open_all;
use larsal_crypto::base64;
use larsal_crypto::bridge::Secret;
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_crypto::{aead, kdf, wrap};
use larsal_files::{
    Control, Identities, Lock, OutputFolder, Phase, Recipient, ScratchRoot, Unlock, Validation,
    encrypt_stream,
};
use larsal_platform::memory::{Probe, Seen, set_needle};
use std::alloc::System;
use std::ffi::OsStr;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const PHRASE: &str = "E22-demo-passphrase-for-wipe";
const ID_TEXT: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const ID_LIST: &str =
    "# demo\nAGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE\n";
/// The bytes `ID_TEXT` says.
const ID_BYTES: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
/// A list a dash comes first in: a plain list that is no list, and no armor.
const DASH_LIST: &str =
    "-\n# demo\nAGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE\n";
/// A private key in no format of this crate, chosen by mistake.
const OTHER_KEY: &str =
    "-----BEGIN DEMO PRIVATE KEY-----\nE22other-demo-demo\n-----END DEMO PRIVATE KEY-----\n";
const MARKER: [u8; 8] = *b"E22plain";
static PLAINTEXT: [u8; 200_000] = {
    let mut bytes = [0x20; 200_000];
    let mut i = 0;
    while i + 8 <= 200_000 {
        let mut j = 0;
        while j < 8 {
            bytes[i + j] = MARKER[j];
            j += 1;
        }
        i += 4096;
    }
    bytes
};

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("larsal-files-wipe-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn seal(lock: &Lock<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(&mut &PLAINTEXT[..], &mut out, lock, &mut |_, _| true).unwrap();
    out
}

/// The field after `word` in the first stanza line, and its body.
fn stanza(file: &[u8], word: &str) -> (String, Vec<u8>) {
    let text = String::from_utf8_lossy(&file[..file.len().min(400)]).into_owned();
    let mut lines = text.lines().skip(1);
    let line = lines.next().unwrap();
    let args: Vec<&str> = line.split(' ').collect();
    assert_eq!(args[1], word);
    let mut body = vec![0u8; 64];
    let n = base64::decode_unpadded_into(lines.next().unwrap().as_bytes(), &mut body).unwrap();
    body.truncate(n);
    (args[2].to_string(), body)
}

/// The file key and payload key of a file, learned as an attacker with the
/// credential would learn them, in wiping memory.
fn learn(file: &[u8], wrap_key: &SecretBytes, body: &[u8]) -> (SecretBytes, SecretBytes) {
    let mut file_key = SecretBytes::new(body[..16].to_vec());
    let tag: &[u8; 16] = body[16..32].try_into().unwrap();
    aead::open_in_place(wrap_key, &[0; 12], b"", file_key.expose_mut(), tag).unwrap();
    let at = file.windows(4).position(|w| w == b"--- ").unwrap();
    let end = at + file[at..].iter().position(|b| *b == b'\n').unwrap() + 1;
    let payload = wrap::hkdf_sha256(&file[end..end + 16], &file_key, b"payload").unwrap();
    (file_key, payload)
}

fn first8(bytes: &[u8]) -> [u8; 8] {
    bytes[..8].try_into().unwrap()
}

/// Every way one decrypt can end, through the public calls only.
fn every_ending(
    x_file: &[u8],
    pass_file: &[u8],
    key_file: &[u8],
    root: &ScratchRoot,
    folder: &OutputFolder,
    out_dir: &std::path::Path,
) {
    let keep: Control<'_> = &mut |_: Phase, _: u64| true;
    let phrase = SecretString::from(PHRASE);
    let keys = Identities::single(&SecretString::from(ID_TEXT)).unwrap();
    let by_key = Unlock::Identities(&keys);
    let by_phrase = Unlock::Passphrase(&phrase);
    let wrong = SecretString::from("E22-wrong-demo");
    let other = Identities::from_list(
        b"AGE-SECRET-KEY-1YY3ZXFP9YCNJS2F29VKZ6T30XQCNYVE5X5MRWWPE8GANC0F78AQQ2X9KSF\n",
    )
    .unwrap();

    // Success: into a stream, into a new file.
    for (file, unlock) in [(x_file, &by_key), (pass_file, &by_phrase)] {
        let snapshot = root.capture_stream(&mut &file[..], keep).unwrap();
        let v = match snapshot.unlock(unlock).unwrap().validate(keep).unwrap() {
            Validation::Ready(v) => v,
            Validation::Weak(w) => w.accept(),
        };
        v.write_to(&mut NowhereWrite, keep).unwrap();
    }
    let snapshot = root.capture_stream(&mut &x_file[..], keep).unwrap();
    let Validation::Ready(v) = snapshot.unlock(&by_key).unwrap().validate(keep).unwrap() else {
        panic!("X25519 files have no work factor");
    };
    let name: &OsStr = "wipe-demo.out".as_ref();
    v.save_new(folder, name, keep).unwrap();
    fs::remove_file(out_dir.join("wipe-demo.out")).unwrap();
    drop(black_box(open_all(x_file, &by_key)));

    // Wrong credential, no match.
    let _ = black_box(open_all(pass_file, &Unlock::Passphrase(&wrong)));
    let _ = black_box(open_all(x_file, &Unlock::Identities(&other)));
    // Bad MAC, at the point the file key is in hand.
    let mut bad_mac = x_file.to_vec();
    let at = x_file.windows(4).position(|w| w == b"--- ").unwrap() + 4;
    bad_mac[at] = if bad_mac[at] == b'A' { b'B' } else { b'A' };
    let _ = black_box(open_all(&bad_mac, &by_key));
    // Bad chunk, with the payload key in hand and plaintext through the buffers.
    let mut bad_chunk = x_file.to_vec();
    *bad_chunk.last_mut().unwrap() ^= 1;
    let _ = black_box(open_all(&bad_chunk, &by_key));
    // F-342 (C2R3-01): a full chunk that opens only under the other flag. The
    // discard pass decrypts it for its count and still refuses the file.
    let at = x_file.windows(4).position(|w| w == b"--- ").unwrap();
    let end = at + x_file[at..].iter().position(|b| *b == b'\n').unwrap() + 1;
    let cut = &x_file[..end + 16 + 3 * 65_552];
    let other_flag = black_box(open_all(cut, &by_key));
    assert!(matches!(other_flag, Err(larsal_files::Error::Decrypt)));
    drop(other_flag);
    // Cancel in the check and in the write.
    let snapshot = root.capture_stream(&mut &x_file[..], keep).unwrap();
    let _ = black_box(
        snapshot
            .unlock(&by_key)
            .unwrap()
            .validate(&mut |_, _| false),
    );
    let snapshot = root.capture_stream(&mut &x_file[..], keep).unwrap();
    let Validation::Ready(v) = snapshot.unlock(&by_key).unwrap().validate(keep).unwrap() else {
        panic!("X25519 files have no work factor");
    };
    assert!(v.save_new(folder, name, &mut |_, _| false).is_err());
    // Key files, each given in wiping memory as a caller holds one.
    let read = |bytes: &[u8], passphrase: Option<&SecretString>| {
        let mut input = SecretReader(SecretBytes::new(bytes.to_vec()), 0);
        drop(black_box(Identities::read_key_file(&mut input, passphrase)));
    };
    read(ID_LIST.as_bytes(), None);
    // An encrypted one, and so its decoded text.
    read(key_file, Some(&phrase));
    // One whose decoded text is past the list's bound: checked, then refused.
    read(pass_file, Some(&phrase));
    // Not ciphertext, whatever comes first, so it goes to no reader's plain buffer.
    read(DASH_LIST.as_bytes(), Some(&phrase));
    read(OTHER_KEY.as_bytes(), Some(&phrase));
}

/// A writer for the flow above, keeping nothing.
struct NowhereWrite;

impl Write for NowhereWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A reader over wiping memory.
struct SecretReader(SecretBytes, usize);

impl std::io::Read for SecretReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rest = &self.0.expose()[self.1..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.1 += n;
        Ok(n)
    }
}

#[test]
fn fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block() {
    let t = scratch();
    let (scratch_dir, out_dir) = (t.join("scratch"), t.join("out"));
    for dir in [&scratch_dir, &out_dir] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = ScratchRoot::open(&scratch_dir).unwrap();
    let folder = OutputFolder::open(&out_dir).unwrap();
    let phrase = SecretString::from(PHRASE);
    let id = Secret::from_bytes(SecretBytes::new(ID_BYTES.to_vec())).unwrap();
    let to = Recipient::parse(&larsal_crypto::bech32::encode_lower("age", &id.public()).unwrap())
        .unwrap();

    // Files to learn from. They hold ciphertext; their memory need not wipe.
    let x_file = seal(&Lock::Recipients(&[to]));
    let pass_file = seal(&Lock::Passphrase(&phrase));
    let mut key_file = Vec::new();
    encrypt_stream(
        &mut ID_LIST.as_bytes(),
        &mut key_file,
        &Lock::Passphrase(&phrase),
        &mut |_, _| true,
    )
    .unwrap();

    let (share_text, x_body) = stanza(&x_file, "X25519");
    let mut share = [0u8; 32];
    base64::decode_unpadded_into(share_text.as_bytes(), &mut share).unwrap();
    let shared = id.agree(&share).unwrap();
    let mut salt = share.to_vec();
    salt.extend_from_slice(&id.public());
    let x_wrap = wrap::hkdf_sha256(&salt, &shared, b"age-encryption.org/v1/X25519").unwrap();
    let (x_file_key, x_payload) = learn(&x_file, &x_wrap, &x_body);

    let (salt_text, p_body) = stanza(&pass_file, "scrypt");
    let mut p_salt = [0u8; 16];
    base64::decode_unpadded_into(salt_text.as_bytes(), &mut p_salt).unwrap();
    let mut full_salt = b"age-encryption.org/v1/scrypt".to_vec();
    full_salt.extend_from_slice(&p_salt);
    let p_wrap = kdf::scrypt(PHRASE.as_bytes(), &full_salt, 18, 8, 1, 32).unwrap();
    let (p_file_key, p_payload) = learn(&pass_file, &p_wrap, &p_body);

    // Control: the probe sees a block that was not wiped.
    set_needle(MARKER);
    SEEN.reset();
    drop(black_box(b"E22plain demo".to_vec()));
    assert!(SEEN.with_needle.load(Relaxed) >= 1, "the probe saw nothing");

    let id_text = first8(&ID_TEXT.as_bytes()[20..]);
    let id_text_lower = first8(&ID_TEXT.to_lowercase().as_bytes()[20..]);
    let needles = [
        ("plaintext", MARKER),
        ("passphrase", first8(PHRASE.as_bytes())),
        ("identity bytes", first8(&ID_BYTES)),
        ("identity text", id_text),
        ("identity text, lower case", id_text_lower),
        ("other key file", *b"E22other"),
        ("X25519 shared secret", first8(shared.expose())),
        ("X25519 wrap key", first8(x_wrap.expose())),
        ("X25519 file key", first8(x_file_key.expose())),
        ("X25519 payload key", first8(x_payload.expose())),
        ("scrypt wrap key", first8(p_wrap.expose())),
        ("scrypt file key", first8(p_file_key.expose())),
        ("scrypt payload key", first8(p_payload.expose())),
    ];
    for (what, needle) in needles {
        set_needle(needle);
        SEEN.reset();
        every_ending(&x_file, &pass_file, &key_file, &root, &folder, &out_dir);
        let found = SEEN.with_needle.load(Relaxed);
        let largest = SEEN.largest_with_needle.load(Relaxed);
        set_needle([0; 8]);
        assert_eq!(
            found, 0,
            "{what}: {found} freed blocks, the largest {largest} bytes"
        );
    }
    assert!(
        fs::read_dir(&scratch_dir).unwrap().next().is_none(),
        "no scratch stays"
    );
    drop(fs::remove_dir_all(&t));
}
