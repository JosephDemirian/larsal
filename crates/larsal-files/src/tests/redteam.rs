//! E22-S6, the Red team run against file encryption (FIL-01, FIL-03; AT-A01,
//! AT-A02, AT-A04, AT-A09, AT-A12, AT-B07, AT-FILE-01 to 07). One test per
//! attack, named after it. Each passes while its defence holds; the
//! private-copy mutant named in its doc comment undoes that defence and turns
//! it red (rule 11: never in the shared tree). A defence that does not hold has
//! its test written to fail and ignored, with its finding. Demo data only.

use super::*;
use crate::decrypt::kdf_probe;
use crate::limits::{CHUNK, MAX_HEADER, MAX_STANZAS, SEALED_CHUNK};
use crate::{OutputFolder, ScratchRoot, SourceFile, encrypt_file};
use std::cell::Cell;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, symlink};
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

const VERSION: &[u8] = b"age-encryption.org/v1\n";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `covered` (through `---`) with its MAC under the demo file key.
fn sign(covered: &[u8]) -> Vec<u8> {
    let key = wrap::hkdf_sha256(&[], &demo_file_key(), HEADER_LABEL).unwrap();
    let tag = mac::hmac_sha256(key.expose(), &[covered]).unwrap();
    let mut out = covered.to_vec();
    out.push(b' ');
    out.extend_from_slice(b64(tag.expose()).as_bytes());
    out.push(b'\n');
    out
}

/// A whole file: `version`, `stanzas`, a correct MAC, then the demo payload.
fn signed_file(version: &[u8], stanzas: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut covered = version.to_vec();
    covered.extend_from_slice(stanzas);
    covered.extend_from_slice(b"---");
    let mut out = sign(&covered);
    let fk = demo_file_key();
    out.extend(payload_of(&payload_key(&fk, &NONCE), &NONCE, plain));
    out
}

/// The X25519 stanza that opens the demo file key for `ID_A`.
fn to_a() -> Vec<u8> {
    x_stanza(&demo_file_key(), &rec(ID_A), 7)
}

fn same_message(e: Error) -> String {
    e.to_string()
}

/// RT-01 (AT-A02, AT-FILE-01, FIL-01-T02, FIL-01-T11): every bit of every
/// header byte, in headers with every line kind: the version line, two X25519
/// stanzas (the first for another key), an unknown stanza with a body of three
/// lines, the footer and the MAC line; and a passphrase file's header. Each
/// change is the one public error with no output.
/// Mutant M01: the header MAC check taken as true (decrypt.rs, `unlock_inner`).
#[test]
fn fil_rt_header_byte_flips_are_refused() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let mut stanzas = x_stanza(&demo_file_key(), &rec(ID_B), 3);
    stanzas.extend(to_a());
    stanzas.extend(raw_stanza("demo-type arg-one arg-two", &[0x41; 100]));
    let good = signed_file(VERSION, &stanzas, PLAIN);
    assert_eq!(open(&good, &unlock).unwrap(), PLAIN, "positive control");
    for at in 0..header_end(&good) {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            refused(&bad, &unlock);
        }
    }
    let phrase = secret(PASS);
    let unlock = Unlock::Passphrase(&phrase);
    let good = seal_pass(PLAIN, PASS);
    assert_eq!(open(&good, &unlock).unwrap(), PLAIN, "positive control");
    for at in 0..header_end(&good) {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            refused(&bad, &unlock);
        }
    }
}

/// RT-02 (AT-FILE-01, FIL-01.2): one value, one spelling. The MAC line is the
/// one line the MAC cannot cover, so a decoder that let two spellings stand for
/// the same 32 bytes would let a changed header through. Every other last
/// character of the MAC, of an X25519 share, of a stanza body and of a scrypt
/// salt is refused, as are a padded MAC and a MAC with a space or CR after it.
/// Mutant M02: the MAC's two unused low bits masked before it is decoded
/// (header.rs, `read`, the footer line).
#[test]
fn fil_rt_one_spelling_per_base64_value() {
    let keys = ids(ID_A);
    let x_unlock = Unlock::Identities(&keys);
    let x_file = craft(b"", PLAIN);
    assert_eq!(open(&x_file, &x_unlock).unwrap(), PLAIN, "positive control");
    let phrase = secret(PASS);
    let p_unlock = Unlock::Passphrase(&phrase);
    let p_file = seal_pass(PLAIN, PASS);
    assert_eq!(open(&p_file, &p_unlock).unwrap(), PLAIN, "positive control");

    // The last character of: the MAC, the first stanza line's last argument
    // (the share or the work factor's salt), and the stanza body.
    let lasts = |file: &[u8]| {
        let first_nl = file.iter().position(|b| *b == b'\n').unwrap();
        let line_end = first_nl
            + 1
            + file[first_nl + 1..]
                .iter()
                .position(|b| *b == b'\n')
                .unwrap();
        let body_end = line_end
            + 1
            + file[line_end + 1..]
                .iter()
                .position(|b| *b == b'\n')
                .unwrap();
        (header_end(file) - 2, line_end - 1, body_end - 1)
    };
    let (x_mac, x_share, x_body) = lasts(&x_file);
    for at in [x_mac, x_share, x_body] {
        for c in BASE64.iter().filter(|c| **c != x_file[at]) {
            let mut bad = x_file.clone();
            bad[at] = *c;
            refused(&bad, &x_unlock);
        }
    }
    // The scrypt line ends with the work factor: its salt ends before it.
    let (p_mac, _, p_body) = lasts(&p_file);
    let first_nl = p_file.iter().position(|b| *b == b'\n').unwrap();
    let line_end = first_nl
        + 1
        + p_file[first_nl + 1..]
            .iter()
            .position(|b| *b == b'\n')
            .unwrap();
    let p_salt = p_file[..line_end].iter().rposition(|b| *b == b' ').unwrap() - 1;
    for at in [p_mac, p_salt, p_body] {
        for c in BASE64.iter().filter(|c| **c != p_file[at]) {
            let mut bad = p_file.clone();
            bad[at] = *c;
            refused(&bad, &p_unlock);
        }
    }
    let end = header_end(&x_file);
    for extra in [&b"="[..], b"==", b" ", b"\r", b"\t"] {
        let mut bad = x_file[..end - 1].to_vec();
        bad.extend_from_slice(extra);
        bad.extend_from_slice(&x_file[end - 1..]);
        refused(&bad, &x_unlock);
    }
}

/// RT-03 (AT-FILE-01, FIL-01.2, FIL-01.11, FIL-01.14): stanza lines in every
/// wrong form, each in a header whose MAC is correct, so only the parser's
/// strictness stands between the change and a decrypt: extra, missing and
/// empty arguments, spaces, tabs, CR, short, long and padded shares and
/// bodies, a body line too long or with an empty line after it, an empty type,
/// and an unknown stanza with a byte outside the visible ASCII range. The
/// same file with the well-formed stanza opens.
/// Mutant M03: the argument character check removed (header.rs, `read_stanza`,
/// `args_ok`).
#[test]
fn fil_rt_stanza_line_forms_are_refused() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let a = String::from_utf8(to_a()).unwrap();
    let (line, body) = a.split_once('\n').unwrap();
    let share = line.strip_prefix("-> X25519 ").unwrap();
    let body_text = body.trim_end_matches('\n');
    assert_eq!(
        open(&signed_file(VERSION, a.as_bytes(), PLAIN), &unlock).unwrap(),
        PLAIN,
        "positive control"
    );
    let long_share = b64(&[7u8; 33]);
    let short_body = b64(&[7u8; 31]);
    let long_body = b64(&[7u8; 33]);
    let x_forms = [
        format!("-> X25519 {share} extra\n{body}"),
        format!("-> X25519\n{body}"),
        format!("->  X25519 {share}\n{body}"),
        format!("-> X25519  {share}\n{body}"),
        format!("-> X25519 {share} \n{body}"),
        format!("->X25519 {share}\n{body}"),
        format!("-> X25519 {share}\r\n{body}"),
        format!("-> X25519\t{share}\n{body}"),
        format!("-> X25519 {}\n{body}", &share[..42]),
        format!("-> X25519 {share}=\n{body}"),
        format!("-> X25519 {long_share}\n{body}"),
        format!("-> X25519 {share}\n{short_body}\n"),
        format!("-> X25519 {share}\n{long_body}\n"),
        format!("-> X25519 {share}\n{body_text}=\n"),
        format!("-> X25519 {share}\n{body_text}\r\n"),
        format!("-> X25519 {share}\n{body}\n"),
        format!("-> X25519 {share}\n\n{body}"),
        format!("-> \n{body}{a}"),
        format!("-> X25519 {share}\n{}\n", "A".repeat(65)),
    ];
    for form in &x_forms {
        refused(&signed_file(VERSION, form.as_bytes(), PLAIN), &unlock);
    }
    // After the good stanza, so a parser that let these pass would open the file.
    let mut unknown: Vec<Vec<u8>> = vec![
        b"-> demo a\x7fb\n\n".to_vec(),
        b"-> demo a\x80b\n\n".to_vec(),
        "-> demo \u{e9}\n\n".as_bytes().to_vec(),
        b"-> demo a\x00b\n\n".to_vec(),
        b"-> demo\nAAAA=\n".to_vec(),
        format!("-> demo\n{}\n", "A".repeat(64)).into_bytes(),
        format!("-> demo\n{}\nAB\n", "A".repeat(63)).into_bytes(),
    ];
    // A body line of a canonical length whose last character carries unused bits.
    unknown.push(b"-> demo\nAB\n".to_vec());
    for form in &unknown {
        let mut stanzas = a.as_bytes().to_vec();
        stanzas.extend_from_slice(form);
        refused(&signed_file(VERSION, &stanzas, PLAIN), &unlock);
    }
}

/// RT-04 (AT-A09, FIL-01.1): the version line is exactly the one version. Each
/// variant has a correct MAC over it, so only the version check stops it.
/// Mutant M04: the version line compared as a prefix (header.rs, `read`).
#[test]
fn fil_rt_version_line_variants_are_refused() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let a = to_a();
    assert_eq!(
        open(&signed_file(VERSION, &a, PLAIN), &unlock).unwrap(),
        PLAIN
    );
    for version in [
        &b"age-encryption.org/v1 \n"[..],
        b"age-encryption.org/v1\r\n",
        b"age-encryption.org/v1/x\n",
        b"age-encryption.org/v1x\n",
        b"age-encryption.org/v2\n",
        b"age-encryption.org/v0\n",
        b"Age-encryption.org/v1\n",
        b"age-encryption.org/V1\n",
        b"age-encryption.org/v1\n\n",
        b"\nage-encryption.org/v1\n",
        b" age-encryption.org/v1\n",
        b"age-encryption.org\n",
        b"\n",
    ] {
        refused(&signed_file(version, &a, PLAIN), &unlock);
    }
}

/// The demo file's parts: header with its nonce, and its three chunks.
struct Parts {
    head: Vec<u8>,
    key: SecretBytes,
    plain: Vec<u8>,
}

impl Parts {
    fn new() -> Self {
        let mut covered = VERSION.to_vec();
        covered.extend(to_a());
        covered.extend_from_slice(b"---");
        let mut head = sign(&covered);
        head.extend_from_slice(&NONCE);
        Self {
            head,
            key: payload_key(&demo_file_key(), &NONCE),
            plain: demo_bytes(2 * CHUNK + 100),
        }
    }

    fn piece(&self, i: usize) -> &[u8] {
        let end = ((i + 1) * CHUNK).min(self.plain.len());
        &self.plain[i * CHUNK..end]
    }

    fn c(&self, counter: u64, last: bool, i: usize) -> Vec<u8> {
        chunk(&self.key, counter, last, self.piece(i))
    }

    fn file(&self, chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = self.head.clone();
        for c in chunks {
            out.extend_from_slice(c);
        }
        out
    }
}

/// RT-05 (AT-A04, AT-FILE-02, FIL-01.12, FIL-03.16, FIL-03-T04): the chunked
/// payload. Cut at every chunk edge, one and sixteen bytes on each side of it
/// and inside each chunk; chunks swapped, repeated, dropped (the last one too);
/// the last-chunk flag on a chunk that is not last, and taken off the last one;
/// a zero-length last chunk after full ones; a chunk after the last; a chunk
/// spliced from a file with another nonce; every bit of the payload nonce.
/// Mutant M05: the last-chunk flag not checked (payload.rs, `open_chunks`: a
/// chunk opens under either flag). Mutant M05b: the zero-length last chunk
/// after others allowed (payload.rs, `plain_len == 0 && counter.0 != 0`).
#[test]
fn fil_rt_chunk_cuts_swaps_repeats_and_flags_are_refused() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let p = Parts::new();
    let (c0, c1, c2) = (p.c(0, false, 0), p.c(1, false, 1), p.c(2, true, 2));
    let good = p.file(&[c0.clone(), c1.clone(), c2.clone()]);
    assert_eq!(open(&good, &unlock).unwrap(), p.plain, "positive control");

    let start = p.head.len();
    let edges = [start, start + SEALED_CHUNK, start + 2 * SEALED_CHUNK];
    let mut cuts: Vec<usize> = Vec::new();
    for e in edges {
        for d in [-17i64, -16, -1, 0, 1, 16, 17] {
            cuts.push((e as i64 + d) as usize);
        }
        cuts.push(e + SEALED_CHUNK / 2);
    }
    cuts.extend([
        good.len() - 1,
        good.len() - 16,
        good.len() - 17,
        start - 1,
        start - 16,
    ]);
    for cut in cuts.into_iter().filter(|c| *c < good.len()) {
        refused(&good[..cut], &unlock);
    }
    for chunks in [
        vec![c1.clone(), c0.clone(), c2.clone()],
        vec![c0.clone(), c0.clone(), c1.clone(), c2.clone()],
        vec![c0.clone(), c1.clone(), c1.clone(), c2.clone()],
        vec![c0.clone(), c1.clone()],
        vec![c0.clone(), c2.clone()],
        vec![c1.clone(), c2.clone()],
        vec![c0.clone()],
        vec![c2.clone()],
        // The flag moved: on the first chunk, on the middle one, and off the last.
        vec![p.c(0, true, 0), c1.clone(), c2.clone()],
        vec![c0.clone(), p.c(1, true, 1), c2.clone()],
        vec![c0.clone(), c1.clone(), p.c(2, false, 2)],
        // A last chunk at the right place but the wrong counter.
        vec![c0.clone(), c1.clone(), chunk(&p.key, 3, true, p.piece(2))],
        // A zero-length last chunk after the full ones.
        vec![c0.clone(), c1.clone(), chunk(&p.key, 2, true, b"")],
        // A chunk after the last.
        vec![
            c0.clone(),
            c1.clone(),
            c2.clone(),
            chunk(&p.key, 3, true, b"x"),
        ],
        vec![
            c0.clone(),
            c1.clone(),
            c2.clone(),
            chunk(&p.key, 3, false, b"x"),
        ],
        vec![c0.clone(), c1.clone(), c2.clone(), vec![0]],
    ] {
        refused(&p.file(&chunks), &unlock);
    }
    // One full chunk exactly: the format has no empty last chunk after it.
    let one = demo_bytes(CHUNK);
    let mut lone = p.head.clone();
    lone.extend(chunk(&p.key, 0, false, &one));
    lone.extend(chunk(&p.key, 1, true, b""));
    refused(&lone, &unlock);
    let mut right = p.head.clone();
    right.extend(chunk(&p.key, 0, true, &one));
    assert_eq!(
        open(&right, &unlock).unwrap(),
        one,
        "a full last chunk is fine"
    );
    // A chunk from a file with another nonce, spliced in.
    let other_nonce = [0x44u8; 16];
    let other_key = payload_key(&demo_file_key(), &other_nonce);
    let spliced = p.file(&[
        c0.clone(),
        chunk(&other_key, 1, false, p.piece(1)),
        c2.clone(),
    ]);
    refused(&spliced, &unlock);
    // Every bit of the payload nonce.
    for at in start - 16..start {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            refused(&bad, &unlock);
        }
    }
}

/// RT-06 (AT-A09, AT-FILE-03, FIL-03.2, FIL-03-T02): the work factor. Over the
/// ceiling, malformed, signed, padded, hexadecimal or huge: refused with zero
/// key derivations. 1 is legal and weak; 17 is weak; both ask for consent and
/// derive exactly once.
/// Mutant M06: the ceiling check removed (header.rs, `work_factor`). Mutant
/// M06b: weak means below 17 (decrypt.rs, `validate_inner`).
#[test]
fn fil_rt_work_factor_bounds_hold_before_any_derivation() {
    let phrase = secret(PASS);
    let unlock = Unlock::Passphrase(&phrase);
    let salt = [9u8; 16];
    let fk = demo_file_key();
    for cost in [
        "99",
        "21",
        "25",
        "31",
        "32",
        "63",
        "64",
        "127",
        "128",
        "255",
        "256",
        "1000",
        "18446744073709551616",
        "0",
        "00",
        "01",
        "018",
        "+18",
        "-18",
        "1e1",
        "0x12",
        "١٨",
        "18.0",
        "",
    ] {
        // The stanza line with any cost text, a body that would open at 18.
        let good = s_stanza(&fk, PASS, 4, &salt);
        let text = String::from_utf8(good).unwrap();
        let (line, body) = text.split_once('\n').unwrap();
        let line = format!("{} {cost}", line.rsplit_once(' ').unwrap().0);
        let file = signed_file(VERSION, format!("{line}\n{body}").as_bytes(), PLAIN);
        kdf_probe::take();
        refused(&file, &unlock);
        assert_eq!(
            kdf_probe::take(),
            0,
            "cost {cost:?} reached a key derivation"
        );
    }
    for weak in [1u8, 17] {
        let file = signed_file(VERSION, &s_stanza(&fk, PASS, weak, &salt), PLAIN);
        kdf_probe::take();
        let state = snapshot(&file).unlock_inner(&unlock).unwrap();
        assert_eq!(kdf_probe::take(), 1, "cost {weak}: one derivation");
        match state.validate_inner(&mut |_| Ok(()), &mut keep).unwrap() {
            Validation::Weak(w) => {
                let mut out = Vec::new();
                w.accept().write_to(&mut out, &mut keep).unwrap();
                assert_eq!(out, PLAIN);
            }
            Validation::Ready(_) => panic!("cost {weak} needs the user's consent"),
        }
    }
}

/// A reader that counts what it hands out, so a refusal can be shown to come
/// before the rest of the file is read.
struct Counted<'a> {
    inner: Cursor<&'a [u8]>,
    read: Rc<Cell<u64>>,
}

impl Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.set(self.read.get() + n as u64);
        Ok(n)
    }
}

impl Seek for Counted<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// RT-07 (AT-FILE-03, FIL-03.1, FIL-03-T01): many stanzas and a huge header.
/// 1,024 stanzas open; 1,025 do not. A header past 2 MiB is refused even with a
/// correct MAC, and an endless header line stops being read near the limit:
/// the reader is never drained.
/// Mutant M07: the header byte limit removed (header.rs, `read_line`). Mutant
/// M07b: the stanza count removed (header.rs, `read`).
#[test]
fn fil_rt_many_stanzas_and_huge_headers_are_refused_early() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let ignored = |n: usize| {
        let mut out = Vec::new();
        for i in 0..n {
            out.extend(raw_stanza(&format!("demo-{i}"), b""));
        }
        out
    };
    let mut at_limit = ignored(MAX_STANZAS - 1);
    at_limit.extend(to_a());
    assert_eq!(
        open(&signed_file(VERSION, &at_limit, PLAIN), &unlock).unwrap(),
        PLAIN
    );
    let mut over = ignored(MAX_STANZAS);
    over.extend(to_a());
    refused(&signed_file(VERSION, &over, PLAIN), &unlock);

    // One unknown stanza whose body takes the header past the limit.
    let mut huge = to_a();
    huge.extend(raw_stanza("demo", &vec![0x5Au8; MAX_HEADER * 3 / 4 + 4096]));
    let file = signed_file(VERSION, &huge, PLAIN);
    assert!(header_end(&file) > MAX_HEADER + 1000);
    let read = Rc::new(Cell::new(0));
    let src = Counted {
        inner: Cursor::new(&file[..]),
        read: Rc::clone(&read),
    };
    let result = Snapshot { src }.unlock_inner(&unlock);
    assert!(
        matches!(result, Err(Failure::Header)),
        "a huge header is refused"
    );
    refused(&file, &unlock);
    // An endless line: 48 MiB, no newline.
    let mut endless = b"age-encryption.org/v1\n-> demo ".to_vec();
    endless.resize(48 << 20, b'a');
    let read = Rc::new(Cell::new(0));
    let src = Counted {
        inner: Cursor::new(&endless[..]),
        read: Rc::clone(&read),
    };
    let result = Snapshot { src }.unlock_inner(&unlock);
    assert!(matches!(result, Err(Failure::Header)));
    assert!(
        read.get() <= (MAX_HEADER + 2 * 65_536) as u64,
        "read {} bytes of an endless header",
        read.get()
    );
}

/// RT-08 (AT-A01, AT-B07, AT-FILE-04, FIL-03.13, FIL-01-T11): every wrong
/// credential gives the one error, word for word: a wrong passphrase, a
/// passphrase on a key file, a key on a passphrase file, another person's key,
/// the key of another file, the passphrase of another file, a list of 64 wrong
/// keys. No output in any case. An empty passphrase is the user's input error,
/// before any key derivation.
/// Mutant M08: no match told apart from the other decrypt failures
/// (error.rs, `Failure::NoMatch` given as `Error::Passphrase`).
#[test]
fn fil_rt_wrong_credentials_give_the_one_error() {
    let to_a_file = seal_to(PLAIN, &[rec(ID_A)]);
    let to_b_file = seal_to(PLAIN, &[rec(ID_B)]);
    let pass_file = seal_pass(PLAIN, PASS);
    let other_pass_file = seal_pass(PLAIN, "another demo passphrase");
    let wrong = secret("demo passphrase ");
    let right = secret(PASS);
    let other = secret("another demo passphrase");
    let a = ids(ID_A);
    let b = ids(ID_B);
    let mut list = String::new();
    for _ in 0..64 {
        let (private, _) = crate::generate_identity().unwrap();
        list.push_str(private.expose());
        list.push('\n');
    }
    let many = Identities::from_list(list.as_bytes()).unwrap();
    let expected = same_message(Error::Decrypt);
    let cases: [(&[u8], Unlock<'_>); 8] = [
        (&pass_file[..], Unlock::Passphrase(&wrong)),
        (&to_a_file[..], Unlock::Passphrase(&right)),
        (&pass_file[..], Unlock::Identities(&a)),
        (&to_a_file[..], Unlock::Identities(&b)),
        (&to_b_file[..], Unlock::Identities(&a)),
        (&pass_file[..], Unlock::Passphrase(&other)),
        (&other_pass_file[..], Unlock::Passphrase(&right)),
        (&to_a_file[..], Unlock::Identities(&many)),
    ];
    for (file, unlock) in &cases {
        refused(file, unlock);
        let public = snapshot(file)
            .unlock(unlock)
            .and_then(|u| u.validate(&mut keep))
            .map(|_| ());
        assert_eq!(public, Err(Error::Decrypt));
        assert_eq!(same_message(public.unwrap_err()), expected);
    }
    // Controls: each right credential opens.
    assert_eq!(open(&to_a_file, &Unlock::Identities(&a)).unwrap(), PLAIN);
    assert_eq!(open(&to_b_file, &Unlock::Identities(&b)).unwrap(), PLAIN);
    assert_eq!(
        open(&pass_file, &Unlock::Passphrase(&right)).unwrap(),
        PLAIN
    );
    let empty = secret("");
    kdf_probe::take();
    let r = snapshot(&pass_file)
        .unlock(&Unlock::Passphrase(&empty))
        .map(|_| ());
    assert_eq!(r, Err(Error::Passphrase));
    assert_eq!(kdf_probe::take(), 0);
}

/// RT-09 (AT-FILE-04, FIL-01.4): a passphrase stanza must be alone. A header
/// with a scrypt stanza and an X25519 stanza that both open the same file key,
/// in either order, two scrypt stanzas, or a scrypt stanza and an unknown one,
/// is refused for the key and for the passphrase alike, with a correct MAC.
/// Mutant M09: the "scrypt alone" check removed (decrypt.rs, `unwrap_file_key`).
#[test]
fn fil_rt_a_passphrase_stanza_must_be_alone() {
    let keys = ids(ID_A);
    let by_key = Unlock::Identities(&keys);
    let phrase = secret(PASS);
    let by_phrase = Unlock::Passphrase(&phrase);
    let fk = demo_file_key();
    let s = s_stanza(&fk, PASS, 1, &[9u8; 16]);
    let s2 = s_stanza(&fk, PASS, 1, &[8u8; 16]);
    let a = to_a();
    let unknown = raw_stanza("demo", b"demo");
    assert_eq!(
        open(&signed_file(VERSION, &s, PLAIN), &by_phrase).unwrap(),
        PLAIN
    );
    assert_eq!(
        open(&signed_file(VERSION, &a, PLAIN), &by_key).unwrap(),
        PLAIN
    );
    for parts in [
        [&s[..], &a[..]],
        [&a[..], &s[..]],
        [&s[..], &s2[..]],
        [&s[..], &unknown[..]],
        [&unknown[..], &s[..]],
    ] {
        let file = signed_file(VERSION, &parts.concat(), PLAIN);
        kdf_probe::take();
        refused(&file, &by_key);
        refused(&file, &by_phrase);
        assert_eq!(kdf_probe::take(), 0, "refused before any key derivation");
    }
}

/// A private folder with `out/` in it, and a checked demo file ready to save.
struct Out {
    t: Temp,
    out: PathBuf,
    file: Vec<u8>,
}

impl Out {
    fn new() -> Self {
        let t = Temp::new();
        let out = t.sub("out");
        Self {
            t,
            out,
            file: seal_to(PLAIN, &[rec(ID_A)]),
        }
    }

    fn folder(&self) -> OutputFolder {
        OutputFolder::open(&self.out).unwrap()
    }

    fn save(&self, name: &OsStr) -> Result<u64, Error> {
        let keys = ids(ID_A);
        let v = checked(&self.file, &Unlock::Identities(&keys)).unwrap();
        v.save_new(&self.folder(), name, &mut keep)
    }
}

/// RT-10 (AT-FILE-09, FIL-03.8, FIL-03-T08): an output name that tries to
/// leave the chosen folder: `..`, `.`, an empty name, `../`, a path through
/// the folder and back out, an absolute path, a trailing slash or `/.`, a NUL,
/// a name over 255 bytes. Each is MSG-FILE-DESTINATION before any file, for a
/// decrypt and an encrypt; nothing is made in the folder or next to it. Odd
/// but plain names (`...`, `-`, a leading dot, a space) are fine.
/// Mutant M10: the plain-name check removed (fsio.rs, `check_name`).
#[test]
fn fil_rt_output_names_never_leave_the_chosen_folder() {
    let case = Out::new();
    let escape = case.t.0.join("escape");
    let absolute = case.t.0.join("absolute-escape");
    let absolute_text = absolute.to_string_lossy().into_owned();
    let long = "y".repeat(256);
    let bad: Vec<&OsStr> = vec![
        OsStr::new(".."),
        OsStr::new("."),
        OsStr::new(""),
        OsStr::new("../escape"),
        OsStr::new("../out/../escape"),
        OsStr::new("./escape"),
        OsStr::new(absolute_text.as_str()),
        OsStr::new("escape/"),
        OsStr::new("escape/."),
        OsStr::new("a/b"),
        OsStr::new(long.as_str()),
        OsStr::from_bytes(b"esc\0ape"),
    ];
    for name in &bad {
        assert_eq!(case.save(name), Err(Error::Destination), "{name:?}");
        let source = case.t.file("plain-source", b"demo plain source");
        let recipients = [rec(ID_A)];
        let r = encrypt_file(
            SourceFile::open(&source).unwrap(),
            &case.folder(),
            name,
            &Lock::Recipients(&recipients),
            &mut keep,
        );
        assert_eq!(r, Err(Error::Destination), "encrypt {name:?}");
        fs::remove_file(&source).unwrap();
    }
    assert!(names_in(&case.out).is_empty(), "{:?}", names_in(&case.out));
    assert_eq!(names_in(&case.t.0), ["out"], "nothing next to the folder");
    assert!(!escape.exists() && !absolute.exists());
    for plain in ["...", "-", ".hidden", "a b", "x..y"] {
        assert_eq!(
            case.save(OsStr::new(plain)),
            Ok(PLAIN.len() as u64),
            "{plain}"
        );
    }
}

fn mkfifo(path: &Path) {
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

/// Puts an entry of `kind` at `out/name`; a link's target goes in `t`.
fn plant(out: &Path, t: &Path, kind: &str, name: &str) {
    let at = out.join(name);
    let target = t.join(format!("target-{name}"));
    match kind {
        "fifo" => mkfifo(&at),
        "link" => {
            fs::write(&target, b"demo target").unwrap();
            symlink(&target, &at).unwrap();
        }
        "dangling" => symlink(t.join("nowhere"), &at).unwrap(),
        "dirlink" => {
            fs::create_dir(&target).unwrap();
            symlink(&target, &at).unwrap();
        }
        _ => fs::create_dir(&at).unwrap(),
    }
}

/// The entry `plant` put there is still there, as it was, and so is its target.
fn intact(out: &Path, t: &Path, kind: &str, name: &str) {
    let at = out.join(name);
    let ty = at.symlink_metadata().unwrap().file_type();
    let target = t.join(format!("target-{name}"));
    match kind {
        "fifo" => assert!(ty.is_fifo(), "{kind}"),
        "link" => {
            assert!(ty.is_symlink(), "{kind}");
            assert_eq!(fs::read(&target).unwrap(), b"demo target");
        }
        "dangling" => {
            assert!(ty.is_symlink(), "{kind}");
            assert!(!t.join("nowhere").exists());
        }
        "dirlink" => {
            assert!(ty.is_symlink(), "{kind}");
            assert!(names_in(&target).is_empty());
        }
        _ => assert!(ty.is_dir() && names_in(&at).is_empty(), "{kind}"),
    }
}

/// RT-11 (AT-FILE-06, FIL-03.8, FIL-03.9, FIL-03-T08): links and FIFOs at the
/// output name before the work and at the moment of the rename: a FIFO, a link
/// to a file outside, a dangling link, a link to a folder, a folder. Never
/// followed, never opened (no wait on a FIFO), never replaced: MSG-FILE-EXISTS
/// (MSG-FILE-DESTINATION for a folder put there at the rename), the planted
/// entry and any link target unchanged, and no staging folder left.
/// Mutant M11: the rename that never replaces made a plain rename
/// (larsal-platform folder.rs, `rename_new_in` without `RENAME_EXCL`).
#[test]
fn fil_rt_links_and_fifos_at_the_output_name_are_never_used() {
    for kind in ["fifo", "link", "dangling", "dirlink", "folder"] {
        // Planted before the work.
        let case = Out::new();
        plant(&case.out, &case.t.0, kind, "early");
        let (tx, rx) = mpsc::channel();
        let file = case.file.clone();
        let out = case.out.clone();
        std::thread::spawn(move || {
            let keys = ids(ID_A);
            let v = checked(&file, &Unlock::Identities(&keys)).unwrap();
            let folder = OutputFolder::open(&out).unwrap();
            let _ = tx.send(v.save_new(&folder, OsStr::new("early"), &mut keep));
        });
        let r = rx.recv_timeout(Duration::from_secs(20));
        if r.is_err() {
            // Free a thread stuck on the FIFO before failing.
            let _ = fs::OpenOptions::new()
                .write(true)
                .open(case.out.join("early"));
            panic!("{kind}: the save waited on the planted entry");
        }
        assert_eq!(r.unwrap(), Err(Error::Exists), "{kind} before the work");
        intact(&case.out, &case.t.0, kind, "early");
        assert_eq!(names_in(&case.out), ["early"], "{kind}");

        // Planted at the last moment, before the rename.
        let case = Out::new();
        let (out, t) = (case.out.clone(), case.t.0.clone());
        watch::at_commit(Box::new(move || plant(&out, &t, kind, "late")));
        let r = case.save(OsStr::new("late"));
        let want = if kind == "folder" || kind == "dirlink" {
            vec![Err(Error::Exists), Err(Error::Destination)]
        } else {
            vec![Err(Error::Exists)]
        };
        assert!(want.contains(&r), "{kind} at the rename: {r:?}");
        intact(&case.out, &case.t.0, kind, "late");
        assert_eq!(
            names_in(&case.out),
            ["late"],
            "{kind}: no staging folder left"
        );
    }
}

/// RT-11b (FIL-03.8, FIL-03.9): a folder this user cannot write gets no file
/// and no staging folder, for a decrypt and an encrypt.
/// Mutant M11b: a failed staging folder taken as made (fsio.rs, `NewOutput::create`,
/// the `make_dir_in` error ignored).
#[test]
fn fil_rt_a_read_only_folder_gets_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let case = Out::new();
    fs::set_permissions(&case.out, fs::Permissions::from_mode(0o500)).unwrap();
    let decrypted = case.save(OsStr::new("plain.bin"));
    let source = case.t.file("plain-source", b"demo plain source");
    let recipients = [rec(ID_A)];
    let encrypted = encrypt_file(
        SourceFile::open(&source).unwrap(),
        &case.folder(),
        OsStr::new("x.age"),
        &Lock::Recipients(&recipients),
        &mut keep,
    );
    fs::set_permissions(&case.out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(decrypted, Err(Error::Destination));
    assert_eq!(encrypted, Err(Error::Destination));
    assert!(names_in(&case.out).is_empty());
    assert_eq!(fs::read(&source).unwrap(), b"demo plain source");
}

/// Runs `open` on a thread and says whether it came back within five seconds.
/// A thread stuck on a FIFO is freed by opening the FIFO's other end.
fn returns_soon(fifo: &Path, open: impl FnOnce() -> bool + Send + 'static) -> Option<bool> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open());
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(ok) => Some(ok),
        Err(_) => {
            let _ = fs::OpenOptions::new().write(true).open(fifo);
            let _ = rx.recv_timeout(Duration::from_secs(5));
            None
        }
    }
}

/// RT-12 (F-555, FIL-03.11, FIL-02.22 limit (8)): a scratch root is a real
/// folder. Opening one never waits on a FIFO and never goes through a link.
/// Fails on BASE: `ScratchRoot::open` is a plain `File::open` (fsio.rs), which
/// follows a link to this user's private folder and waits on a FIFO until a
/// writer comes. Fix by the Builder (F-555's own fix: open it with
/// larsal-platform's `open_dir`).
#[test]
fn fil_rt_scratch_root_open_takes_no_fifo_and_no_link() {
    let t = Temp::new();
    let fifo = t.0.join("scratch-fifo");
    mkfifo(&fifo);
    let f = fifo.clone();
    let came_back = returns_soon(&fifo, move || ScratchRoot::open(&f).is_ok());
    assert_eq!(
        came_back,
        Some(false),
        "a FIFO as scratch root: waited or taken"
    );
    let real = t.sub("real");
    let link = t.0.join("link");
    symlink(&real, &link).unwrap();
    assert!(
        ScratchRoot::open(&link).is_err(),
        "a link to a private folder was taken as the scratch root"
    );
}

/// RT-12b (new, FIL-03.8, FIL-03.14): an output folder is a real folder; a
/// FIFO named as the folder is refused at once. Fails on BASE:
/// `OutputFolder::open` is a plain `File::open` (fsio.rs), which waits on a FIFO
/// until a writer comes, so `larsal decrypt x --output FIFO/name` and the
/// bridge's `choose` hang before any prompt. Fix by the Builder (open the
/// folder with `O_DIRECTORY | O_NONBLOCK`, as larsal-platform's `open_dir` does,
/// keeping links to folders allowed if wanted).
#[test]
fn fil_rt_output_folder_open_never_waits_on_a_fifo() {
    let t = Temp::new();
    let fifo = t.0.join("out-fifo");
    mkfifo(&fifo);
    let f = fifo.clone();
    let came_back = returns_soon(&fifo, move || OutputFolder::open(&f).is_ok());
    assert_eq!(
        came_back,
        Some(false),
        "a FIFO as output folder: waited or taken"
    );
}

/// RT-13 (F-528, FIL-03.7, FIL-03-T07, AT-FILE-07), the library half: what a
/// write that stops dead leaves (a crash between the first byte and the
/// rename) is exactly the documented residual: nothing at the chosen name, one
/// hidden staging folder of this user, 0700, holding only `incomplete`, 0600,
/// one link. A second save to the same name is not blocked by it, and it is
/// never swept.
/// Mutant M13: the staging folder made 0755 (fsio.rs, `NewOutput::create`).
#[test]
fn fil_rt_a_dead_write_leaves_only_the_private_staging_folder() {
    let case = Out::new();
    let keys = ids(ID_A);
    let v = checked(&case.file, &Unlock::Identities(&keys)).unwrap();
    // The worker dies in its write: the output is leaked as a crash leaves it.
    let folder = case.folder();
    let mut out = crate::fsio::NewOutput::create(
        &folder,
        OsStr::new("dead.bin"),
        crate::fsio::Holds::Plaintext,
        &mut || false,
    )
    .unwrap();
    let mut first = Vec::new();
    v.write_to(&mut first, &mut keep).unwrap();
    out.write(&first[..10]).unwrap();
    std::mem::forget(out);
    let names = names_in(&case.out);
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(!case.out.join("dead.bin").exists());
    let staging = case.out.join(&names[0]);
    let tail = names[0].strip_prefix(".larsal-staging-").unwrap();
    assert!(
        tail.len() == 32
            && tail
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let m = staging.symlink_metadata().unwrap();
    let own = fs::metadata(&case.out).unwrap().uid();
    assert!(
        m.is_dir() && m.mode() & 0o7777 == 0o700 && m.uid() == own,
        "{:o}",
        m.mode()
    );
    assert_eq!(names_in(&staging), ["incomplete"]);
    let f = staging.join("incomplete").symlink_metadata().unwrap();
    assert!(
        f.is_file() && f.mode() & 0o7777 == 0o600 && f.nlink() == 1,
        "{:o}",
        f.mode()
    );
    assert_eq!(fs::read(staging.join("incomplete")).unwrap(), &PLAIN[..10]);
    // The next save to the same name works and leaves the residual alone.
    assert_eq!(case.save(OsStr::new("dead.bin")), Ok(PLAIN.len() as u64));
    let mut after = names_in(&case.out);
    after.sort();
    assert_eq!(after, [names[0].clone(), "dead.bin".to_owned()]);
    // A scratch sweep of this folder takes nothing of it.
    if let Ok(root) = ScratchRoot::open(&case.out) {
        let _ = root.sweep();
    }
    assert!(staging.join("incomplete").exists());
}
