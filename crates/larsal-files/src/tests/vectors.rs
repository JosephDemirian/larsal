//! FIL-03.17, FIL-03-T17: the vector runner. Files have the form of the published
//! test files: `key: value` lines, a blank line, then the file's bytes.
//!
//! `testdata/age-testkit/` holds the published files, pinned by count, hash and
//! the counts below (`SOURCE.md` there says where they come from). They run by
//! default; a corpus put elsewhere stops the run.
//! `testdata/derived/` holds the runner's own proof: files written from the public
//! format text by `testdata/make_derived.py`, a separate writing in Python that
//! shares no code with this crate and first passes the RFC vectors.
//!
//! A row is compared before normalizing: the expected stage against the internal
//! cause, the plaintext's hash, the prefix's hash, and the file key against the
//! payload key it gives. A row the profile does not support, and a row over a
//! limit of the cards that the corpus expects to open, are counted apart, open, and
//! are never a pass. A row marked `armored: yes` goes through the armor route.

use super::*;
use crate::armor::Source;
use crate::fsio::watch;
use crate::limits::{CHUNK, MAX_ARMOR_SPACE, MAX_HEADER, MAX_STANZAS, READ_MAX_LOG_N};
use larsal_crypto::hash;
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};

const PUBLISHED: &str = "testdata/age-testkit";
const DERIVED: &str = "testdata/derived";
/// C2SP/CCTV at the commit `SOURCE.md` names (FIL-03.18).
const PUBLISHED_FILES: usize = 147;
const PUBLISHED_HASH: &str = "461c15f61ce87a16ef71f22080a5d7876a1fa21b00c62a6a077883fb4a73555b";
/// What must pass in profile age-classic-1, by the stage each row names.
const PUBLISHED_PASSES: [(&str, usize); 6] = [
    ("Success", 21),
    ("NoMatch", 8),
    ("HmacFailure", 1),
    ("HeaderFailure", 53),
    ("PayloadFailure", 19),
    ("ArmorFailure", 26),
];
/// Outside the profile (LD-366): recorded OPEN by name, never a pass.
const PUBLISHED_OPEN: [&str; 19] = [
    "armor_hybrid",
    "hybrid",
    "hybrid_and_x25519",
    "hybrid_bad_tag",
    "hybrid_currupted_enc_mlkem",
    "hybrid_currupted_enc_x25519",
    "hybrid_extra_argument",
    "hybrid_grease",
    "hybrid_identity",
    "hybrid_long_file_key",
    "hybrid_long_share",
    "hybrid_low_order",
    "hybrid_multiple_recipients",
    "hybrid_no_match",
    "hybrid_not_canonical_body",
    "hybrid_not_canonical_enc",
    "hybrid_short_share",
    "hybrid_uppercase",
    "hybrid_x25519_arg",
];
/// A full chunk that opens only under the other flag: refused, and its plaintext
/// counted in the internal hash the row names (FIL-03.17).
const OTHER_FLAG_ROWS: [&str; 8] = [
    "armor_garbage_encoded",
    "stream_no_final_full",
    "stream_no_final_two_chunks_full",
    "stream_trailing_garbage_long",
    "stream_trailing_garbage_short",
    "stream_two_final_chunks",
    "stream_two_final_chunks_full",
    "stream_two_final_chunks_second",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum Expect {
    Success,
    NoMatch,
    HmacFailure,
    HeaderFailure,
    PayloadFailure,
    ArmorFailure,
}

#[derive(Debug, Clone)]
struct Vector {
    name: String,
    expect: Expect,
    payload: Option<Vec<u8>>,
    file_key: Option<Vec<u8>>,
    identities: Vec<String>,
    passphrases: Vec<String>,
    armored: bool,
    body: Vec<u8>,
}

fn from_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(name: &str, raw: &[u8]) -> Result<Vector, String> {
    let split = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| format!("{name}: no blank line"))?;
    let (head, rest) = raw.split_at(split);
    let mut body = rest[2..].to_vec();
    let head = std::str::from_utf8(head).map_err(|_| format!("{name}: head is not UTF-8"))?;
    let mut vector = Vector {
        name: name.to_string(),
        expect: Expect::Success,
        payload: None,
        file_key: None,
        identities: Vec::new(),
        passphrases: Vec::new(),
        armored: false,
        body: Vec::new(),
    };
    let mut got_expect = false;
    for line in head.lines() {
        let (key, value) = line
            .split_once(": ")
            .ok_or_else(|| format!("{name}: bad line {line}"))?;
        match key {
            "expect" => {
                got_expect = true;
                vector.expect = match value {
                    "success" => Expect::Success,
                    "no match" => Expect::NoMatch,
                    "HMAC failure" => Expect::HmacFailure,
                    "header failure" => Expect::HeaderFailure,
                    "payload failure" => Expect::PayloadFailure,
                    "armor failure" => Expect::ArmorFailure,
                    other => return Err(format!("{name}: unknown expect {other}")),
                };
            }
            "payload" => vector.payload = Some(from_hex(value)),
            "file key" => vector.file_key = Some(from_hex(value)),
            "identity" => vector.identities.push(value.to_string()),
            "passphrase" => vector.passphrases.push(value.to_string()),
            "armored" => vector.armored = value == "yes",
            "comment" => {}
            "compressed" => {
                if value != "zlib" {
                    return Err(format!("{name}: unknown compression {value}"));
                }
                let mut plain = Vec::new();
                flate2::read::ZlibDecoder::new(&body[..])
                    .read_to_end(&mut plain)
                    .map_err(|_| format!("{name}: bad zlib"))?;
                body = plain;
            }
            other => return Err(format!("{name}: unknown key {other}")),
        }
    }
    if !got_expect {
        return Err(format!("{name}: no expect line"));
    }
    vector.body = body;
    Ok(vector)
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Pass,
    /// A row outside the profile: refused, and recorded as still open.
    Unsupported(String),
    /// A row over a limit of the cards that the corpus expects otherwise: refused
    /// by rule, and recorded as still open (FIL-03.17).
    Policy(String),
    Fail(String),
}

fn expected_failure(expect: Expect) -> Option<Failure> {
    match expect {
        Expect::Success => None,
        Expect::NoMatch => Some(Failure::NoMatch),
        Expect::HmacFailure => Some(Failure::Mac),
        Expect::HeaderFailure => Some(Failure::Header),
        Expect::PayloadFailure => Some(Failure::Payload),
        Expect::ArmorFailure => Some(Failure::Armor),
    }
}

/// True for a row the classical profile refuses by rule (FIL-01.20).
fn outside_profile(vector: &Vector) -> Option<String> {
    let body = &vector.body;
    let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
    if has(b"-> mlkem768x25519") {
        return Some("native post-quantum recipient".into());
    }
    if vector
        .identities
        .iter()
        .any(|i| i.starts_with("AGE-SECRET-KEY-PQ-"))
    {
        return Some("native post-quantum identity".into());
    }
    if vector
        .identities
        .iter()
        .any(|i| i.starts_with("AGE-PLUGIN-"))
    {
        return Some("plugin identity".into());
    }
    None
}

/// A limit of the cards (FIL-03.1, FIL-03.2) this row goes past, seen in its raw
/// bytes. An armored row is not decoded for this: it comes out as a failure, which
/// is loud.
fn policy_limit(vector: &Vector) -> Option<String> {
    let body = &vector.body;
    let space = body
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .count();
    if space > MAX_ARMOR_SPACE {
        return Some(format!("{space} bytes of white space first"));
    }
    let end = body
        .windows(4)
        .position(|w| w == b"--- ")
        .unwrap_or(body.len());
    if end > MAX_HEADER {
        return Some(format!("a header of {end} bytes"));
    }
    let stanzas: Vec<&[u8]> = body[..end]
        .split(|b| *b == b'\n')
        .filter(|line| line.starts_with(b"-> "))
        .collect();
    if stanzas.len() > MAX_STANZAS {
        return Some(format!("{} stanzas", stanzas.len()));
    }
    let over_ceiling = |line: &&[u8]| {
        line.starts_with(b"-> scrypt ")
            && line
                .rsplit(|b| *b == b' ')
                .next()
                .and_then(|cost| std::str::from_utf8(cost).ok())
                .and_then(|cost| cost.parse::<u64>().ok())
                .is_some_and(|cost| cost > u64::from(READ_MAX_LOG_N))
    };
    stanzas
        .iter()
        .any(over_ceiling)
        .then(|| format!("a scrypt cost over {READ_MAX_LOG_N}"))
}

fn run(vector: &Vector) -> Outcome {
    let outside = outside_profile(vector);
    let phrases: Vec<SecretString> = vector.passphrases.iter().map(|p| secret(p)).collect();
    let mut lines = Vec::new();
    for identity in &vector.identities {
        match ids_checked(identity) {
            Ok(line) => lines.push(line),
            Err(outcome) => return outcome,
        }
    }
    // A row with no credential is about the file itself: any unrelated identity does.
    let parsed = if lines.is_empty() {
        phrases.is_empty().then(|| ids(ID_B))
    } else {
        match Identities::from_list(lines.join("\n").as_bytes()) {
            Ok(keys) => Some(keys),
            Err(_) => return Outcome::Fail("no usable identity".into()),
        }
    };
    // A person with all of the row's credentials uses the one that fits, if any.
    let mut unlocks: Vec<Unlock<'_>> = parsed.iter().map(Unlock::Identities).collect();
    unlocks.extend(phrases.iter().map(Unlock::Passphrase));
    let misses = |u: &&Unlock<'_>| {
        matches!(
            snapshot(&vector.body).unlock_inner(u),
            Err(Failure::NoMatch)
        )
    };
    let chosen = unlocks.iter().find(|u| !misses(u)).or(unlocks.first());
    let Some(unlock) = chosen else {
        return Outcome::Fail("no credential on the row".into());
    };

    watch::take();
    // A row marked as armor goes through the armor route, whatever comes first in
    // it. The product's own route must refuse the same bytes.
    if vector.armored
        && let Err(cause) = Source::armored(&vector.body[..])
    {
        if snapshot(&vector.body).unlock_inner(unlock).is_ok() {
            return Outcome::Fail("the product opened what the armor route refused".into());
        }
        return judge(vector, cause, &[], outside);
    }
    // The stage comes out with the plaintext that passed before it.
    let mut prefix = Vec::new();
    let unwrapped = match snapshot(&vector.body).unlock_inner(unlock) {
        Ok(u) => u,
        Err(cause) => return judge(vector, cause, &prefix, outside),
    };
    if let Some(key) = &vector.file_key {
        let key = SecretBytes::new(key.clone());
        let expected = payload_key(&key, &unwrapped.nonce);
        if expected != unwrapped.payload_key {
            return Outcome::Fail("wrong file key".into());
        }
    }
    let validation = {
        let mut sink = |bytes: &[u8]| {
            prefix.extend_from_slice(bytes);
            Ok(())
        };
        unwrapped.validate_inner(&mut sink, &mut keep)
    };
    let validated = match validation {
        Ok(Validation::Ready(v)) => v,
        Ok(Validation::Weak(w)) => w.accept(),
        Err(cause) => return judge(vector, cause, &prefix, outside),
    };
    if outside.is_some() {
        return Outcome::Fail("a row outside the profile opened".into());
    }
    if vector.expect != Expect::Success {
        return Outcome::Fail(format!("expected {:?}, the file opened", vector.expect));
    }
    let mut out = Vec::new();
    if validated.write_to(&mut out, &mut keep).is_err() {
        return Outcome::Fail("the second pass failed".into());
    }
    if out != prefix {
        return Outcome::Fail("the passes gave different bytes".into());
    }
    match &vector.payload {
        Some(want) if hash::sha256(&[&out]).expose() != &want[..] => {
            Outcome::Fail("wrong plaintext".into())
        }
        _ => Outcome::Pass,
    }
}

/// A list line for a supported identity, or the row's outcome.
fn ids_checked(identity: &str) -> Result<String, Outcome> {
    if identity.starts_with("AGE-SECRET-KEY-PQ-") || identity.starts_with("AGE-PLUGIN-") {
        return Err(Outcome::Unsupported(format!(
            "identity type {}",
            identity.split('1').next().unwrap_or("")
        )));
    }
    Ok(identity.to_string())
}

fn judge(vector: &Vector, cause: Failure, prefix: &[u8], outside: Option<String>) -> Outcome {
    if !no_output(&watch::take()) {
        return Outcome::Fail("output during a failed validation".into());
    }
    if Error::from(cause) != Error::Decrypt {
        return Outcome::Fail(format!("not the generic error: {cause:?}"));
    }
    if let Some(why) = outside {
        // Refused, as the profile says; recorded, and not a pass.
        return Outcome::Unsupported(why);
    }
    if expected_failure(vector.expect) != Some(cause) {
        return match policy_limit(vector) {
            Some(why) => Outcome::Policy(why),
            None => Outcome::Fail(format!("expected {:?}, got {cause:?}", vector.expect)),
        };
    }
    if let Some(want) = &vector.payload
        && hash::sha256(&[prefix]).expose() != &want[..]
    {
        return Outcome::Fail(format!(
            "prefix hash {} after {} bytes",
            hex(hash::sha256(&[prefix]).expose()),
            prefix.len()
        ));
    }
    Outcome::Pass
}

fn folder(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load(dir: &Path) -> Vec<Vector> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|e| e != "md"))
        .collect();
    names.sort();
    names
        .iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            parse(&name, &fs::read(path).unwrap()).unwrap()
        })
        .collect()
}

#[derive(Default)]
struct Tally {
    passed: BTreeMap<String, usize>,
    unsupported: Vec<(String, String)>,
    policy: Vec<(String, String)>,
    failed: Vec<(String, String)>,
}

fn run_all(vectors: &[Vector]) -> Tally {
    let mut tally = Tally::default();
    for vector in vectors {
        match run(vector) {
            Outcome::Pass => {
                *tally
                    .passed
                    .entry(format!("{:?}", vector.expect))
                    .or_default() += 1;
            }
            Outcome::Unsupported(why) => tally.unsupported.push((vector.name.clone(), why)),
            Outcome::Policy(why) => tally.policy.push((vector.name.clone(), why)),
            Outcome::Fail(why) => tally.failed.push((vector.name.clone(), why)),
        }
    }
    println!("passed by family: {:?}", tally.passed);
    println!("OPEN, unsupported, not passes: {:?}", tally.unsupported);
    println!("OPEN, policy limit, not passes: {:?}", tally.policy);
    tally
}

/// No row failed or met a limit, each family has its exact count, and exactly the
/// rows outside the profile stayed open.
fn check_published(tally: &Tally) -> Result<(), String> {
    if !tally.failed.is_empty() {
        return Err(format!("{:#?}", tally.failed));
    }
    if !tally.policy.is_empty() {
        return Err(format!("over a limit: {:#?}", tally.policy));
    }
    let open: Vec<&str> = tally.unsupported.iter().map(|r| r.0.as_str()).collect();
    if open != PUBLISHED_OPEN {
        return Err(format!("open rows: {open:?}"));
    }
    for (family, want) in PUBLISHED_PASSES {
        let got = tally.passed.get(family).copied().unwrap_or(0);
        if got != want {
            return Err(format!("{family}: {got} rows, {want} wanted"));
        }
    }
    Ok(())
}

/// The hash `SOURCE.md` explains, over the rows as they are on disk.
fn corpus_hash(dir: &Path) -> (usize, String) {
    let mut lines = Vec::new();
    let names = names_in(dir);
    let rows: Vec<&String> = names.iter().filter(|n| !n.ends_with(".md")).collect();
    for name in &rows {
        let sum = hash::sha256(&[&fs::read(dir.join(name)).unwrap()]);
        lines.extend_from_slice(format!("{name} {}\n", hex(sum.expose())).as_bytes());
    }
    (rows.len(), hex(hash::sha256(&[&lines]).expose()))
}

/// C1-R2-03: a green run must say what stays open. Print macros are captured when a
/// test passes; this stream is not.
fn print_open(open: &[(String, String)]) {
    let mut text = format!(
        "age-testkit: {} rows OPEN, outside profile age-classic-1 (LD-366), not passes:\n",
        open.len()
    );
    for (name, why) in open {
        text.push_str(&format!("  OPEN {name}: {why}\n"));
    }
    std::io::stderr().write_all(text.as_bytes()).unwrap();
}

#[test]
fn fil03_t17_published_vectors_pass() {
    let dir = folder(PUBLISHED);
    assert_eq!(
        corpus_hash(&dir),
        (PUBLISHED_FILES, PUBLISHED_HASH.to_string())
    );
    let tally = run_all(&load(&dir));
    print_open(&tally.unsupported);
    check_published(&tally).unwrap();
}

#[test]
fn fil03_t17_a_corpus_in_place_runs_by_default_and_a_misplaced_one_stops_the_run() {
    assert_eq!(
        names_in(&folder("testdata")),
        ["age-testkit", "derived", "make_derived.py"],
        "published vectors go at {PUBLISHED}"
    );
    let names = names_in(&folder(PUBLISHED));
    assert_eq!(names.len(), PUBLISHED_FILES + 2);
    assert!(names.iter().any(|n| n == "README.md") && names.iter().any(|n| n == "SOURCE.md"));
    assert_eq!(load(&folder(PUBLISHED)).len(), PUBLISHED_FILES);
}

#[test]
fn fil03_t17_a_thin_or_foreign_corpus_does_not_pass() {
    let all = load(&folder(PUBLISHED));
    check_published(&run_all(&all)).unwrap();

    // Only rows outside the profile: nothing fails, and it is no pass.
    let tally = run_all(&[derived("native_pq_only")]);
    assert!(tally.failed.is_empty());
    assert_eq!(tally.unsupported.len(), 1);
    assert!(check_published(&tally).is_err());

    // One row cut, from a family.
    let at = all
        .iter()
        .position(|v| v.expect == Expect::ArmorFailure)
        .unwrap();
    let mut cut = all.clone();
    cut.remove(at);
    let why = check_published(&run_all(&cut)).unwrap_err();
    assert!(why.contains("ArmorFailure"), "{why}");

    // One row with another expectation.
    let mut bent = all.clone();
    bent[at].expect = Expect::HmacFailure;
    assert!(check_published(&run_all(&bent)).is_err());

    // One open row more.
    let mut more = all;
    more.push(derived("native_pq_only"));
    let why = check_published(&run_all(&more)).unwrap_err();
    assert!(why.contains("open rows"), "{why}");

    // A failed row, or one over a limit, with the counts all right.
    let good = run_all(&load(&folder(PUBLISHED)));
    let mut tally = run_all(&load(&folder(PUBLISHED)));
    tally.failed.push(("demo".into(), "demo".into()));
    assert!(check_published(&tally).is_err());
    let mut tally = good;
    check_published(&tally).unwrap();
    tally.policy.push(("demo".into(), "demo".into()));
    assert!(check_published(&tally).is_err());

    // A file changed on disk, or one more, is another hash.
    let t = Temp::new();
    let dir = t.sub("copy");
    fs::write(dir.join("a"), b"expect: success\n\nbody").unwrap();
    let before = corpus_hash(&dir);
    fs::write(dir.join("a"), b"expect: success\n\nbodY").unwrap();
    assert_ne!(corpus_hash(&dir), before);
    fs::write(dir.join("b"), b"").unwrap();
    assert_eq!(corpus_hash(&dir).0, 2);
}

#[test]
fn fil03_t17_a_row_over_a_cards_limit_is_recorded_open_and_never_a_pass() {
    // A cost over the ceiling, on a row that says it opens.
    let mut row = derived("scrypt_basic");
    let at = row
        .body
        .windows(10)
        .position(|w| w == b"-> scrypt ")
        .unwrap();
    let end = at + row.body[at..].iter().position(|b| *b == b'\n').unwrap();
    let space = at + row.body[at..end].iter().rposition(|b| *b == b' ').unwrap();
    row.body.splice(space + 1..end, b"21".iter().copied());
    assert!(
        matches!(run(&row), Outcome::Policy(why) if why.contains("scrypt cost")),
        "{:?}",
        run(&row)
    );
    let tally = run_all(&[row]);
    assert!(tally.passed.is_empty() && tally.failed.is_empty());
    assert_eq!(tally.policy.len(), 1);
    assert!(check_published(&tally).is_err());

    // More white space than armor may have.
    let mut row = derived("x25519_basic");
    row.body.splice(0..0, vec![b' '; MAX_ARMOR_SPACE + 1]);
    assert!(matches!(run(&row), Outcome::Policy(why) if why.contains("white space")));

    // More stanzas than a header may have.
    let mut row = derived("x25519_basic");
    let many = b"-> demo\nAAAA\n".repeat(MAX_STANZAS + 1);
    row.body.splice(22..22, many);
    assert!(matches!(run(&row), Outcome::Policy(why) if why.contains("stanzas")));

    // A longer header than a file may have.
    let mut row = derived("x25519_basic");
    row.body.splice(22..22, vec![b'A'; MAX_HEADER + 1]);
    assert!(matches!(run(&row), Outcome::Policy(why) if why.contains("header")));

    // Within every limit a wrong expectation is still a failure.
    let mut row = derived("scrypt_basic");
    row.expect = Expect::HeaderFailure;
    assert!(matches!(run(&row), Outcome::Fail(_)));
}

#[test]
fn fil03_t17_a_row_names_its_stage_and_its_credentials() {
    // Armored, and junk first: the row calls that an armor failure.
    let row = derived("armor_junk_before_begin");
    assert!(row.armored);
    assert_eq!(row.expect, Expect::ArmorFailure);
    assert_eq!(run(&row), Outcome::Pass);
    // Not marked armored, the same bytes are a bad version line.
    let mut plain_row = row.clone();
    plain_row.armored = false;
    assert!(matches!(run(&plain_row), Outcome::Fail(_)));
    plain_row.expect = Expect::HeaderFailure;
    assert_eq!(run(&plain_row), Outcome::Pass);
    // Armor that does start right keeps its own stage.
    let mut wrong_stage = derived("armor_crlf");
    wrong_stage.body.truncate(wrong_stage.body.len() / 2);
    wrong_stage.expect = Expect::HeaderFailure;
    assert!(matches!(run(&wrong_stage), Outcome::Fail(_)));
    // Good armor round a bad header is a header failure, armored row or not: the
    // route does not rename a stage (C1-R2-11).
    let mut inner = derived("armor_crlf");
    inner.body = armor(b"not a header\n", "\n");
    inner.payload = None;
    inner.file_key = None;
    inner.expect = Expect::HeaderFailure;
    assert!(inner.armored);
    assert_eq!(run(&inner), Outcome::Pass);
    inner.expect = Expect::ArmorFailure;
    assert!(matches!(run(&inner), Outcome::Fail(_)));

    // Every credential on a row counts: an identity and a passphrase, either way
    // round, and the second of two passphrases.
    let mut row = derived("x25519_basic");
    row.passphrases = vec!["not this one".into()];
    assert_eq!(run(&row), Outcome::Pass);
    let mut row = derived("scrypt_basic");
    row.identities = vec![ID_A.into()];
    assert_eq!(run(&row), Outcome::Pass);
    row.identities.clear();
    row.passphrases.insert(0, "not this one".into());
    assert_eq!(run(&row), Outcome::Pass);
    // None of them fits.
    row.passphrases.remove(1);
    assert!(matches!(run(&row), Outcome::Fail(_)));
    row.expect = Expect::NoMatch;
    row.payload = None;
    row.file_key = None;
    assert_eq!(run(&row), Outcome::Pass);
    // No credential at all: an unrelated identity stands in, and opens nothing.
    row.passphrases.clear();
    assert_eq!(run(&row), Outcome::Pass);
    let mut row = derived("x25519_basic");
    row.identities.clear();
    assert!(matches!(run(&row), Outcome::Fail(_)));
    assert_eq!(run(&derived("empty_file")), Outcome::Pass);
}

/// The sealed bytes after the nonce, and what comes out on the way to a failure, on
/// one pass. A failed tag leaves the buffer as it was, so a chunk counted is whole.
fn one_pass(body: &[u8], phase: Phase) -> (Result<u64, Failure>, Vec<u8>) {
    let key = payload_key(&demo_file_key(), &NONCE);
    let mut seen = Vec::new();
    let mut src = Source::Binary(BufReader::new(body));
    let result = crate::payload::open_chunks(
        &mut src,
        &key,
        phase,
        &mut |bytes| {
            seen.extend_from_slice(bytes);
            Ok(())
        },
        &mut keep,
    );
    (result, seen)
}

/// A whole file to `ID_A` around chunks that were sealed by hand.
fn with_chunks(body: &[u8]) -> Vec<u8> {
    let file_key = demo_file_key();
    let stanzas = x_stanza(&file_key, &rec(ID_A), 7);
    [&sealed_header(&file_key, &stanzas)[..], &NONCE[..], body].concat()
}

#[test]
fn fil03_t17_the_discard_pass_counts_a_full_chunk_under_the_other_flag_and_still_refuses() {
    // Every published row of this kind, by the hash it names.
    let keys = ids(ID_A);
    for name in OTHER_FLAG_ROWS {
        let raw = fs::read(folder(PUBLISHED).join(name)).unwrap();
        let mut row = parse(name, &raw).unwrap();
        assert_eq!(row.expect, Expect::PayloadFailure, "{name}");
        assert_eq!(row.payload.as_ref().map(Vec::len), Some(32), "{name}");
        assert_eq!(run(&row), Outcome::Pass, "{name}");
        row.payload = Some(vec![0; 32]);
        assert!(matches!(run(&row), Outcome::Fail(_)), "{name}");
    }

    let key = payload_key(&demo_file_key(), &NONCE);
    let full = demo_bytes(CHUNK);
    let two = [&full[..], &full[..]].concat();
    let last = chunk(&key, 0, true, &full);
    let middle = chunk(&key, 0, false, &full);
    let second_as_middle = chunk(&key, 1, false, &full);
    for (what, body, counted) in [
        (
            "full last chunk, then bytes",
            [&last[..], b"x"].concat(),
            &full,
        ),
        (
            "full last chunk, then a good last chunk",
            [&last[..], &chunk(&key, 1, true, PLAIN)[..]].concat(),
            &full,
        ),
        ("full chunk, not last, then the end", middle.clone(), &full),
        (
            "two full chunks, not last, then the end",
            [&middle[..], &second_as_middle[..]].concat(),
            &two,
        ),
    ] {
        // The discard pass counts it, and the file is refused.
        let (result, seen) = one_pass(&body, Phase::Validate);
        assert_eq!(result, Err(Failure::Payload), "{what}");
        assert_eq!(&seen, counted, "{what}");
        // The pass that writes does not take the other flag: only chunks that
        // hold as they stand reach it. A first chunk under the other flag is nothing.
        let (result, seen) = one_pass(&body, Phase::Write);
        assert_eq!(result, Err(Failure::Payload), "{what}");
        assert_eq!(seen.len(), counted.len() - CHUNK, "{what}");
        // The whole public flow: refused, and not a byte to a caller's writer.
        let file = with_chunks(&body);
        assert_eq!(
            refused(&file, &Unlock::Identities(&keys)),
            Failure::Payload,
            "{what}"
        );
        assert_eq!(
            snapshot(&file)
                .unlock(&Unlock::Identities(&keys))
                .unwrap()
                .validate(&mut keep)
                .map(|_| ()),
            Err(Error::Decrypt)
        );
    }

    // Nothing else is tried: a short chunk under the other flag, a full one that
    // opens under neither.
    let (result, seen) = one_pass(&chunk(&key, 0, false, PLAIN), Phase::Validate);
    assert_eq!(result, Err(Failure::Payload));
    assert!(seen.is_empty());
    let mut broken = last;
    broken[0] ^= 1;
    let (result, seen) = one_pass(&broken, Phase::Validate);
    assert_eq!(result, Err(Failure::Payload));
    assert!(seen.is_empty());

    // What opened still opens, at a chunk's edge too.
    for plain in [full, two] {
        let file = craft(b"", &plain);
        assert_eq!(open(&file, &Unlock::Identities(&keys)).unwrap(), plain);
        let (result, seen) = one_pass(&file[header_end(&file) + 16..], Phase::Validate);
        assert_eq!(result, Ok(plain.len() as u64));
        assert_eq!(seen, plain);
    }
}

/// The road a user's file takes: scratch, capture, consent, new output. A file the
/// discard pass counts anything from makes no output at all.
#[test]
fn fil03_t17_a_counted_chunk_leaves_no_output_on_the_road_of_a_users_file() {
    let t = Temp::new();
    let (scratch, out_dir) = (t.sub("scratch"), t.sub("out"));
    let root = crate::ScratchRoot::open(&scratch).unwrap();
    let key = payload_key(&demo_file_key(), &NONCE);
    let file = with_chunks(&chunk(&key, 0, false, &demo_bytes(CHUNK)));
    let keys = ids(ID_A);
    watch::take();
    let snap = root.capture_stream(&mut &file[..], &mut keep).unwrap();
    let result = snap
        .unlock(&Unlock::Identities(&keys))
        .unwrap()
        .validate(&mut keep);
    assert_eq!(result.map(|_| ()), Err(Error::Decrypt));
    assert!(no_output(&watch::take()));
    assert!(names_in(&out_dir).is_empty());
}

#[test]
fn fil03_t17_derived_vectors_all_behave_and_each_family_is_present() {
    let vectors = load(&folder(DERIVED));
    assert_eq!(vectors.len(), 129, "the set from make_derived.py");
    let tally = run_all(&vectors);
    assert!(tally.failed.is_empty(), "{:#?}", tally.failed);
    for (family, least) in [
        ("Success", 20),
        ("NoMatch", 5),
        ("HmacFailure", 4),
        ("HeaderFailure", 40),
        ("PayloadFailure", 20),
        ("ArmorFailure", 15),
    ] {
        let got = tally.passed.get(family).copied().unwrap_or(0);
        assert!(got >= least, "{family}: {got} rows");
    }
    let wanted = [
        "armor_crlf",
        "armor_no_final_eol",
        "compressed_zlib",
        "payload_65536",
        "scrypt_basic",
    ];
    for name in wanted {
        assert!(vectors.iter().any(|v| v.name == name), "{name}");
    }
}

fn derived(name: &str) -> Vector {
    let path = folder(DERIVED).join(name);
    parse(name, &fs::read(path).unwrap()).unwrap()
}

#[test]
fn fil03_t17_a_valid_prefix_is_accounted_for_and_external_output_is_zero() {
    let vector = derived("no_final_flag_two_chunks");
    assert_eq!(vector.expect, Expect::PayloadFailure);
    assert_eq!(run(&vector), Outcome::Pass);

    // The first chunk passed internally, with the hash the row names; nothing
    // reached a caller's writer.
    let keys = ids(ID_A);
    let mut internal = 0usize;
    let cause = snapshot(&vector.body)
        .unlock_inner(&Unlock::Identities(&keys))
        .unwrap()
        .validate_inner(
            &mut |bytes| {
                internal += bytes.len();
                Ok(())
            },
            &mut keep,
        )
        .map(|_| ())
        .unwrap_err();
    assert_eq!(cause, Failure::Payload);
    assert_eq!(internal, CHUNK);
    assert_eq!(
        refused(&vector.body, &Unlock::Identities(&keys)),
        Failure::Payload
    );
}

#[test]
fn fil03_t17_a_native_pq_row_is_recorded_open_and_never_a_pass() {
    let vector = derived("native_pq_only");
    assert_eq!(
        vector.expect,
        Expect::Success,
        "as a published row would say"
    );
    let Outcome::Unsupported(why) = run(&vector) else {
        panic!("a native post-quantum row must be counted apart");
    };
    assert!(why.contains("post-quantum"));
    // Identities of those kinds are recorded the same way, with no attempt.
    let mut row = derived("x25519_basic");
    row.identities = vec!["AGE-SECRET-KEY-PQ-1DEMO".to_string()];
    assert!(matches!(run(&row), Outcome::Unsupported(_)));
    row.identities = vec!["AGE-PLUGIN-DEMO-1DEMO".to_string()];
    assert!(matches!(run(&row), Outcome::Unsupported(_)));
}

#[test]
fn fil03_t17_the_runner_catches_a_wrong_expectation() {
    // Positive controls: rows bent on purpose must come out as failures, so a
    // green run means the runner compared.
    let mut row = derived("x25519_basic");
    row.expect = Expect::HeaderFailure;
    assert!(matches!(run(&row), Outcome::Fail(_)));
    let mut row = derived("x25519_basic");
    row.payload = Some(vec![0; 32]);
    assert!(matches!(run(&row), Outcome::Fail(_)));
    let mut row = derived("x25519_basic");
    row.file_key = Some(vec![0; 16]);
    assert!(matches!(run(&row), Outcome::Fail(_)));
    let mut row = derived("mac_flip");
    row.expect = Expect::PayloadFailure;
    assert!(matches!(run(&row), Outcome::Fail(_)));
    let mut row = derived("no_final_flag_two_chunks");
    row.payload = Some(vec![0; 32]);
    assert!(matches!(run(&row), Outcome::Fail(_)));
    let bad = parse("demo", b"expect: nonsense\n\nbody");
    assert!(bad.is_err(), "an unknown stage stops the run");
    let bad = parse("demo", b"expect: success\nnew key: value\n\nbody");
    assert!(bad.is_err(), "an unknown key stops the run");
}
