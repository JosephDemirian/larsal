//! FIL-03-T01, T02, T12: each limit, one past it, and the work factor's rules.

use super::*;
use crate::decrypt::kdf_probe;
use crate::limits::{
    CHUNK, MAX_ARMOR_SPACE, MAX_FILE, MAX_HEADER, MAX_IDENTITIES, MAX_IDENTITY_LIST,
    MAX_PASSPHRASE, MAX_RECIPIENTS, MAX_STANZAS, READ_MAX_LOG_N, WRITE_LOG_N,
};
use crate::payload::{Counter, count};
use crate::{ScratchRoot, encrypt_stream};
use larsal_crypto::bech32;

fn ignored(n: usize) -> Vec<u8> {
    raw_stanza("demo", b"").repeat(n)
}

#[test]
fn fil03_t01_stanza_count_includes_ignored_ones() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    assert_eq!(
        open(&craft(&ignored(MAX_STANZAS - 1), PLAIN), &unlock).unwrap(),
        PLAIN
    );
    assert_eq!(
        refused(&craft(&ignored(MAX_STANZAS), PLAIN), &unlock),
        Failure::Header
    );
}

/// A file whose header is exactly `size` bytes, with one long ignored argument.
fn with_header_size(size: usize) -> Vec<u8> {
    let plain_head = craft(&raw_stanza("demo a", b""), PLAIN);
    let base = header_end(&plain_head);
    let pad = "a".repeat(size - base + 1);
    let file = craft(&raw_stanza(&format!("demo {pad}"), b""), PLAIN);
    assert_eq!(header_end(&file), size);
    file
}

#[test]
fn fil03_t01_header_limit_counts_every_byte() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    assert_eq!(open(&with_header_size(MAX_HEADER), &unlock).unwrap(), PLAIN);
    assert_eq!(
        refused(&with_header_size(MAX_HEADER + 1), &unlock),
        Failure::Header
    );
    // A hostile file with no newline at all stops at the same byte.
    let mut endless = b"age-encryption.org/v1\n-> demo ".to_vec();
    endless.resize(MAX_HEADER * 2, b'a');
    assert_eq!(refused(&endless, &unlock), Failure::Header);
    // And a line over the base64 width in a body.
    let long_body = format!("-> demo\n{}\n\n", "A".repeat(68));
    assert_eq!(
        refused(&craft(long_body.as_bytes(), PLAIN), &unlock),
        Failure::Header
    );
}

#[test]
fn fil03_t01_recipient_limit() {
    let many: Vec<Recipient> = (0..=MAX_RECIPIENTS)
        .map(|i| {
            let mut key = SecretBytes::zeroed(32);
            key.expose_mut()[1..9].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            Recipient(Secret::from_bytes(key).unwrap().public())
        })
        .collect();
    let file = seal_to(PLAIN, &many[..MAX_RECIPIENTS]);
    assert!(!file.is_empty());
    let mut out = Vec::new();
    let result = encrypt_stream(&mut &*PLAIN, &mut out, &Lock::Recipients(&many), &mut keep);
    assert_eq!(result, Err(Error::Recipient));
    assert!(out.is_empty());
}

#[test]
fn fil03_t01_passphrase_limit_is_checked_before_any_key_derivation() {
    let file = seal_pass(PLAIN, PASS);
    let at = secret(&"p".repeat(MAX_PASSPHRASE));
    let over = secret(&"p".repeat(MAX_PASSPHRASE + 1));
    kdf_probe::take();
    assert_eq!(
        snapshot(&file)
            .unlock(&Unlock::Passphrase(&over))
            .map(|_| ()),
        Err(Error::Passphrase)
    );
    assert_eq!(kdf_probe::take(), 0);
    let mut out = Vec::new();
    assert_eq!(
        encrypt_stream(&mut &*PLAIN, &mut out, &Lock::Passphrase(&over), &mut keep),
        Err(Error::Passphrase)
    );
    assert_eq!(kdf_probe::take(), 0);
    assert!(out.is_empty());
    // The limit itself is a passphrase like any other.
    let long = seal_pass(PLAIN, at.expose());
    assert_eq!(open(&long, &Unlock::Passphrase(&at)).unwrap(), PLAIN);
}

fn key_line(i: usize) -> String {
    let mut key = SecretBytes::zeroed(32);
    key.expose_mut()[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    format!(
        "{}\n",
        bech32::encode_upper_secret("AGE-SECRET-KEY-", &key)
            .unwrap()
            .expose()
    )
}

#[test]
fn fil03_t01_identity_list_limits() {
    let lines = |n: usize| (0..n).map(key_line).collect::<String>();
    assert_eq!(
        Identities::from_list(lines(MAX_IDENTITIES).as_bytes())
            .unwrap()
            .keys
            .len(),
        MAX_IDENTITIES
    );
    assert_eq!(
        Identities::from_list(lines(MAX_IDENTITIES + 1).as_bytes()).map(|_| ()),
        Err(Error::Decrypt)
    );
    let one = key_line(0);
    let fill = |n: usize| format!("{one}{}", "#".repeat(n - one.len()));
    assert!(Identities::from_list(fill(MAX_IDENTITY_LIST).as_bytes()).is_ok());
    assert_eq!(
        Identities::from_list(fill(MAX_IDENTITY_LIST + 1).as_bytes()).map(|_| ()),
        Err(Error::Decrypt)
    );
}

#[test]
fn fil03_t01_armor_space_limits() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let body = armor(&craft(b"", PLAIN), "\n");
    let with = |before: usize, after: usize| {
        let mut out = vec![b' '; before];
        out.extend_from_slice(&body);
        out.extend(vec![b'\n'; after]);
        out
    };
    assert_eq!(
        open(&with(MAX_ARMOR_SPACE, MAX_ARMOR_SPACE), &unlock).unwrap(),
        PLAIN
    );
    assert_eq!(
        refused(&with(MAX_ARMOR_SPACE + 1, 0), &unlock),
        Failure::Armor
    );
    assert_eq!(
        refused(&with(0, MAX_ARMOR_SPACE + 1), &unlock),
        Failure::Armor
    );
}

#[test]
fn fil03_t02_legal_costs_derive_once_and_weak_ones_need_consent() {
    let phrase = secret(PASS);
    let unlock = Unlock::Passphrase(&phrase);
    for log_n in [1, 17, WRITE_LOG_N, READ_MAX_LOG_N] {
        let file = seal_cost(PLAIN, PASS, log_n);
        kdf_probe::take();
        let unwrapped = snapshot(&file).unlock(&unlock).unwrap();
        assert_eq!(kdf_probe::take(), 1, "cost {log_n}");
        let result = unwrapped.validate(&mut keep).unwrap();
        assert_eq!(kdf_probe::take(), 0, "the file key is not derived again");
        let mut out = Vec::new();
        match (log_n < WRITE_LOG_N, result) {
            (true, Validation::Weak(w)) => {
                w.accept().write_to(&mut out, &mut keep).unwrap();
            }
            (false, Validation::Ready(v)) => {
                v.write_to(&mut out, &mut keep).unwrap();
            }
            _ => panic!("cost {log_n} came back in the wrong state"),
        }
        assert_eq!(out, PLAIN);
    }
}

#[test]
fn fil03_t02_over_ceiling_or_malformed_means_zero_key_derivations() {
    let phrase = secret(PASS);
    let unlock = Unlock::Passphrase(&phrase);
    let good = seal_pass(PLAIN, PASS);
    let line_end = good[22..].iter().position(|b| *b == b'\n').unwrap() + 22;
    let cost_at = good[..line_end].iter().rposition(|b| *b == b' ').unwrap() + 1;
    for cost in [
        "21",
        "22",
        "63",
        "64",
        "255",
        "256",
        "0",
        "00",
        "04",
        "+4",
        "-4",
        "4 ",
        " 4",
        "0x4",
        "4x",
        "١",
        "340282366920938463463374607431768211456",
        "99999999999999999999999999999999999999999999",
    ] {
        let mut file = good[..cost_at].to_vec();
        file.extend_from_slice(cost.as_bytes());
        file.extend_from_slice(&good[line_end..]);
        kdf_probe::take();
        assert_eq!(refused(&file, &unlock), Failure::Header, "cost {cost:?}");
        assert_eq!(
            kdf_probe::take(),
            0,
            "cost {cost:?} reached a key derivation"
        );
    }
}

#[test]
fn fil03_t02_weak_consent_comes_only_after_a_whole_check() {
    let phrase = secret(PASS);
    let unlock = Unlock::Passphrase(&phrase);
    // A low cost and a bad last byte: a failure, never a consent question.
    let mut bad = seal_pass(&demo_bytes(CHUNK + 5), PASS);
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(refused(&bad, &unlock), Failure::Payload);
    let other = secret("other");
    let file = seal_pass(PLAIN, PASS);
    assert_eq!(
        refused(&file, &Unlock::Passphrase(&other)),
        Failure::NoMatch
    );
    assert!(matches!(
        snapshot(&file).unlock(&unlock).unwrap().validate(&mut keep),
        Ok(Validation::Weak(_))
    ));
}

#[test]
fn fil03_t12_counters_and_offsets_never_wrap() {
    let mut near = Counter(u64::MAX - 1);
    near.advance().unwrap();
    assert_eq!(near, Counter(u64::MAX));
    assert_eq!(near.advance(), Err(Failure::Payload), "the wrap is refused");
    assert_eq!(near, Counter(u64::MAX), "and leaves the counter alone");
    assert_eq!(&Counter(0x0102).nonce(true)[9..], [1, 2, 1]);
    assert_eq!(&Counter(0x0102).nonce(false)[9..], [1, 2, 0]);
    assert_eq!(Counter(u64::MAX).nonce(false)[..3], [0, 0, 0]);

    assert_eq!(count(MAX_FILE - 10, 10), Ok(MAX_FILE));
    assert_eq!(count(MAX_FILE - 10, 11), Err(Failure::Other(Error::Io)));
    assert_eq!(count(MAX_FILE, 1), Err(Failure::Other(Error::Io)));
    assert_eq!(count(u64::MAX, CHUNK), Err(Failure::Other(Error::Io)));
}

/// A stream that says nothing of its length and hands out little at a time.
struct Dribble<'a>(&'a [u8]);

impl std::io::Read for Dribble<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.len().min(buf.len()).min(1021);
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn fil03_t12_unknown_length_input_is_counted_as_it_comes() {
    let plain = demo_bytes(CHUNK * 2 + 17);
    let phrase = secret(PASS);
    let mut sealed = Vec::new();
    let n = crate::encrypt::encrypt_stream_with(
        &mut random::bytes,
        LOW,
        &mut Dribble(&plain),
        &mut sealed,
        &Lock::Passphrase(&phrase),
        &mut keep,
    )
    .unwrap();
    assert_eq!(n, plain.len() as u64);

    let t = Temp::new();
    let root = ScratchRoot::open(&t.sub("scratch")).unwrap();
    let snapshot = root
        .capture_stream(&mut Dribble(&sealed), &mut keep)
        .unwrap();
    let mut out = Vec::new();
    let unlock = Unlock::Passphrase(&phrase);
    let Validation::Weak(w) = snapshot
        .unlock(&unlock)
        .unwrap()
        .validate(&mut keep)
        .unwrap()
    else {
        panic!("a low cost file is a weak one");
    };
    let written = w.accept().write_to(&mut out, &mut keep).unwrap();
    assert_eq!(written, plain.len() as u64);
    assert_eq!(out, plain);
}

/// FIL-03.1, FIL-03.2, FIL-01.8, FIL-01.4, as the cards write them. A test above that
/// reads a limit from its constant follows the constant wherever it goes; this one
/// does not.
#[test]
fn fil03_t01_the_limits_are_the_cards_numbers() {
    assert_eq!(MAX_HEADER, 2_097_152);
    assert_eq!(MAX_STANZAS, 1024);
    assert_eq!(MAX_RECIPIENTS, 1024);
    assert_eq!(MAX_IDENTITY_LIST, 65_536);
    assert_eq!(MAX_IDENTITIES, 64);
    assert_eq!(MAX_PASSPHRASE, 1_048_576);
    assert_eq!(MAX_ARMOR_SPACE, 16_384);
    assert_eq!(WRITE_LOG_N, 18);
    assert_eq!(READ_MAX_LOG_N, 20);
    assert_eq!(CHUNK, 65_536);
    assert_eq!(crate::limits::TAG, 16);
    assert_eq!(MAX_FILE, 9_223_372_036_854_775_807);
    // The crate's own bound on a key file: the longest legal one is under it.
    assert_eq!(crate::limits::MAX_IDENTITY_FILE, 4_194_304);
}

/// A stream that counts what was asked of it, and never ends.
struct Endless(usize);

impl std::io::Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(b'#');
        self.0 += buf.len();
        Ok(buf.len())
    }
}

#[test]
fn fil03_t01_a_key_file_is_read_only_to_its_bound() {
    let mut input = Endless(0);
    assert_eq!(
        Identities::read_key_file(&mut input, None).map(|_| ()),
        Err(Error::Decrypt)
    );
    assert_eq!(input.0, 4_194_305, "the bound and one byte, then it stops");
}

/// A file the reader sees through a counter, so a test can see how far it read.
struct Counted<'a>(Cursor<&'a [u8]>, &'a std::cell::Cell<usize>);

impl std::io::Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(buf)?;
        self.1.set(self.1.get() + n);
        Ok(n)
    }
}

impl std::io::Seek for Counted<'_> {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(from)
    }
}

#[test]
fn fil03_t01_a_hostile_armor_line_stops_at_the_line_bound() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    let mut file = b"-----BEGIN AGE ENCRYPTED FILE-----\n".to_vec();
    file.resize(8 << 20, b'A');
    let read = std::cell::Cell::new(0);
    let snapshot = Snapshot {
        src: Counted(Cursor::new(&file), &read),
    };
    assert_eq!(
        snapshot.unlock_inner(&unlock).map(|_| ()).unwrap_err(),
        Failure::Armor
    );
    assert!(
        read.get() <= 2 * 65_536,
        "it read {} bytes of one line",
        read.get()
    );
    // A whole legal line in CRLF, 64 columns and the line end, still opens.
    let plain = demo_bytes(4096);
    assert_eq!(
        open(&armor(&craft(b"", &plain), "\r\n"), &unlock).unwrap(),
        plain
    );
}

/// An armored file whose last data line has `pad` `=` of its own.
fn armored_with_padding(pad: usize) -> Vec<u8> {
    (0..12)
        .map(|extra| armor(&craft(b"", &demo_bytes(100 + extra)), "\n"))
        .find(|file| {
            let text = String::from_utf8_lossy(file).into_owned();
            let last = text.lines().rev().nth(1).unwrap().to_string();
            last.len() < 64 && last.bytes().rev().take_while(|b| *b == b'=').count() == pad
        })
        .unwrap()
}

/// The same file, with `edit` run on its last data line.
fn with_last_line(file: &[u8], edit: impl Fn(&str) -> String) -> Vec<u8> {
    let text = String::from_utf8(file.to_vec()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let at = lines.len() - 2;
    lines[at] = edit(&lines[at]);
    format!("{}\n", lines.join("\n")).into_bytes()
}

#[test]
fn fil03_t01_armor_padding_is_exactly_what_the_length_needs() {
    let keys = ids(ID_A);
    let unlock = Unlock::Identities(&keys);
    for (pad, wrong) in [(0, "===="), (1, "===="), (2, "====")] {
        let good = armored_with_padding(pad);
        assert!(open(&good, &unlock).is_ok(), "{pad} is the right amount");
        let more = with_last_line(&good, |l| format!("{l}{wrong}"));
        assert_eq!(refused(&more, &unlock), Failure::Armor, "{pad} and {wrong}");
    }
    for pad in [1, 2] {
        let good = armored_with_padding(pad);
        let cut = with_last_line(&good, |l| l.trim_end_matches('=').to_string());
        assert_eq!(refused(&cut, &unlock), Failure::Armor, "without its {pad}");
        let extra = with_last_line(&good, |l| format!("{l}="));
        assert_eq!(refused(&extra, &unlock), Failure::Armor, "{pad} and one");
    }
    // Vertical tab is not outer white space, on either side.
    let body = armored_with_padding(0);
    let mut before = vec![0x0B];
    before.extend_from_slice(&body);
    assert_eq!(refused(&before, &unlock), Failure::Header);
    let mut after = body.clone();
    after.push(0x0B);
    assert_eq!(refused(&after, &unlock), Failure::Armor);
}
