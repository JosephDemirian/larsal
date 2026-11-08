//! `larsal show --qr` (FEA-10.22, FEA-10.23, E21-S3): one value as a QR code
//! in block characters. The matrix comes from larsal-qr, the encoder the Mac
//! app uses (FEA-10.8 to .10).
//!
//! Guarantees: an ordinary display goes only to a terminal that is large
//! enough; `--stdout` writes the same cells to anything and reads no terminal
//! size. The note goes to stderr before any cell, also with `-q`, and a note
//! that cannot be written stops the command. Every write and the final flush
//! are checked. The matrix (larsal-qr's, wiped on drop) and the rows live in
//! wiping buffers, both dropped before the command returns; nothing goes to
//! the clipboard, a log, an error text or a file.

use crate::term::{self, Fail, Res};
use larsal_crypto::secret::SecretBytes;
use std::io::{self, Write};
use std::os::fd::AsFd;

/// `MSG-QR-CLI-AUTH`.
pub const AUTH: &str =
    "larsal show: name one field with -a, or use -s to show the password as a QR code.";
/// `MSG-QR-CLI-OPTIONS`.
pub const OPTIONS: &str = "larsal show: --qr needs one field, --totp, or --wifi; it cannot be combined with --all or --show-attachments.";
/// `MSG-QR-CLI-PIPE`.
pub const PIPE: &str =
    "larsal show: QR output needs a terminal. Use --stdout to allow a pipe or file.";
/// `MSG-QR-CLI-SIZE`.
pub const SIZE: &str = "larsal show: the QR code does not fit this terminal. Make it larger.";
/// `MSG-QR-CLI-NOTE`.
pub const NOTE: &str = "Anyone who sees this code can read its contents. Terminal scrollback, logs and recordings may keep it after Larsal exits.";

/// ECMA-48 SGR: black foreground (30) on a white background (47), then the
/// reset (0). The only control text a terminal display holds.
const SET: &[u8] = b"\x1b[30;47m";
const RESET: &[u8] = b"\x1b[0m";

/// One of the card's `larsal show:` lines on stderr; the command exits 1.
pub fn refuse(text: &str) -> Fail {
    term::err(text);
    Fail
}

/// The text rows of a `size × size` matrix (1 is dark): two module rows per
/// text row, as space, U+2580, U+2584 or U+2588, each row ended by LF. An odd
/// last row has a white lower half. With `sgr` each row is wrapped in the fixed
/// black-on-white colours. One buffer of a fixed size, so no grown copy is left.
pub fn cells(size: usize, modules: &[u8], sgr: bool) -> SecretBytes {
    let frame = if sgr { SET.len() + RESET.len() } else { 0 };
    let mut out = Vec::with_capacity(size.div_ceil(2) * (size * 3 + frame + 1));
    let dark = |y: usize, x: usize| y < size && modules.get(y * size + x) == Some(&1);
    for y in (0..size).step_by(2) {
        if sgr {
            out.extend_from_slice(SET);
        }
        for x in 0..size {
            let cell = match (dark(y, x), dark(y + 1, x)) {
                (false, false) => " ",
                (true, false) => "\u{2580}",
                (false, true) => "\u{2584}",
                (true, true) => "\u{2588}",
            };
            out.extend_from_slice(cell.as_bytes());
        }
        if sgr {
            out.extend_from_slice(RESET);
        }
        out.push(b'\n');
    }
    SecretBytes::new(out)
}

/// The terminal on stdout holds `size` columns, and the `size / 2` rows (rounded
/// up) with the line the final LF moves to; an unknown size never fits.
fn fits(size: usize) -> bool {
    larsal_platform::macos::window_size(io::stdout().as_fd()).is_some_and(|(cols, rows)| {
        usize::from(cols) >= size && usize::from(rows) > size.div_ceil(2)
    })
}

/// `MSG-QR-CLI-NOTE` on stderr, checked to the flush.
fn note() -> io::Result<()> {
    let mut e = io::stderr().lock();
    e.write_all(NOTE.as_bytes())?;
    e.write_all(b"\n")?;
    e.flush()
}

/// Prints `matrix` (FEA-10.23). Ordinary: a terminal of known, large enough
/// size (else `MSG-QR-CLI-SIZE`, nothing printed) and the fixed colours.
/// `raw` (`--stdout`): plain cells and LF, no size asked. Then the note, and
/// only after it the cells.
pub fn print(matrix: larsal_qr::Matrix, raw: bool) -> Res {
    let size = matrix.size();
    if !raw && !fits(size) {
        return Err(refuse(SIZE));
    }
    let rows = cells(size, matrix.modules(), !raw);
    drop(matrix);
    note().map_err(|_| Fail)?;
    term::out_bytes(rows.expose())
        .map_err(|e| term::fail(format!("cannot write to standard output: {e}.")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_crypto::kdf::Host;
    use larsal_crypto::secret::SecretString;
    use larsal_format::keys::Credentials;
    use larsal_format::limits::Limits;
    use larsal_model::{Entry, Field, Group, Kdf, Time, Uuid, Vault};
    use larsal_platform::memory::{copies_in_memory, marker_survives_free};
    use std::process::{Command, Stdio};

    const MASK: u8 = 0xA5;
    /// The child's full name: it runs only when named exactly. No variable of
    /// the environment is read (INT-10.16, int10_16_a).
    const CHILD: &str = "qr::tests::qr_t29_child";

    /// A span held masked, so the search never finds its own needle.
    struct Span(Vec<u8>);

    impl Span {
        fn copies(&self) -> usize {
            copies_in_memory(&self.0, MASK)
        }
    }

    /// The folder a parent and its child share: TMPDIR, named by the parent.
    fn shared(parent: u32) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("larsal-cli-qr-t29-{parent}"))
    }

    /// QR-T29 for the `larsal` tool (FEA-10.10, LD-133, LD-361): what one
    /// `larsal show --qr --stdout -s` leaves in memory once it returns,
    /// buffer by buffer, found by searching all writable memory (heap, freed
    /// blocks and the stack). The command runs in a child of this program,
    /// alone, as the search needs, under this program's allocator: the tool's
    /// own (`main.rs`). This parent makes the demo vault and the five spans
    /// and hands them over in TMPDIR, so the child's memory holds no value,
    /// bits, codewords, matrix or rows but what the command makes. A 1,272-byte
    /// value fills version 40 exactly: the value, the encoder's input bits, the
    /// interleaved codewords, the matrix and the printed rows.
    #[test]
    fn qr_t29_cli_release_leaves_no_value_bits_codewords_matrix_or_rows() {
        // 1,272 demo characters no other run holds.
        let mut state = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % u128::from(u64::MAX),
        )
        .unwrap();
        let value: Vec<u8> = (0..1_272)
            .map(|_| {
                state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                b'g' + u8::try_from((state >> 40) % 20).unwrap()
            })
            .collect();

        // The vault: one entry, its protected Password the value; a fast KDF.
        let dir = shared(std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = Time::from_unix(1_700_000_000).unwrap();
        let mut vault = Vault::new(Group::new(Uuid([1; 16]), "Root".to_owned(), now), now);
        vault.encryption.kdf = Kdf::AesKdf { rounds: 1 };
        let mut e = Entry::new(Uuid([2; 16]), now);
        let field = |value: String, protected| Field {
            value: SecretString::new(value),
            protected,
        };
        e.set_field("Title".into(), field("Wipe".into(), false));
        e.set_field(
            "Password".into(),
            field(String::from_utf8(value.clone()).unwrap(), true),
        );
        vault.root.entries.push(e);
        let pw = SecretString::new("demo-pass-1".into());
        let creds = Credentials {
            password: Some(&pw),
            ..Credentials::default()
        };
        let mut host = Host {
            physical_memory: 16 << 30,
            logical_processors: 8,
            argon2_record: None,
            aes_record: None,
        };
        let saved = larsal_format::save(&vault, &creds, None, &mut host, &Limits::DEFAULT, None);
        let Ok(larsal_format::Saved::File(file)) = saved else {
            panic!("1 AES-KDF round never asks");
        };
        std::fs::write(dir.join("wipe.larsalvault"), &file.bytes).unwrap();

        // The spans, 64 bytes each. The value: its middle. The bits: ECI 26,
        // byte mode and the count of 1,272, then the value, 1,276 data
        // codewords with no terminator or pad; their head. The codewords,
        // interleaved: version 40 at level H has 20 blocks of 15, then 61
        // blocks of 16; their middle. The matrix: modules of the middle row
        // from a dark one, inside the quiet zone. The printed rows: from a
        // block character in the middle.
        let mut bits = vec![0x71, 0xA4, 0x04, 0xF8];
        bits.extend_from_slice(&value);
        let start = |block: usize| {
            if block < 20 {
                block * 15
            } else {
                300 + (block - 20) * 16
            }
        };
        let mut interleaved = Vec::with_capacity(1_276);
        for column in 0..16 {
            for block in 0..81 {
                if column < 15 || block >= 20 {
                    interleaved.push(bits[start(block) + column]);
                }
            }
        }
        assert_eq!(interleaved.len(), 1_276);
        let symbol = larsal_qr::encode(&value).unwrap();
        let n = symbol.size();
        assert_eq!(n, 185);
        let row = &symbol.modules()[92 * n..93 * n];
        let from = (4..n - 4 - 64).find(|x| row[*x] == 1).unwrap();
        let printed = cells(n, symbol.modules(), false);
        let middle = printed.len() / 2;
        let at = middle
            + printed.expose()[middle..]
                .iter()
                .position(|b| *b == 0xE2)
                .unwrap();
        let spans: Vec<u8> = [
            &value[600..664],
            &bits[..64],
            &interleaved[600..664],
            &row[from..from + 64],
            &printed.expose()[at..at + 64],
        ]
        .concat()
        .iter()
        .map(|b| b ^ MASK)
        .collect();
        std::fs::write(dir.join("spans"), &spans).unwrap();

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_remove("RUST_TEST_THREADS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"demo-pass-1\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let (text, err) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(out.status.success(), "{err}");
        assert!(err.contains("QR-T29 after: [0, 0, 0, 0, 0]"), "{err}");
        assert!(text.contains("1 passed"), "{text}");
        // The code itself: 93 rows of 185 cells, the quiet zone included,
        // the rows this parent printed for its span among them.
        let cell = |c: char| matches!(c, ' ' | '\u{2580}' | '\u{2584}' | '\u{2588}');
        let rows = text
            .lines()
            .filter(|l| l.chars().rev().take(185).filter(|c| cell(*c)).count() == 185)
            .count();
        assert_eq!(rows, 93, "{text}");
        assert!(
            text.contains(
                std::str::from_utf8(printed.expose())
                    .unwrap()
                    .lines()
                    .nth(46)
                    .unwrap()
            )
        );
    }

    /// The child: the controls, the spans before, the command, the spans after.
    #[test]
    #[ignore = "a child of qr_t29_cli_release_leaves_no_value_bits_codewords_matrix_or_rows"]
    fn qr_t29_child() {
        if !std::env::args().any(|a| a == CHILD) {
            return;
        }
        // The control: a plain free keeps a block's bytes on this Mac, and
        // this program's allocator does not.
        assert!(marker_survives_free(false));
        assert!(!marker_survives_free(true));
        let dir = shared(std::os::unix::process::parent_id());
        let masked = std::fs::read(dir.join("spans")).unwrap();
        assert_eq!(masked.len(), 5 * 64);
        let spans: Vec<Span> = masked.chunks(64).map(|c| Span(c.to_vec())).collect();
        // The search sees a live span: each one, made plain here for a moment.
        for span in &spans {
            let mut plain: Vec<u8> = span.0.iter().map(|b| b ^ MASK).collect();
            assert!(span.copies() >= 1, "the control: a live span");
            plain.fill(0);
            std::hint::black_box(&plain);
        }
        let before: Vec<usize> = spans.iter().map(Span::copies).collect();
        assert_eq!(before, [0; 5], "value, bits, codewords, matrix, rows");

        let words: Vec<String> = ["show", "--qr", "--stdout", "-s"]
            .into_iter()
            .map(str::to_owned)
            .chain([
                dir.join("wipe.larsalvault").to_string_lossy().into_owned(),
                "Wipe".to_owned(),
            ])
            .collect();
        assert_eq!(crate::start(&words), 0);

        let after: Vec<usize> = spans.iter().map(Span::copies).collect();
        eprintln!("QR-T29 after: {after:?}");
        assert_eq!(after, [0; 5], "value, bits, codewords, matrix, rows");
    }

    /// FEA-10.23: the four cells, the white half of an odd last row, the
    /// fixed colours only on a terminal.
    #[test]
    fn fea_10_23_two_modules_a_cell_and_the_odd_row() {
        // 3 × 3, rows: 1 0 1 / 1 1 0 / 0 1 1.
        let m = [1, 0, 1, 1, 1, 0, 0, 1, 1];
        let plain = cells(3, &m, false);
        assert_eq!(
            std::str::from_utf8(plain.expose()).unwrap(),
            "\u{2588}\u{2584}\u{2580}\n \u{2580}\u{2580}\n"
        );
        let shown = cells(3, &m, true);
        assert_eq!(
            std::str::from_utf8(shown.expose()).unwrap(),
            "\x1b[30;47m\u{2588}\u{2584}\u{2580}\x1b[0m\n\x1b[30;47m \u{2580}\u{2580}\x1b[0m\n"
        );
        assert_eq!(cells(2, &[0, 0, 0, 0], false).expose(), b"  \n");
    }
}
