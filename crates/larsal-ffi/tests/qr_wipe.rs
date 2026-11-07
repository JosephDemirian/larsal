//! QR-T29, native (FEA-10.10, LD-133): what one code's release leaves in this
//! process's memory, per buffer, measured by searching all of its writable
//! memory (heap, freed blocks and this thread's stack) with the vault still
//! unlocked. Alone in its program: the search reads all memory, so nothing else
//! may run. Spans come from one version 40 Wi-Fi join, large enough that a plain
//! free keeps their bytes. A join text is never stored, so each span here exists
//! only where the QR path made it.
//!
//! Measured, each one shown by a run with the plain allocator, which finds it
//! where this program's finds none (mutant W2): the join text, the working bits,
//! the matrix, the RGBA picture and the PNG, in Rust. The negative control is that
//! allocator: the search alone then goes red (mutant W4).
//! Searched, but it shows nothing: the interleaved codewords. The plain allocator's
//! run finds none either, since `qrcode`'s freed block is reused at once, so their
//! wiping rests on the allocator, not on this search.
//! Not measured: Swift's copy of the matrix (released, not wiped, as FEA-10.10
//! allows), UniFFI's buffer on its way to Swift, spans too short to tell a wipe
//! from macOS's own zeroing of small blocks, any stack but this thread's, and
//! wasm, which has its own story.

use larsal_ffi::edit::EditText;
use larsal_ffi::qr::QrExport;
use larsal_ffi::session::{Session, UnlockResult};
use larsal_platform::memory::{copies_in_memory, marker_survives_free};
use std::path::PathBuf;

const MASK: u8 = 0xA5;

/// A span held masked, so the search never finds its own needle.
struct Span(Vec<u8>);

impl Span {
    fn of(plain: &[u8]) -> Self {
        Self(plain.iter().map(|b| b ^ MASK).collect())
    }

    fn copies(&self) -> usize {
        copies_in_memory(&self.0, MASK)
    }
}

/// This test's own plain copy, gone before the search, so with any allocator
/// only what the QR path made can be found.
fn scrub(mut plain: Vec<u8>) {
    plain.fill(0);
    std::hint::black_box(&plain);
}

/// `n` demo characters no other run or field holds, made at run time.
fn unique(n: usize) -> String {
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            char::from(b'g' + ((state >> 40) % 20) as u8)
        })
        .collect()
}

#[test]
fn qr_t29_native_release_leaves_no_input_bits_matrix_rgba_or_png() {
    // The control: a plain free keeps a block's bytes on this Mac, and this
    // program's allocator does not.
    assert!(marker_survives_free(false));
    assert!(!marker_survives_free(true));

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("qr-wipe");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Wipe.larsalvault");
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/option-a-personal.larsalvault"),
        &path,
    )
    .unwrap();
    let s = Session::new();
    let v = s.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap(),
        UnlockResult::Unlocked
    );

    // 1,270 bytes on the wire: version 40, count of 16 bits, and two bytes left
    // for the terminator and one pad, which only the working bits hold.
    let head = "WIFI:T:WPA;S:Wipe;P:";
    let tail = ";H:false;;";
    let password = unique(1_270 - head.len() - tail.len());
    s.begin_new(v, None).unwrap();
    s.set_text(v, EditText::Title, "Wipe".into()).unwrap();
    s.set_text(v, EditText::UserName, "Wipe".into()).unwrap();
    s.set_password(v, password.clone()).unwrap();
    let made = s.add_field(v).unwrap();
    s.rename_field(v, made, "Security".into()).unwrap();
    s.set_field(v, "Security".into(), "WPA".into()).unwrap();
    let id = s.commit_edit(v).unwrap();

    // Made at its full size: a buffer that grew would leave a copy behind.
    let mut wire = String::with_capacity(1_270);
    wire.push_str(head);
    wire.push_str(&password);
    wire.push_str(tail);
    assert_eq!(wire.len(), 1_270);
    // The input: the end of the join text, which only a join holds.
    let input = Span::of(&wire.as_bytes()[wire.len() - 64..]);
    // The working bits: ECI 26, byte mode and the count, the text, the
    // terminator and a pad. Their end: a freed block loses its first bytes to
    // the allocator's own list.
    let mut bits = Vec::with_capacity(1_276);
    bits.extend_from_slice(&[0x71, 0xA4, 0x04, 0xF6]);
    bits.extend_from_slice(wire.as_bytes());
    bits.extend_from_slice(&[0x00, 0xEC]);
    let working = Span::of(&bits[bits.len() - 64..]);
    // The codewords, interleaved: version 40 at level H has 20 blocks of 15
    // data codewords, then 61 blocks of 16 (the standard's table).
    let start = |block: usize| {
        if block < 20 {
            block * 15
        } else {
            300 + (block - 20) * 16
        }
    };
    let mut interleaved = Vec::with_capacity(15 * 81);
    for column in 0..15 {
        for block in 0..81 {
            interleaved.push(bits[start(block) + column]);
        }
    }
    let codewords = Span::of(&interleaved[600..664]);
    scrub(wire.into_bytes());
    scrub(bits);
    scrub(password.into_bytes());
    scrub(interleaved);

    assert_eq!(input.copies(), 0, "no join text before the request");
    assert_eq!(working.copies(), 0, "no bits before the request");
    assert_eq!(codewords.copies(), 0, "no codewords before the request");

    let shown = s.qr_show_wifi(v, id).unwrap();
    let ticket = shown.ticket;
    let side = shown.symbol.size as usize;
    assert_eq!(side, 177 + 8);

    // Rust's matrix without its quiet zone, and one row of its picture.
    let row = side / 2;
    let cells = &shown.symbol.modules[row * side + 4..row * side + side - 4];
    let matrix = Span::of(cells);
    let mut pixels = Vec::with_capacity(24 * 32);
    for cell in cells.iter().take(24) {
        for sample in 0..32 {
            pixels.push(if *cell == 1 && sample % 4 != 3 {
                0
            } else {
                0xFF
            });
        }
    }
    let picture = Span::of(&pixels);
    scrub(pixels);

    let gone = |step: &str, spans: &[(&str, &Span)]| {
        for (name, span) in spans {
            assert_eq!(span.copies(), 0, "{name}, {step}");
        }
    };
    let working_spans = [
        ("input", &input),
        ("working bits", &working),
        ("codewords", &codewords),
    ];
    // The live matrix is found: the search sees what is there.
    assert!(matrix.copies() >= 1, "the control: a live matrix");
    gone("after the request", &working_spans);
    for _ in 0..3 {
        assert!(s.qr_is_current(v, ticket));
    }
    gone("after each check", &working_spans);

    // Share: the PNG lives only in what the caller holds.
    let consent = s.qr_consent(v, ticket, QrExport::Share).unwrap();
    let png = s.qr_share_png(v, ticket, consent).unwrap();
    let image = Span::of(&png[41..41 + 64]);
    assert!(image.copies() >= 1, "the control: a live PNG");
    gone("after the PNG", &working_spans);
    gone("after the PNG", &[("picture", &picture)]);
    drop(png);
    gone("the PNG dropped", &[("PNG", &image)]);

    // Save: the same, written to a file only.
    let consent = s.qr_consent(v, ticket, QrExport::Save).unwrap();
    let file = dir.join("Wipe.png");
    let _ = std::fs::remove_file(&file);
    s.qr_save_png(v, ticket, consent, file.to_string_lossy().into_owned())
        .unwrap();
    gone("after Save", &working_spans);
    gone("after Save", &[("picture", &picture), ("PNG", &image)]);
    std::fs::remove_file(&file).unwrap();

    // The release, before any lock: nothing is left to the whole-session wipe.
    drop(shown);
    s.qr_release(v, ticket);
    gone(
        "released",
        &[
            ("input", &input),
            ("working bits", &working),
            ("codewords", &codewords),
            ("matrix", &matrix),
            ("picture", &picture),
            ("PNG", &image),
        ],
    );
    s.lock(v).unwrap();
}
