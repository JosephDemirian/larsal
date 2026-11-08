//! E21-S3: `larsal show --qr` (FEA-10.22, FEA-10.23; QR-T26 to QR-T28 and the
//! command line part of QR-T31). Every printed code is read back by this
//! test's own reader (`read.rs`, from ISO/IEC 18004), proven first on the
//! matrices of E21-S2's encoder. Terminal cases run `larsal` on a
//! pseudo-terminal under `script(1)`, as INT-10's "pty" cases do, with the
//! size set by `stty`; never a visible window.

mod read;

use super::*;
use read::Segment;

const NOTE: &str = "Anyone who sees this code can read its contents. Terminal scrollback, logs and recordings may keep it after Larsal exits.";
const AUTH: &str =
    "larsal show: name one field with -a, or use -s to show the password as a QR code.\n";
const OPTIONS: &str = "larsal show: --qr needs one field, --totp, or --wifi; it cannot be combined with --all or --show-attachments.\n";
const PIPE: &str =
    "larsal show: QR output needs a terminal. Use --stdout to allow a pipe or file.\n";
const SIZE: &str = "larsal show: the QR code does not fit this terminal. Make it larger.";
const TOO_LARGE: &str =
    "larsal: This value is too large for one QR code. Nothing was shown, saved or shared.\n";
const EMPTY: &str = "larsal: This field is empty.\n";

const RICH: &str = "rich-v3.larsalvault";
const FULL: &str = "Full demo entry";
const PW: &str = "demo-pass-4\n";
const Q: &str = "q.larsalvault";
const Q_PW: &str = "demo-pass-1\n";

/// `larsal show ARGS VAULT ENTRY`, the password on stdin, all on pipes.
fn show(d: &Dir, args: &[&str], vault: &str, entry: &str, pw: &str) -> Out {
    d.run(&[&["show"][..], args, &[vault, entry]].concat(), pw)
}

/// `q.larsalvault` (demo-pass-1, fast KDF): one entry `QR demo` with `fields`
/// (name, value, protected).
fn q_vault(d: &Dir, fields: &[(&str, &str, bool)]) {
    let mut v = small_vault("QR demo");
    let e = find_mut(&mut v.root, "QR demo").unwrap();
    for (name, value, protected) in fields {
        e.set_field((*name).into(), field(value, *protected));
    }
    store(&d.path(Q), &v, "demo-pass-1");
}

/// The value `--stdout` printed on a pipe.
fn raw(o: &Out) -> Vec<u8> {
    assert_eq!(o.code, Some(0), "{}", o.err);
    assert!(o.err.ends_with(&format!("{NOTE}\n")), "{}", o.err);
    read::value(&o.out, false)
}

/// The refusal `line` on stderr, nothing on stdout, exit 1. Stderr holds the
/// line and at most the unlock's prompt before it, nothing else: no byte of a
/// value reaches either stream.
fn refused(o: &Out, line: &str) {
    assert_eq!(o.code, Some(1), "{}", o.err);
    assert!(o.out.is_empty(), "{:?}", o.out);
    let before = o
        .err
        .strip_suffix(line)
        .unwrap_or_else(|| panic!("{:?}", o.err));
    let prompts = [RICH, Q, "pin.larsalvault", "w.larsalvault"]
        .map(|vault| format!("Vault password for {vault}: "));
    assert!(
        before.is_empty() || prompts.iter().any(|p| p == before),
        "{:?}",
        o.err
    );
}

/// Refused before the unlock: the line alone, no prompt.
fn refused_first(o: &Out, line: &str) {
    refused(o, line);
    assert_eq!(o.err, line);
}

/// `script` on a pseudo-terminal of `rows` × `cols` (0 × 0: no known size):
/// the password typed at the prompt with echo off. Its text, CR LF made LF.
fn on_terminal(d: &Dir, rows: u16, cols: u16, args: &str) -> String {
    typed(d, rows, cols, args, PW)
}

/// [`on_terminal`] with the password `pw`.
fn typed(d: &Dir, rows: u16, cols: u16, args: &str, pw: &str) -> String {
    let mut p = d.pty(&format!(
        "stty rows {rows} cols {cols}; '{APP}' show {args}; echo STATUS:$?; stty -a"
    ));
    p.wait_for("Vault password for ");
    p.send(pw);
    p.wait_for("STATUS:");
    p.finish()
}

/// The rows after the note, up to the shell's status line.
fn after_note(t: &str) -> &str {
    let rest = t
        .split_once(&format!("{NOTE}\n"))
        .unwrap_or_else(|| panic!("no note: {t:?}"))
        .1;
    rest.split_once("STATUS:").unwrap().0
}

/// `larsal show ARGS rich-v3 'Full demo entry'` with the given streams; the
/// password written on stdin.
fn spawn(d: &Dir, args: &[&str], stdout: Stdio, stderr: Stdio) -> Child {
    let mut child = d
        .command(&[&["show"][..], args, &[RICH, FULL]].concat())
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    // The process may refuse and end before it reads.
    let _ = child.stdin.take().unwrap().write_all(PW.as_bytes());
    child
}

// ---------------------------------------------------------------------------
// The reader, proven on E21-S2's encoder.

#[test]
fn e21s3_reader_reads_e21s2_matrices_at_every_version() {
    let cap: Vec<usize> = (1..=40).map(read::data_codewords).collect();
    // §7.4.10 Table 7, level H data codewords: versions 1, 10, 40.
    assert_eq!((cap[0], cap[9], cap[39]), (9, 122, 1_276));
    let mut masks = std::collections::BTreeSet::new();
    for v in 1..=40 {
        let count = if v <= 9 { 8 } else { 16 };
        let room = (cap[v - 1] * 8 - 16 - count) / 8;
        for (len, version) in [(room, v), (room + 1, v + 1)] {
            if len > larsal_qr::MAX_BYTES {
                continue;
            }
            let text: Vec<u8> = (0..len).map(|i| ((i * 7 + v) % 256) as u8).collect();
            let m = larsal_qr::encode(&text).unwrap();
            let s = read::read(m.size(), m.modules()).unwrap();
            assert_eq!(s.version, version, "{len} bytes");
            assert_eq!(read::smallest(len), version);
            assert_eq!(s.segments, [Segment::Eci(26), Segment::Bytes(text)]);
            masks.insert(s.mask);
        }
    }
    assert_eq!(masks.len(), 8, "every mask unmasked: {masks:?}");
    // Without ECI, the authenticator setup code's form (FEA-04.23).
    for len in [1, 7, 1_273] {
        let text = vec![b'k'; len];
        let m = larsal_qr::symbol(&text, None).unwrap();
        let s = read::read(m.size(), m.modules()).unwrap();
        assert_eq!(s.segments, [Segment::Bytes(text)]);
    }
    // 1,272 bytes fill version 40 with no terminator bits; 1,273 refuse.
    let full = larsal_qr::encode(&[b'x'; 1_272]).unwrap();
    assert_eq!(read::read(full.size(), full.modules()).unwrap().version, 40);
    assert!(matches!(
        larsal_qr::encode(&[b'x'; 1_273]),
        Err(larsal_qr::Refusal::TooLarge)
    ));
    // It refuses what is not well formed: one data module flipped, a dark
    // quiet zone module, one format bit flipped.
    let m = larsal_qr::encode(b"demo-entry-pass-2").unwrap();
    let n = m.size();
    for at in [(n - 5) * n + n - 5, 0, 4 * n + 12] {
        let mut bad = m.modules().to_vec();
        bad[at] ^= 1;
        assert!(read::read(n, &bad).is_err(), "{at}");
    }
}

/// The reader takes an ECI designator only in its shortest form: 26 as one
/// byte, never as two (0x80 0x1A) or three (0xC0 0x00 0x1A). Version 1 data
/// codewords: ECI 26, one byte "k", the terminator, the fill and the pads.
#[test]
fn e21s3_reader_refuses_a_non_canonical_eci_designator() {
    let short = [0x71, 0xA4, 0x01, 0x6B, 0x00, 0xEC, 0x11, 0xEC, 0x11];
    assert_eq!(
        read::segments(&short, 1),
        Ok(vec![Segment::Eci(26), Segment::Bytes(b"k".to_vec())])
    );
    let two = [0x78, 0x01, 0xA4, 0x01, 0x6B, 0x00, 0xEC, 0x11, 0xEC];
    assert!(
        read::segments(&two, 1).is_err(),
        "{:?}",
        read::segments(&two, 1)
    );
    let three = [0x7C, 0x00, 0x01, 0xA4, 0x01, 0x6B, 0x00, 0xEC, 0x11];
    assert!(
        read::segments(&three, 1).is_err(),
        "{:?}",
        read::segments(&three, 1)
    );
}

// ---------------------------------------------------------------------------
// E21-S3's acceptance checks.

/// Check 1: the printed blocks, turned back into a matrix, give the value.
#[test]
fn e21s3_a_printed_blocks_give_the_value() {
    let d = Dir::new("qr-a");
    let o = show(&d, &["--qr", "--stdout", "-s"], RICH, FULL, PW);
    assert_eq!(raw(&o), b"demo-entry-pass-2");
    let t = on_terminal(&d, 40, 80, "--qr -s rich-v3.larsalvault 'Full demo entry'");
    assert_eq!(read::value(after_note(&t), true), b"demo-entry-pass-2");
    assert!(t.contains("STATUS:0"), "{t}");
}

/// Check 2: no pipe or file unless asked with --stdout.
#[test]
fn e21s3_b_a_pipe_or_a_file_needs_stdout() {
    let d = Dir::new("qr-b");
    refused_first(&show(&d, &["--qr", "-s"], RICH, FULL, PW), PIPE);
    let file = d.path("code.txt");
    let child = spawn(
        &d,
        &["--qr", "-s"],
        std::fs::File::create(&file).unwrap().into(),
        Stdio::piped(),
    );
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&o.stderr), PIPE);
    assert_eq!(std::fs::read(&file).unwrap(), b"");
    let child = spawn(
        &d,
        &["--qr", "--stdout", "-s"],
        std::fs::File::create(&file).unwrap().into(),
        Stdio::piped(),
    );
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let written = std::fs::read_to_string(&file).unwrap();
    assert_eq!(read::value(&written, false), b"demo-entry-pass-2");
    let piped = show(&d, &["--qr", "--stdout", "-s"], RICH, FULL, PW);
    assert_eq!(piped.out, written, "the same cells to a pipe and a file");
}

/// Check 3: the `qrcode` crate reaches larsal-cli only through larsal-qr,
/// the words the proposed architecture row and LD-198 say.
#[test]
fn e21s3_c_qrcode_reaches_the_cli_through_larsal_qr() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut users = Vec::new();
    let mut cli_uses_qr = false;
    for dir in std::fs::read_dir(&crates).unwrap() {
        let dir = dir.unwrap().path();
        let Ok(manifest) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
        let mut section = String::new();
        for line in manifest.lines() {
            if line.starts_with('[') {
                section = line.to_owned();
            } else if section.ends_with("dependencies]") && !section.contains("dev-") {
                if line.starts_with("qrcode") {
                    users.push(name.clone());
                }
                if name == "larsal-cli" && line.starts_with("larsal-qr ") {
                    cli_uses_qr = true;
                }
            }
        }
    }
    assert_eq!(users, ["larsal-qr"]);
    assert!(cli_uses_qr);
}

// ---------------------------------------------------------------------------
// QR-T26: the selected value.

#[test]
fn qr_t26_a_password_with_s_and_one_field_with_a() {
    let d = Dir::new("qr-26a");
    // -s: the Password, never the (hidden) marker or a label.
    assert_eq!(
        raw(&show(&d, &["--qr", "--stdout", "-s"], RICH, FULL, PW)),
        b"demo-entry-pass-2"
    );
    // One -a, as INT-10.28: exact or any case, protected too, no -s needed.
    for (name, want) in [
        ("UserName", "demo-user"),
        ("username", "demo-user"),
        ("Demo PIN", "0000"),
        ("Tags", "demo,work"),
        ("Uuid", "{00000000-0000-0000-0000-00000000000a}"),
    ] {
        let o = show(&d, &["--qr", "--stdout", "-a", name], RICH, FULL, PW);
        assert_eq!(raw(&o), want.as_bytes(), "{name}");
    }
    // Saved values resolve fully, as show -a and show -s print them, also
    // through a protected value (never the mask of text show without -s); a
    // protected note and a passkey field are no refusal (FEA-10.3, .22).
    let pem = "-----BEGIN PRIVATE KEY-----\ndemo\n-----END PRIVATE KEY-----";
    q_vault(
        &d,
        &[
            ("UserName", "demo-user", false),
            ("Password", "{USERNAME}", true),
            ("URL", "https://h.example/?p={PASSWORD}", false),
            ("Private key note", "demo private note", true),
            ("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem, true),
        ],
    );
    let q = |args: &[&str]| raw(&show(&d, args, Q, "QR demo", Q_PW));
    assert_eq!(q(&["--qr", "--stdout", "-s"]), b"demo-user");
    assert_eq!(
        q(&["--qr", "--stdout", "-a", "URL"]),
        b"https://h.example/?p=demo-user"
    );
    assert_eq!(
        q(&["--qr", "--stdout", "-a", "Private key note"]),
        b"demo private note"
    );
    let text = show(
        &d,
        &["-a", "KPEX_PASSKEY_PRIVATE_KEY_PEM"],
        Q,
        "QR demo",
        Q_PW,
    );
    let qr = q(&["--qr", "--stdout", "-a", "KPEX_PASSKEY_PRIVATE_KEY_PEM"]);
    assert_eq!(qr, pem.as_bytes());
    assert_eq!(text.out, format!("{pem}\n"), "text show unchanged");
    // Text show is unchanged: the hidden marker without --qr.
    let o = show(&d, &[], RICH, FULL, PW);
    assert!(lines(&o.out).contains(&"Password: (hidden)"));
    // An empty Password is MSG-QR-EMPTY.
    q_vault(&d, &[("UserName", "u", false)]);
    refused(
        &show(&d, &["--qr", "--stdout", "-s"], Q, "QR demo", Q_PW),
        EMPTY,
    );
}

#[test]
fn qr_t26_b_totp_is_the_current_code_and_otp_fields_stay_as_show() {
    let d = Dir::new("qr-26b");
    let before = current_code(&d);
    let o = show(&d, &["--qr", "--stdout", "--totp"], RICH, FULL, PW);
    let after = current_code(&d);
    let code = String::from_utf8(raw(&o)).unwrap();
    assert!(code == before || code == after, "{code} {before} {after}");
    assert_eq!(code.len(), 6);
    // -a otp gives what show -a otp prints: the CLI's existing output.
    let text = show(&d, &["-a", "otp"], RICH, FULL, PW).out;
    let setup = raw(&show(
        &d,
        &["--qr", "--stdout", "-a", "otp"],
        RICH,
        FULL,
        PW,
    ));
    assert_eq!(
        format!("{}\n", String::from_utf8(setup.clone()).unwrap()),
        text
    );
    assert_ne!(setup, code.as_bytes(), "the current code is not the setup");
    // No one-time password: show's own error.
    refused(
        &show(
            &d,
            &["--qr", "--stdout", "--totp"],
            RICH,
            "Server login",
            PW,
        ),
        "larsal: Server login has no one-time password.\n",
    );
}

#[test]
fn qr_t26_c_wifi_join_with_s() {
    let d = Dir::new("qr-26c");
    q_vault(
        &d,
        &[
            ("UserName", "Demo net", false),
            ("Password", "demo-wifi;pass", true),
            ("Security", "WPA2 Personal", false),
        ],
    );
    let o = show(
        &d,
        &["--qr", "--stdout", "--wifi", "-s"],
        Q,
        "QR demo",
        Q_PW,
    );
    assert_eq!(
        raw(&o),
        br"WIFI:T:WPA;S:Demo net;P:demo-wifi\;pass;H:false;;".as_slice()
    );
    // The pipe flag grants no disclosure.
    refused_first(
        &show(&d, &["--qr", "--stdout", "--wifi"], Q, "QR demo", Q_PW),
        AUTH,
    );
    // Enterprise stays unavailable (LD-361); a login is not a Wi-Fi entry.
    q_vault(
        &d,
        &[
            ("UserName", "Demo net", false),
            ("Password", "demo-pass", true),
            ("Security", "WPA2-EAP", false),
            ("EAP Method", "TTLS", false),
            ("Phase 2 Method", "MSCHAPV2", false),
            ("Identity", "demo-id", false),
        ],
    );
    refused(
        &show(
            &d,
            &["--qr", "--stdout", "--wifi", "-s"],
            Q,
            "QR demo",
            Q_PW,
        ),
        "larsal: This network type cannot be shared as a Wi-Fi join code. Show an individual field as text instead.\n",
    );
    refused(
        &show(&d, &["--qr", "--stdout", "--wifi", "-s"], RICH, FULL, PW),
        "larsal: This Wi-Fi entry is incomplete or has invalid settings.\n",
    );
}

/// INT-10's no-echo prompt and stdin credentials stay: the typed password is
/// never shown and echo is back on after.
#[test]
fn qr_t26_d_no_echo_prompt_on_a_terminal_pty() {
    let d = Dir::new("qr-26d");
    let t = on_terminal(
        &d,
        40,
        80,
        "--qr -a UserName rich-v3.larsalvault 'Full demo entry'",
    );
    assert!(!t.contains("demo-pass-4"), "{t}");
    assert_eq!(read::value(after_note(&t), true), b"demo-user");
    assert!(echo_on(t.split("STATUS:0").nth(1).unwrap()), "{t}");
}

/// A control outside the CLI's Show: an attachment is no field, and the
/// attachment list cannot be a code.
#[test]
fn qr_t26_e_attachments_are_not_a_code() {
    let d = Dir::new("qr-26e");
    refused(
        &show(&d, &["--qr", "--stdout", "-a", "notes.txt"], RICH, FULL, PW),
        "larsal: Full demo entry has no field called notes.txt.\n",
    );
    refused_first(
        &show(
            &d,
            &["--qr", "--stdout", "--show-attachments", "-s"],
            RICH,
            FULL,
            PW,
        ),
        OPTIONS,
    );
}

/// QR-T26: the code holds the raw bytes of the full Show, before the escaping
/// INT-10.10 gives terminal text: ESC, BEL, a C1 control (U+009B) and DEL go
/// into the matrix as they are, and only the fixed colours reach the
/// terminal.
#[test]
fn qr_t26_f_control_characters_encode_raw_on_a_terminal_pty() {
    let d = Dir::new("qr-26f");
    let value = "demo\x1b[31m-bel\x07-csi\u{9b}-del\x7f-end";
    q_vault(&d, &[("Controls", value, true)]);
    let t = typed(&d, 40, 80, "--qr -a Controls q.larsalvault 'QR demo'", Q_PW);
    assert_eq!(read::value(after_note(&t), true), value.as_bytes());
    let rows = after_note(&t);
    assert_eq!(
        rows.matches('\x1b').count(),
        2 * rows.lines().count(),
        "{t:?}"
    );
    assert!(!rows.contains(['\x07', '\u{9b}', '\x7f']), "{t:?}");
    assert!(t.contains("STATUS:0"), "{t}");
    let o = show(
        &d,
        &["--qr", "--stdout", "-a", "Controls"],
        Q,
        "QR demo",
        Q_PW,
    );
    assert_eq!(raw(&o), value.as_bytes(), "the same bytes on a pipe");
}

// ---------------------------------------------------------------------------
// QR-T27: selectors and options.

#[test]
fn qr_t27_a_conflicts_are_refused_before_the_unlock() {
    let d = Dir::new("qr-27a");
    for args in [
        &["--qr", "--all", "-s"][..],
        &["--qr", "--show-attachments", "-a", "UserName"],
        &["--qr", "-a", "UserName", "-a", "Password"],
        &["--qr", "-a", "UserName", "-a", "UserName"],
        &["--qr", "-a", "UserName", "--totp"],
        &["--qr", "--wifi", "-s", "-a", "UserName"],
        &["--qr", "--wifi", "-s", "--totp"],
        &["--stdout", "-s"],
        &["--stdout", "-a", "UserName"],
        &["--wifi", "-s"],
        &["--stdout", "--all"],
    ] {
        // A wrong password: an unlock would print its own error.
        let o = show(&d, args, RICH, FULL, "wrong\n");
        refused_first(&o, OPTIONS);
    }
}

#[test]
fn qr_t27_b_disclosure_needs_s_or_one_field() {
    let d = Dir::new("qr-27b");
    for args in [
        &["--qr"][..],
        &["--qr", "--stdout"],
        &["--qr", "--wifi"],
        &["--qr", "--wifi", "--stdout"],
    ] {
        refused_first(&show(&d, args, RICH, FULL, "wrong\n"), AUTH);
    }
}

#[test]
fn qr_t27_c_field_errors_stay_int10() {
    let d = Dir::new("qr-27c");
    refused(
        &show(&d, &["--qr", "--stdout", "-a", "No such"], RICH, FULL, PW),
        "larsal: Full demo entry has no field called No such.\n",
    );
    refused(
        &show(&d, &["--qr", "--stdout", "-s"], RICH, "No entry", PW),
        "larsal: no entry at No entry.\n",
    );
    refused(
        &show(
            &d,
            &["--qr", "--stdout", "-a", "Empty custom field"],
            RICH,
            FULL,
            PW,
        ),
        EMPTY,
    );
    let mut v = load(&d.path("password-only.larsalvault"), "demo-pass-1");
    let e = find_mut(&mut v.root, "Demo login").unwrap();
    e.set_field("pin".into(), field("1", false));
    e.set_field("PIN".into(), field("2", false));
    store(&d.path("pin.larsalvault"), &v, "demo-pass-1");
    refused(
        &show(
            &d,
            &["--qr", "--stdout", "-a", "Pin"],
            "pin.larsalvault",
            "Demo login",
            Q_PW,
        ),
        "larsal: Pin could mean any of PIN, pin. Give the exact name.\n",
    );
    assert_eq!(
        raw(&show(
            &d,
            &["--qr", "--stdout", "-a", "PIN"],
            "pin.larsalvault",
            "Demo login",
            Q_PW
        )),
        b"2"
    );
}

/// The same rules in the shell of `open`.
#[test]
fn qr_t27_d_the_shell() {
    let d = Dir::new("qr-27d");
    let o = d.run(
        &["open", RICH],
        "demo-pass-4\n\
         show --qr --all \"Full demo entry\"\n\
         show --qr \"Full demo entry\"\n\
         show --qr -s \"Full demo entry\"\n\
         show --qr --stdout -a nosuch \"Full demo entry\"\n\
         show --qr --stdout -a UserName \"Full demo entry\"\n\
         exit\n",
    );
    assert_eq!(read::value(&o.out, false), b"demo-user");
    assert_eq!(
        o.err,
        format!(
            "Vault password for {RICH}: {OPTIONS}{AUTH}{PIPE}larsal: Full demo entry has no field called nosuch.\n{NOTE}\n"
        )
    );
}

// ---------------------------------------------------------------------------
// QR-T28: terminal display and raw output.

/// The ordinary display on a terminal just large enough: N = 37 columns and
/// 19 rows plus the final line feed's (version 3).
#[test]
fn qr_t28_a_adequate_terminal_pty() {
    let d = Dir::new("qr-28a");
    let t = on_terminal(&d, 20, 37, "--qr -s rich-v3.larsalvault 'Full demo entry'");
    let rows = after_note(&t);
    assert_eq!(read::value(rows, true), b"demo-entry-pass-2");
    assert_eq!(rows.lines().count(), 19);
    // The only control text: the fixed colours, and nothing erases scrollback.
    let escapes = t.matches('\x1b').count();
    assert_eq!(escapes, 2 * 19, "{t:?}");
    assert!(t.contains("STATUS:0"));
}

/// Too small or unknown: MSG-QR-CLI-SIZE before any cell and before the
/// note; --stdout prints raw cells there, as it reads no size, and on a
/// terminal large enough too: never the colours.
#[test]
fn qr_t28_b_small_or_unknown_terminal_pty() {
    let d = Dir::new("qr-28b");
    for (rows, cols) in [(19, 37), (20, 36), (0, 0)] {
        let t = on_terminal(
            &d,
            rows,
            cols,
            "--qr -s rich-v3.larsalvault 'Full demo entry'",
        );
        assert!(t.contains(SIZE), "{rows}x{cols}: {t:?}");
        assert!(t.contains("STATUS:1"));
        assert!(!t.contains(NOTE));
        assert!(
            !t.contains(['\u{2580}', '\u{2584}', '\u{2588}', '\x1b']),
            "{t:?}"
        );
    }
    let piped = show(&d, &["--qr", "--stdout", "-s"], RICH, FULL, PW).out;
    for (rows, cols) in [(5, 10), (0, 0), (40, 80)] {
        let t = on_terminal(
            &d,
            rows,
            cols,
            "--qr --stdout -s rich-v3.larsalvault 'Full demo entry'",
        );
        assert_eq!(after_note(&t), piped, "the same raw cells on a terminal");
        assert!(!t.contains('\x1b'));
    }
}

/// --stdout: raw cells and LF only, no colour or prose on stdout; the note on
/// stderr, also with -q.
#[test]
fn qr_t28_c_raw_output_and_the_note_with_q() {
    let d = Dir::new("qr-28c");
    let o = show(&d, &["--qr", "--stdout", "-s", "-q"], RICH, FULL, PW);
    assert_eq!(o.err, format!("{NOTE}\n"));
    assert!(
        o.out
            .chars()
            .all(|c| matches!(c, ' ' | '\u{2580}' | '\u{2584}' | '\u{2588}' | '\n'))
    );
    assert_eq!(read::value(&o.out, false), b"demo-entry-pass-2");
    // A quiet zone of 4 modules: two blank rows and four blank columns.
    let first: Vec<&str> = o.out.lines().take(2).collect();
    assert!(first.iter().all(|l| l.trim().is_empty()));
}

/// A note that cannot be written stops before any cell; a broken stdout
/// exits 1 with a safe error.
#[test]
fn qr_t28_d_write_failures_exit_1() {
    let d = Dir::new("qr-28d");
    let mut child = spawn(
        &d,
        &["--qr", "--stdout", "-s", "-q"],
        Stdio::piped(),
        Stdio::piped(),
    );
    drop(child.stderr.take());
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    assert_eq!(wait_child(&mut child).code(), Some(1));
    assert!(out.is_empty(), "no cell after a failed note");
    let mut child = spawn(
        &d,
        &["--qr", "--stdout", "-s"],
        Stdio::piped(),
        Stdio::piped(),
    );
    drop(child.stdout.take());
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(wait_child(&mut child).code(), Some(1));
    assert!(
        err.ends_with(&format!(
            "{NOTE}\nlarsal: cannot write to standard output: Broken pipe (os error 32).\n"
        )),
        "{err}"
    );
    assert!(!err.contains("demo-entry-pass-2"));
}

// ---------------------------------------------------------------------------
// QR-T29 without the zeroing allocator: this program frees through the
// system's, so only larsal-qr's own wipe on drop (Rust rule 3) keeps the
// matrix and the join text out of freed memory.

/// The child's full name: it runs only when named exactly.
const CHILD: &str = "qr::qr_t29_b_child";

#[test]
fn qr_t29_b_the_matrix_and_the_join_text_wipe_on_drop() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            CHILD,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_remove("RUST_TEST_THREADS")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("QR-T29 b after the drop: [0, 0]"), "{err}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
}

/// The child, alone in its process as the search of all writable memory
/// (heap, freed blocks and the stack) needs. Each span exists only in the
/// buffer it is taken from.
#[test]
#[ignore = "a child of qr_t29_b_the_matrix_and_the_join_text_wipe_on_drop"]
fn qr_t29_b_child() {
    use larsal_platform::memory::{copies_in_memory, marker_survives_free};
    if !std::env::args().any(|a| a == CHILD) {
        return;
    }
    const MASK: u8 = 0xA5;
    let masked = |plain: &[u8]| plain.iter().map(|b| b ^ MASK).collect::<Vec<u8>>();
    // The control: a free here keeps a block's bytes.
    assert!(marker_survives_free(true));
    // Demo letters no other run holds.
    let mut state = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % u128::from(u64::MAX),
    )
    .unwrap();
    let mut unique = |n: usize| -> String {
        (0..n)
            .map(|_| {
                state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                char::from(b'g' + u8::try_from((state >> 40) % 20).unwrap())
            })
            .collect()
    };
    // The matrix of 1,272 bytes (version 40): the end of the middle row, the
    // quiet zone between it and the next row, and that row's start. Only this
    // matrix has it: `qrcode`'s own grid has no quiet zone.
    let symbol = larsal_qr::encode(unique(1_272).as_bytes()).unwrap();
    let n = symbol.size();
    let at = 92 * n + n - 4 - 28;
    let matrix = masked(&symbol.modules()[at..at + 64]);
    assert!(
        copies_in_memory(&matrix, MASK) >= 1,
        "the control: a live matrix"
    );
    drop(symbol);
    // Searched at once: a later block may take the freed one's place.
    let matrix_after = copies_in_memory(&matrix, MASK);
    // The join text: the end of a 66,000-byte password and the fields after
    // it, which only the join text holds. The size is near the control's
    // (`marker_survives_free`, 66,770 bytes), a block whose bytes a free here
    // keeps: with a 1,200-byte password, a lost copy freed here was not found
    // (E21-S3 round 2, mutant D2's first run).
    let mut e = Entry::new(Uuid([3; 16]), Time(0));
    for (name, value) in [
        ("UserName", "Wipe".to_owned()),
        ("Password", unique(66_000)),
        ("Security", "WPA".to_owned()),
    ] {
        e.set_field(name.into(), field(&value, false));
    }
    let join = larsal_qr::join_text(&e).unwrap();
    let text = join.expose().as_bytes();
    assert!(text.ends_with(b";H:false;;"));
    let tail = masked(&text[text.len() - 64..]);
    assert!(
        copies_in_memory(&tail, MASK) >= 1,
        "the control: a live join text"
    );
    drop(join);
    let after = [matrix_after, copies_in_memory(&tail, MASK)];
    eprintln!("QR-T29 b after the drop: {after:?}");
    assert_eq!(after, [0, 0], "matrix, join text");
}

// ---------------------------------------------------------------------------
// QR-T31, the command line's maxima and the 1,272 / 1,273-byte boundary.

/// The stored Password of `title` in w.larsalvault.
fn stored(d: &Dir, title: &str) -> String {
    let v = load(&d.path("w.larsalvault"), "demo-pass-4");
    find(&v, title).value("Password").to_owned()
}

fn qr_of(d: &Dir, title: &str) -> Out {
    show(d, &["--qr", "--stdout", "-s"], "w.larsalvault", title, PW)
}

#[test]
fn qr_t31_a_generated_passwords() {
    let d = Dir::new("qr-31a");
    // 1,024 four-byte scalars, the extra group's limit (D-02-4).
    let wide: String = (0x2_0000..0x2_0400)
        .map(|c| char::from_u32(c).unwrap())
        .collect();
    for (title, extra, fits) in [
        ("A1272", &["-L", "1272", "-l"][..], true),
        ("A1273", &["-L", "1273", "-l"], false),
        ("A10000", &["-L", "10000", "-l"], false),
        ("W318", &["-L", "318", "-c", &wide], true),
        ("W319", &["-L", "319", "-c", &wide], false),
        ("W10000", &["-L", "10000", "-c", &wide], false),
    ] {
        let o = d.run(
            &[&["add", "-g"][..], extra, &["w.larsalvault", title]].concat(),
            PW,
        );
        assert_eq!(o.code, Some(0), "{title}: {}", o.err);
        let value = stored(&d, title);
        let o = qr_of(&d, title);
        if fits {
            assert_eq!(value.len(), 1_272, "{title}");
            assert_eq!(raw(&o), value.as_bytes(), "{title}");
        } else {
            refused(&o, TOO_LARGE);
        }
    }
    let more = format!("{wide}a");
    let o = d.run(&["add", "-g", "-c", &more, "w.larsalvault", "X"], PW);
    assert_eq!(o.code, Some(1), "the 1,024 limit stays");
}

#[test]
fn qr_t31_b_passphrases() {
    let d = Dir::new("qr-31b");
    // The built-in list: 127 words of at most nine bytes always fit; 1,000
    // never do. A custom list of one 256-scalar word, made lower case: İ
    // becomes i and U+0307, 768 bytes for one word and 1,537 for two.
    std::fs::write(d.path("list.txt"), "İ".repeat(256)).unwrap();
    for (title, extra, fits) in [
        ("P127", &["-W", "127"][..], true),
        ("P1000", &["-W", "1000"], false),
        ("L1", &["-W", "1", "-w", "list.txt"], true),
        ("L2", &["-W", "2", "-w", "list.txt"], false),
        ("L1000", &["-W", "1000", "-w", "list.txt"], false),
    ] {
        let o = d.run(&[&["passphrase"][..], extra].concat(), "");
        assert_eq!(o.code, Some(0), "{title}: {}", o.err);
        let phrase = o.out.strip_suffix('\n').unwrap().to_owned();
        if title == "L1" {
            assert_eq!(phrase, "i\u{307}".repeat(256));
        }
        // Stored with the engine: `add -p` reads at most 65,536 bytes a line.
        q_vault(&d, &[("Password", &phrase, true)]);
        let o = show(&d, &["--qr", "--stdout", "-s"], Q, "QR demo", Q_PW);
        if fits {
            assert!(phrase.len() <= 1_272);
            assert_eq!(raw(&o), phrase.as_bytes(), "{title}");
        } else {
            assert!(phrase.len() > 1_272);
            refused(&o, TOO_LARGE);
        }
    }
}

#[test]
fn qr_t31_c_exactly_1272_and_1273_bytes() {
    let d = Dir::new("qr-31c");
    // A saved placeholder whose resolution reaches the sizes.
    for (name, fits) in [("u".repeat(1_262), true), ("u".repeat(1_263), false)] {
        q_vault(
            &d,
            &[
                ("UserName", &name, false),
                ("Password", "{USERNAME}0123456789", true),
            ],
        );
        let o = show(&d, &["--qr", "--stdout", "-s"], Q, "QR demo", Q_PW);
        if fits {
            assert_eq!(raw(&o), format!("{name}0123456789").as_bytes());
        } else {
            refused(&o, TOO_LARGE);
        }
    }
    // Literal bytes, two-byte scalars.
    for (value, fits) in [
        ("é".repeat(636), true),
        (format!("{}a", "é".repeat(636)), false),
    ] {
        q_vault(&d, &[("Note", &value, true)]);
        let o = show(&d, &["--qr", "--stdout", "-a", "Note"], Q, "QR demo", Q_PW);
        if fits {
            assert_eq!(raw(&o), value.as_bytes());
        } else {
            refused(&o, TOO_LARGE);
        }
    }
    // The Wi-Fi wire: S wrapped in quotes, all five escapes, Unicode.
    for (pad, fits) in [(1_228, true), (1_229, false)] {
        let password = format!(r#"\;,":é{}"#, "a".repeat(pad));
        q_vault(
            &d,
            &[
                ("UserName", "ABCD", false),
                ("Password", &password, true),
                ("Security", "WPA", false),
            ],
        );
        let o = show(
            &d,
            &["--qr", "--stdout", "--wifi", "-s"],
            Q,
            "QR demo",
            Q_PW,
        );
        let wire = format!(
            r#"WIFI:T:WPA;S:"ABCD";P:\\\;\,\"\:é{};H:false;;"#,
            "a".repeat(pad)
        );
        if fits {
            assert_eq!(wire.len(), 1_272);
            assert_eq!(raw(&o), wire.as_bytes());
        } else {
            refused(&o, TOO_LARGE);
        }
    }
    // 1,272 bytes on a terminal of exactly 185 columns and 93 + 1 rows.
    q_vault(&d, &[("Password", &"p".repeat(1_272), true)]);
    let mut p = d.pty(&format!(
        "stty rows 94 cols 185; '{APP}' show --qr -s q.larsalvault 'QR demo'; echo STATUS:$?"
    ));
    p.wait_for("Vault password for ");
    p.send(Q_PW);
    p.wait_for("STATUS:");
    let t = p.finish();
    assert_eq!(
        read::value(after_note(&t), true),
        "p".repeat(1_272).as_bytes()
    );
}
