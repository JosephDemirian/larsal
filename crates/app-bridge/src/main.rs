//! `app-bridge`, the host program a browser starts for App's extension
//! (INT-01.1 to INT-01.5; story E7-S6). A dumb relay: it copies each framed
//! message from standard input to App's bridge socket and each frame from
//! the socket to standard output, in order and unchanged. It holds no key,
//! never parses a message, and answers only three plain errors itself: 43
//! (a frame over 1 MiB, then it exits), 44 (App is not running) and 45 (App
//! runs, but browser integration is off).
//!
//! Standard output carries frames only (INT-01.1); standard error carries
//! nothing but APP-11's M11-01 when hardening fails (Firefox shows it in
//! the browser console, INT-01.47). The arguments the browser passes (the
//! caller origin, or Firefox's manifest path and add-on id) are ignored
//! (INT-01.4). End of standard input exits at once; SIGTERM, SIGINT and
//! SIGHUP keep their default action, which ends the process at once.
#![forbid(unsafe_code)]
// Rust rule 4: every frame is hostile input. Test code is exempt via clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

/// The largest frame either way: JSON bytes after the 4-byte length (INT-01.3).
const MAX_FRAME: usize = 1_048_576;
/// How long one try to reach App's socket may take (INT-01.5).
const CONNECT: Duration = Duration::from_secs(1);

/// App's bridge socket and App's single-instance socket (APP-09.7) in the
/// same folder. Debug builds use their own names, as App's do (INT-01.6,
/// APP-09.29), so a debug relay never reaches a release App.
const SOCKETS: (&str, &str) = if cfg!(debug_assertions) {
    ("com.app.browser-debug.sock", "com.app.desktop-debug.sock")
} else {
    ("com.app.browser.sock", "com.app.desktop.sock")
};

/// The plain errors of INT-01.40 the relay sends itself.
const TOO_LARGE: &[u8] = br#"{"type":"error","error":43}"#;
const NOT_RUNNING: &[u8] = br#"{"type":"error","error":44}"#;
const INTEGRATION_OFF: &[u8] = br#"{"type":"error","error":45}"#;

fn main() {
    // D-APP11-1: APP-11's hardening first (M11-01 on stderr when a step fails).
    let _ = app_platform::hardening::harden();
    let Ok(dir) = folder() else {
        // No folder from the OS: App cannot be reached; every frame says so.
        relay(None);
        return;
    };
    relay(Some(dir));
}

/// The per-user temp folder from the OS (INT-01.6: `confstr`, never
/// `TMPDIR`). Debug builds started by a test use the test's instance folder
/// (`APP_TEST_INSTANCE_DIR`, as App does); release builds read no
/// environment variable.
fn folder() -> io::Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("APP_TEST_INSTANCE_DIR") {
        return Ok(dir.into());
    }
    app_platform::macos::user_temp_dir()
}

/// One link to App: the socket's write side, and whether App still holds
/// the other end (cleared by the thread that copies App's frames out).
struct Link {
    socket: UnixStream,
    open: Arc<AtomicBool>,
}

/// The relay loop until standard input ends (INT-01.5).
fn relay(dir: Option<PathBuf>) {
    let out = Arc::new(Mutex::new(io::stdout()));
    let mut input = io::stdin().lock();
    let mut link: Option<Link> = None;
    loop {
        let frame = match read_frame(&mut input) {
            Frame::Message(frame) => frame,
            Frame::TooLarge => {
                let _ = write_out(&out, &error_frame(TOO_LARGE));
                return;
            }
            Frame::End => return,
        };
        if link
            .as_ref()
            .is_some_and(|l| !l.open.load(Ordering::SeqCst))
        {
            link = None;
        }
        if link.is_none() {
            link = dir.as_ref().and_then(|d| connect(&d.join(SOCKETS.0), &out));
        }
        let sent = link
            .as_mut()
            .is_some_and(|l| l.socket.write_all(&frame).is_ok());
        if !sent {
            link = None;
            let running = dir.as_ref().is_some_and(|d| app_runs(&d.join(SOCKETS.1)));
            let reply = if running {
                INTEGRATION_OFF
            } else {
                NOT_RUNNING
            };
            if write_out(&out, &error_frame(reply)).is_err() {
                return;
            }
        }
    }
}

/// App runs for this user when its single-instance socket (APP-09.7: one
/// App per user and build kind) takes a connection. The connection is
/// closed at once without a request, which App drops unread (APP-09.12).
fn app_runs(instance: &std::path::Path) -> bool {
    UnixStream::connect(instance).is_ok()
}

/// Connects to App's bridge socket within [`CONNECT`], and starts the
/// thread that copies App's frames to standard output.
fn connect(socket: &std::path::Path, out: &Arc<Mutex<io::Stdout>>) -> Option<Link> {
    let (tx, rx) = mpsc::channel();
    let path = socket.to_owned();
    // A try that blocks past the limit is left behind; its result is dropped.
    thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(UnixStream::connect(path));
        })
        .ok()?;
    let socket = rx.recv_timeout(CONNECT).ok()?.ok()?;
    let mut reader = socket.try_clone().ok()?;
    let open = Arc::new(AtomicBool::new(true));
    let (alive, out) = (open.clone(), out.clone());
    thread::Builder::new()
        .spawn(move || {
            // App never sends a frame over 1 MiB (INT-01.3); one that says so
            // ends the link without reaching the browser.
            while let Frame::Message(frame) = read_frame(&mut reader) {
                if write_out(&out, &frame).is_err() {
                    std::process::exit(0); // the browser is gone
                }
            }
            alive.store(false, Ordering::SeqCst);
            let _ = reader.shutdown(std::net::Shutdown::Both);
        })
        .ok()?;
    Some(Link { socket, open })
}

/// One read of a frame.
enum Frame {
    /// The whole frame, its 4-byte length included, ready to copy on.
    Message(Vec<u8>),
    /// A length over [`MAX_FRAME`]: refused before any byte of the body is
    /// read or any memory is reserved for it (INT-01.3).
    TooLarge,
    /// The stream ended, also inside a frame.
    End,
}

/// The length is a 32-bit unsigned number in native byte order, which is
/// little-endian on every Mac App supports (INT-01.1, INT-01.2).
fn read_frame(stream: &mut impl Read) -> Frame {
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).is_err() {
        return Frame::End;
    }
    let Some(len) = usize::try_from(u32::from_le_bytes(head))
        .ok()
        .filter(|&n| n <= MAX_FRAME)
    else {
        return Frame::TooLarge;
    };
    let mut frame = Vec::with_capacity(len.saturating_add(4));
    frame.extend_from_slice(&head);
    match stream.take(len as u64).read_to_end(&mut frame) {
        Ok(n) if n == len => Frame::Message(frame),
        _ => Frame::End,
    }
}

/// Writes bytes that hold whole frames to standard output under its lock,
/// so frames never interleave.
fn write_out(out: &Mutex<io::Stdout>, frames: &[u8]) -> io::Result<()> {
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    out.write_all(frames)?;
    out.flush()
}

/// One plain error frame of the relay's own.
fn error_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(body.len())
        .unwrap_or(0)
        .to_le_bytes()
        .to_vec();
    frame.extend_from_slice(body);
    frame
}
