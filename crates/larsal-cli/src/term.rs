//! The three streams (INT-10.6, INT-10.7, INT-10.10): data and success lines
//! on stdout, everything else on stderr; vault text escaped on a terminal;
//! lines read from stdin one byte at a time, without echo on a terminal.

use larsal_crypto::secret::{SecretBytes, SecretString};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;
use std::sync::OnceLock;

/// A command failed; its message is already on stderr. Exit code 1.
#[derive(Debug)]
pub struct Fail;

/// A command's result.
pub type Res<T = ()> = Result<T, Fail>;

/// Longest line kept, in bytes; the rest of a longer line is read and dropped.
const MAX_LINE: usize = 65_536;

pub fn stdin_tty() -> bool {
    static T: OnceLock<bool> = OnceLock::new();
    *T.get_or_init(|| io::stdin().is_terminal())
}

pub fn stdout_tty() -> bool {
    static T: OnceLock<bool> = OnceLock::new();
    *T.get_or_init(|| io::stdout().is_terminal())
}

pub fn stderr_tty() -> bool {
    static T: OnceLock<bool> = OnceLock::new();
    *T.get_or_init(|| io::stderr().is_terminal())
}

/// INT-10.10: C0 controls except TAB and LF, DEL and C1 controls as visible
/// escapes (`\x1b`, `\x7f`, `\u{9b}`).
pub fn escape(text: &str) -> Cow<'_, str> {
    let bad = |c: char| matches!(c, '\0'..='\x08' | '\x0b'..='\x1f' | '\x7f'..='\u{9f}');
    if !text.chars().any(bad) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            c if !bad(c) => out.push(c),
            c if u32::from(c) < 0x80 => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
        }
    }
    Cow::Owned(out)
}

/// One line of data or a success line on stdout, escaped on a terminal.
pub fn out(line: &str) {
    out_parts(&[line]);
}

/// A label and a value (perhaps secret) as one line on stdout, with no
/// joined copy of the value; an escaped copy is wiped.
pub fn out_pair(label: &str, value: &str) {
    out_parts(&[label, value]);
}

/// Parts written as one line on stdout, escaped on a terminal; escaped
/// copies are wiped after the write.
pub fn out_parts(parts: &[&str]) {
    let mut o = io::stdout().lock();
    for part in parts {
        match if stdout_tty() {
            escape(part)
        } else {
            Cow::Borrowed(*part)
        } {
            Cow::Borrowed(t) => {
                let _ = o.write_all(t.as_bytes());
            }
            Cow::Owned(t) => {
                let t = SecretString::new(t);
                let _ = o.write_all(t.expose().as_bytes());
            }
        }
    }
    let _ = o.write_all(b"\n");
}

/// Raw bytes on stdout (attachment-export `--stdout`): exact, never escaped.
pub fn out_bytes(bytes: &[u8]) -> io::Result<()> {
    let mut o = io::stdout().lock();
    o.write_all(bytes)?;
    o.flush()
}

/// One line on stderr, escaped on a terminal.
pub fn err(line: &str) {
    let text = if stderr_tty() {
        escape(line)
    } else {
        Cow::Borrowed(line)
    };
    let _ = io::stdout().flush();
    let mut e = io::stderr().lock();
    let _ = e.write_all(text.as_bytes());
    let _ = e.write_all(b"\n");
}

/// An error line `larsal: <text>`; the command then exits 1.
pub fn fail(text: impl AsRef<str>) -> Fail {
    err(&format!("larsal: {}", text.as_ref()));
    Fail
}

/// A prompt on stderr, no line end (INT-10.6); none with `-q`.
pub fn prompt(text: &str, quiet: bool) {
    if quiet {
        return;
    }
    let _ = io::stdout().flush();
    let text = if stderr_tty() {
        escape(text)
    } else {
        Cow::Borrowed(text)
    };
    let mut e = io::stderr().lock();
    let _ = e.write_all(text.as_bytes());
    let _ = e.flush();
}

/// Our own text on stderr, written as it is (the clip countdown's carriage
/// return and line clear); never vault text.
pub fn err_raw(text: &str) {
    let mut e = io::stderr().lock();
    let _ = e.write_all(text.as_bytes());
    let _ = e.flush();
}

/// Standard input as one unbuffered handle: std's buffer would keep later
/// lines (passwords) unwiped and would read past the line the shell needs.
fn input() -> Option<&'static File> {
    static IN: OnceLock<Option<File>> = OnceLock::new();
    IN.get_or_init(|| {
        io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from)
    })
    .as_ref()
}

/// Standard input with echo off: each read first waits for input and fails
/// once a quit signal arrived.
struct Hidden<'a> {
    file: &'a File,
    echo: Option<&'a larsal_platform::macos::EchoOff<'a>>,
}

impl Read for Hidden<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(echo) = self.echo {
            echo.wait_for_input()?;
        }
        let mut file = self.file;
        file.read(buf)
    }
}

/// Reads one line from stdin (INT-10.12 steps 2, 3 and 5). `hidden`: on a
/// terminal echo is off while it is typed, a newline follows on stderr
/// (not with `quiet`), and a quit signal restores the terminal, then ends
/// the process by that signal. `None`: end of input before any byte.
pub fn read_line(hidden: bool, quiet: bool) -> Option<SecretString> {
    let file = input()?;
    if hidden && stdin_tty() {
        let echo = larsal_platform::macos::echo_off(file.as_fd()).ok();
        // After a quit signal the read fails; dropping `echo` at the end of
        // this block restores the terminal and ends the process.
        let line = read_from(&mut Hidden {
            file,
            echo: echo.as_ref(),
        });
        drop(echo);
        if !quiet {
            let _ = io::stderr().write_all(b"\n");
        }
        line.ok().flatten()
    } else {
        read_from(&mut Hidden { file, echo: None }).ok().flatten()
    }
}

/// A password line: end of input is the empty line (INT-10.12 step 3).
pub fn read_secret(prompt_text: &str, quiet: bool) -> SecretString {
    prompt(prompt_text, quiet);
    read_line(true, quiet).unwrap_or_else(|| SecretString::new(String::new()))
}

/// One line without its LF or CR LF; nothing else is trimmed. The bytes are
/// read one at a time into a wiped buffer, so no other copy is left. A line
/// that is not UTF-8 gives the empty line. `None` at end of input with
/// nothing read.
fn read_from(input: &mut impl Read) -> io::Result<Option<SecretString>> {
    let mut buf = SecretBytes::zeroed(MAX_LINE + 1);
    let (mut len, mut any) = (0, false);
    loop {
        let slot = len.min(MAX_LINE);
        match input.read(&mut buf.expose_mut()[slot..=slot]) {
            Ok(0) => break,
            Ok(_) => {
                any = true;
                if buf.expose()[slot] == b'\n' {
                    break;
                }
                len = (len + 1).min(MAX_LINE + 1);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if !any {
        return Ok(None);
    }
    let mut line = &buf.expose()[..len.min(MAX_LINE)];
    if let Some(rest) = line.strip_suffix(b"\r") {
        line = rest;
    }
    Ok(Some(SecretString::new(
        String::from_utf8(line.to_vec()).unwrap_or_else(|e| {
            drop(SecretBytes::new(e.into_bytes()));
            String::new()
        }),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(input: &[u8]) -> Option<String> {
        read_from(&mut &input[..])
            .unwrap()
            .map(|s| s.expose().to_owned())
    }

    #[test]
    fn int10_12_line_ends_go_nothing_else_is_trimmed() {
        assert_eq!(line(b"demo-pass-1\n").as_deref(), Some("demo-pass-1"));
        assert_eq!(line(b"demo-pass-1\r\n").as_deref(), Some("demo-pass-1"));
        assert_eq!(line(b"demo-pass-1 \n").as_deref(), Some("demo-pass-1 "));
        assert_eq!(line(b"\n").as_deref(), Some(""));
        assert_eq!(line(b""), None);
        assert_eq!(line(b"\xff\n").as_deref(), Some(""));
    }

    #[test]
    fn int10_10_controls_are_escaped() {
        assert_eq!(escape("Demo\x1b[31mred"), "Demo\\x1b[31mred");
        assert_eq!(escape("a\tb\nc\x7f\u{9b}"), "a\tb\nc\\x7f\\u{9b}");
        assert!(matches!(escape("plain é"), Cow::Borrowed(_)));
    }
}
