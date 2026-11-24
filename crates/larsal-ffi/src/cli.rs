//! The window app's command line (APP-09.2 to APP-09.6, APP-09.16): flags F01
//! to F11, help, version, debug info, file arguments and password lines.
//! No flag takes a secret as its value (APP-09.18).

use larsal_crypto::secret::{SecretBytes, SecretString};
use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

/// The flags of one launch, F01 to F11.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// F01, as given.
    pub files: Vec<OsString>,
    /// F02 `--config`.
    pub config: Option<PathBuf>,
    /// F03 `--local-config`.
    pub local_config: Option<PathBuf>,
    /// F04 `--lock`.
    pub lock: bool,
    /// F05 `--key-file`.
    pub key_file: Option<PathBuf>,
    /// F06 `--password-stdin`.
    pub password_stdin: bool,
    /// F07 `--allow-screen-capture` (APP-10.5, `start::allows_screen_capture`).
    pub allow_screen_capture: bool,
    /// F08 `--minimized` (applied in E5-S9).
    pub minimized: bool,
    /// F09 `--debug-info`.
    pub debug_info: bool,
    /// F10 `-h`, `--help`.
    pub help: bool,
    /// F11 `-v`, `--version`.
    pub version: bool,
}

/// A command line Larsal does not accept (M09-09).
#[derive(Debug, PartialEq, Eq)]
pub enum FlagError {
    /// An unknown flag, as given.
    Unknown(String),
    /// F02, F03 or F05 without a value.
    MissingValue(String),
}

impl FlagError {
    /// M09-09: names the flag, then points to `--help`.
    #[must_use]
    pub fn message(&self) -> String {
        let first = match self {
            Self::Unknown(flag) => format!("Unknown flag: {flag}."),
            Self::MissingValue(flag) => format!("The flag {flag} needs a value."),
        };
        format!("{first} Run Larsal --help for the list of flags.")
    }
}

/// Reads the arguments after the program name. Long flags take a value as
/// `--flag value` or `--flag=value`; flags and files may be mixed; `--` ends
/// the flags. The reference spellings are hidden aliases (D-APP09-1).
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Flags, FlagError> {
    let mut flags = Flags::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(text) = arg.to_str() else {
            // Not UTF-8: a file name, unless it looks like a flag.
            if arg.as_encoded_bytes().starts_with(b"-") && arg.len() > 1 {
                return Err(FlagError::Unknown(arg.to_string_lossy().into_owned()));
            }
            flags.files.push(arg);
            continue;
        };
        if text == "--" {
            flags.files.extend(args);
            break;
        }
        if !text.starts_with('-') || text == "-" {
            flags.files.push(arg);
            continue;
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (text, None),
        };
        let slot = match name {
            "--config" => Some(&mut flags.config),
            "--local-config" | "--localconfig" => Some(&mut flags.local_config),
            "--key-file" | "--keyfile" => Some(&mut flags.key_file),
            _ => None,
        };
        if let Some(slot) = slot {
            let value = match inline {
                Some(value) => Some(OsString::from(value)),
                None => args.next(),
            };
            match value {
                Some(value) if !value.is_empty() => *slot = Some(PathBuf::from(value)),
                _ => return Err(FlagError::MissingValue(name.to_string())),
            }
            continue;
        }
        let switch = match (name, inline) {
            ("--lock", None) => &mut flags.lock,
            ("--password-stdin" | "--pw-stdin", None) => &mut flags.password_stdin,
            ("--allow-screen-capture" | "--allow-screencapture", None) => {
                &mut flags.allow_screen_capture
            }
            ("--minimized", None) => &mut flags.minimized,
            ("--debug-info", None) => &mut flags.debug_info,
            ("-h" | "--help", None) => &mut flags.help,
            ("-v" | "--version", None) => &mut flags.version,
            _ => return Err(FlagError::Unknown(text.to_string())),
        };
        *switch = true;
    }
    Ok(flags)
}

/// F11 output.
#[must_use]
pub fn version() -> String {
    format!("Larsal {}", env!("CARGO_PKG_VERSION"))
}

/// F10 output: every flag of the table, no aliases.
pub const HELP: &str = "\
Larsal keeps your passwords in encrypted vault files.

Usage: Larsal [flags] [FILE ...]

  FILE ...                  Vault files to open.
  --config PATH             Use PATH as the settings file.
  --local-config PATH       Use PATH as the local settings file of this Mac.
  --lock                    Lock every open vault of the running Larsal, then exit.
  --key-file PATH           Use the key file PATH for the files to open.
  --password-stdin          Read one password line from standard input for each file to open.
  --allow-screen-capture    Allow screen capture while Larsal runs.
  --minimized               Start minimized.
  --debug-info              Print build information and exit.
  -h, --help                Print this help and exit.
  -v, --version             Print the version and exit.
  --                        Read every later argument as a file.
";

/// The crypto crates Larsal uses, with their pinned versions, except the two
/// behind the OS random source: only larsal-crypto's random module may name those
/// (AT-B04), so [`crypto_crates`] adds them from there. A test keeps the whole
/// list equal to larsal-crypto's dependencies and the workspace pins.
const CRYPTO_CRATES: &[(&str, &str)] = &[
    ("aes", "0.9.3"),
    ("aes-gcm", "0.11.1"),
    ("argon2", "0.6.0"),
    ("base64ct", "1.8.3"),
    ("bcrypt-pbkdf", "0.11.0"),
    ("cbc", "0.2.1"),
    ("chacha20", "0.10.2"),
    ("ed25519-dalek", "3.0.0"),
    ("hkdf", "0.13.0"),
    ("hmac", "0.13.0"),
    ("hpke", "0.14.1"),
    ("p256", "0.14.0"),
    ("pbkdf2", "0.13.0"),
    ("salsa20", "0.11.0"),
    ("sha1", "0.11.0"),
    ("sha2", "0.11.1"),
    ("ssh-key", "0.7.0-rc.11"),
    ("subtle", "2.6.1"),
    ("twofish", "0.8.0"),
    ("x25519-dalek", "3.0.0"),
    ("zeroize", "1.9.1"),
];

/// Every crypto crate Larsal uses, with its pinned version, sorted by name.
fn crypto_crates() -> Vec<(&'static str, &'static str)> {
    let mut all = [CRYPTO_CRATES, &larsal_crypto::random::SOURCE_CRATES].concat();
    all.sort_unstable();
    all
}

/// F09 output (APP-09.4). Never a path, a settings value or vault content.
#[must_use]
pub fn debug_info() -> String {
    use larsal_platform::macos;
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let kernel = macos::kernel().map_or_else(|_| "unknown".into(), |(n, r)| format!("{n} {r}"));
    let crypto: Vec<String> = crypto_crates()
        .iter()
        .map(|(n, v)| format!("{n} {v}"))
        .collect();
    // The source revision line comes when the build knows it (no git yet).
    format!(
        "{}\nBuild type: {build}\nShell: SwiftUI (native)\nWeb engine: none\n\
         Debugging mode: {}\nOperating system: macOS {}\nCPU architecture: {}\n\
         Kernel: {kernel}\nFeatures built in: none\nCrypto crates: {}\n",
        version(),
        if cfg!(debug_assertions) { "on" } else { "off" },
        macos::os_version(),
        std::env::consts::ARCH,
        crypto.join(", "),
    )
}

/// F01 (APP-09.6): the arguments that name an existing regular file (symbolic
/// links followed), in order, made absolute against the current folder.
/// Others are dropped without a message.
#[must_use]
pub fn existing_files(files: &[OsString]) -> Vec<PathBuf> {
    files
        .iter()
        .filter(|f| std::fs::metadata(f).is_ok_and(|m| m.is_file()))
        .filter_map(|f| std::path::absolute(f).ok())
        .collect()
}

/// Longest password line kept, in bytes; the rest of a longer line is read and dropped.
const MAX_PASSWORD: usize = 65_536;

/// F06 (APP-09.16): one password line from standard input for each of
/// `count` files. Prints M09-08 before each line; when standard input is a
/// terminal, echo is off while the line is typed, and a quit signal there
/// ends Larsal only after echo is back on. A missing line, or a read error,
/// gives an empty password.
#[must_use]
pub fn read_passwords(count: usize) -> Vec<SecretString> {
    // An unbuffered handle: std's stdin buffer would keep later lines unwiped.
    let input = std::fs::File::open("/dev/stdin");
    (0..count)
        .map(|_| {
            print!("Vault password: ");
            let _ = io::stdout().flush();
            let line = match &input {
                Ok(file) => {
                    use std::os::fd::AsFd;
                    let echo = if file.is_terminal() {
                        larsal_platform::macos::echo_off(file.as_fd()).ok()
                    } else {
                        None
                    };
                    // After a quit signal the read fails; dropping `echo` at
                    // the end of this block restores the terminal and ends Larsal.
                    read_password_line(&mut Prompt {
                        file,
                        echo: echo.as_ref(),
                    })
                }
                Err(_) => Ok(SecretString::new(String::new())),
            };
            eprintln!();
            line.unwrap_or_else(|_| SecretString::new(String::new()))
        })
        .collect()
}

/// Standard input at the F06 prompt: with echo off, each read first waits for
/// input and fails once a quit signal has arrived.
struct Prompt<'a> {
    file: &'a std::fs::File,
    echo: Option<&'a larsal_platform::macos::EchoOff<'a>>,
}

impl Read for Prompt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(echo) = self.echo {
            echo.wait_for_input()?;
        }
        self.file.read(buf)
    }
}

/// One line from `input`, without its LF or CRLF; nothing else is trimmed.
/// End of input gives what was read so far (empty at once). The bytes are read
/// one at a time into a wiped buffer, so no other copy is left behind. A line
/// that is not UTF-8 gives an empty password.
pub fn read_password_line(input: &mut impl Read) -> io::Result<SecretString> {
    // One spare byte past the limit: where the rest of a long line is read and dropped.
    let mut buf = SecretBytes::zeroed(MAX_PASSWORD + 1);
    let mut len = 0;
    loop {
        let slot = len.min(MAX_PASSWORD);
        match input.read(&mut buf.expose_mut()[slot..=slot]) {
            Ok(0) => break,
            Ok(_) if buf.expose()[slot] == b'\n' => break,
            Ok(_) => len = (len + 1).min(MAX_PASSWORD + 1),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut line = &buf.expose()[..len.min(MAX_PASSWORD)];
    if let Some(rest) = line.strip_suffix(b"\r") {
        line = rest;
    }
    // to_vec allocates the exact length once; the String takes it without copying.
    Ok(SecretString::new(
        String::from_utf8(line.to_vec()).unwrap_or_else(|e| {
            drop(SecretBytes::new(e.into_bytes()));
            String::new()
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn flags(list: &[&str]) -> Flags {
        parse(args(list)).unwrap()
    }

    #[test]
    fn app09_2_values_take_both_forms_and_files_mix_with_flags() {
        let f = flags(&[
            "a",
            "--config",
            "/s1",
            "b",
            "--local-config=/s2",
            "--key-file",
            "k",
        ]);
        assert_eq!(f.files, args(&["a", "b"]));
        assert_eq!(f.config, Some(PathBuf::from("/s1")));
        assert_eq!(f.local_config, Some(PathBuf::from("/s2")));
        assert_eq!(f.key_file, Some(PathBuf::from("k")));
    }

    #[test]
    fn app09_2_reference_spellings_are_aliases() {
        let f = flags(&[
            "--localconfig",
            "/l",
            "--keyfile=/k",
            "--pw-stdin",
            "--allow-screencapture",
        ]);
        assert_eq!(f.local_config, Some(PathBuf::from("/l")));
        assert_eq!(f.key_file, Some(PathBuf::from("/k")));
        assert!(f.password_stdin && f.allow_screen_capture);
        let all = flags(&[
            "--lock",
            "--password-stdin",
            "--allow-screen-capture",
            "--minimized",
            "--debug-info",
            "-h",
            "-v",
        ]);
        assert!(all.lock && all.password_stdin && all.allow_screen_capture && all.minimized);
        assert!(all.debug_info && all.help && all.version);
    }

    #[test]
    fn app09_2_unknown_flag_and_missing_value_give_m09_09() {
        for (list, want) in [
            (&["--bogus"][..], FlagError::Unknown("--bogus".into())),
            (
                &["--password", "x"][..],
                FlagError::Unknown("--password".into()),
            ),
            (&["--lock=yes"][..], FlagError::Unknown("--lock=yes".into())),
            (&["-vh"][..], FlagError::Unknown("-vh".into())),
            (
                &["--key-file"][..],
                FlagError::MissingValue("--key-file".into()),
            ),
            (
                &["--config="][..],
                FlagError::MissingValue("--config".into()),
            ),
            (
                &["a", "--localconfig"][..],
                FlagError::MissingValue("--localconfig".into()),
            ),
        ] {
            assert_eq!(parse(args(list)), Err(want), "{list:?}");
        }
        let text = FlagError::Unknown("--bogus".into()).message();
        assert_eq!(
            text,
            "Unknown flag: --bogus. Run Larsal --help for the list of flags."
        );
    }

    #[test]
    fn app09_2_d_double_dash_ends_the_flags() {
        let f = flags(&["--minimized", "--", "--lock", "-", "--bogus"]);
        assert!(f.minimized && !f.lock);
        assert_eq!(f.files, args(&["--lock", "-", "--bogus"]));
    }

    #[test]
    fn app09_3_help_lists_every_flag_and_no_alias() {
        for flag in [
            "FILE",
            "--config",
            "--local-config",
            "--lock",
            "--key-file",
            "--password-stdin",
            "--allow-screen-capture",
            "--minimized",
            "--debug-info",
            "-h, --help",
            "-v, --version",
        ] {
            assert!(HELP.contains(flag), "{flag}");
        }
        for alias in [
            "--localconfig",
            "--keyfile",
            "--pw-stdin",
            "--allow-screencapture",
        ] {
            assert!(!HELP.contains(alias), "{alias}");
        }
        assert_eq!(version(), format!("Larsal {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn app09_4_crypto_list_matches_larsal_crypto_and_the_pins() {
        let root =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
                .unwrap();
        let crypto = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../larsal-crypto/Cargo.toml"
        ))
        .unwrap();
        let deps = crypto
            .split("[dependencies]")
            .nth(1)
            .unwrap()
            .split("\n[")
            .next()
            .unwrap();
        let mut used: Vec<&str> = deps
            .lines()
            .filter_map(|l| l.split(['.', ' ']).next())
            .filter(|n| !n.is_empty() && !n.starts_with('#'))
            .collect();
        used.sort_unstable();
        let all = crypto_crates();
        let listed: Vec<&str> = all.iter().map(|(n, _)| *n).collect();
        assert_eq!(listed, used);
        for (name, version) in all {
            let pin = root
                .lines()
                .find(|l| l.starts_with(&format!("{name} = ")))
                .unwrap();
            assert!(pin.contains(&format!("\"={version}\"")), "{pin}");
        }
    }

    #[test]
    fn app09_4_debug_info_has_no_path() {
        let text = debug_info();
        // F-166: the build this test runs in.
        let build = if cfg!(debug_assertions) {
            "Build type: debug"
        } else {
            "Build type: release"
        };
        for line in [
            build,
            "Operating system: macOS ",
            "CPU architecture: ",
            "Kernel: Darwin ",
            "Crypto crates: aes 0.9.3",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        assert!(!text.contains('/'), "{text}");
    }

    #[test]
    fn app09_6_keeps_existing_regular_files_made_absolute() {
        let dir = std::env::temp_dir().join(format!("larsal-ffi-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.larsalvault");
        std::fs::write(&file, b"demo").unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let kept = existing_files(&args(&[
            "a.larsalvault",
            "/nonexistent/none.larsalvault",
            dir.to_str().unwrap(),
        ]));
        assert_eq!(kept, vec![std::path::absolute("a.larsalvault").unwrap()]);
        assert!(kept[0].is_absolute());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn line(input: &[u8]) -> String {
        read_password_line(&mut &input[..])
            .unwrap()
            .expose()
            .to_string()
    }

    #[test]
    fn app09_16_line_ends_go_nothing_else_is_trimmed() {
        assert_eq!(line(b"demo-pass-a\n"), "demo-pass-a");
        assert_eq!(line(b"demo-pass-a\r\n"), "demo-pass-a");
        assert_eq!(line(b"demo-pass-a \n"), "demo-pass-a ");
        assert_eq!(line(b"\n"), "");
        assert_eq!(line(b""), "");
        assert_eq!(line(b"no-newline"), "no-newline");
        assert_eq!(line(b"\xff\xfe\n"), "");
    }

    #[test]
    fn app09_16_one_line_per_call_and_long_lines_are_cut() {
        let mut input: &[u8] = b"first\nsecond\n";
        assert_eq!(read_password_line(&mut input).unwrap().expose(), "first");
        assert_eq!(read_password_line(&mut input).unwrap().expose(), "second");
        assert_eq!(read_password_line(&mut input).unwrap().expose(), "");
        let mut long = vec![b'x'; MAX_PASSWORD + 10];
        long.extend_from_slice(b"\nnext\n");
        let mut input = &long[..];
        assert_eq!(read_password_line(&mut input).unwrap().len(), MAX_PASSWORD);
        assert_eq!(read_password_line(&mut input).unwrap().expose(), "next");
    }
}
