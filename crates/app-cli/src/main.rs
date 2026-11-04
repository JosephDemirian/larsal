//! The command line tool `app` (spec INT-10, story E12-S1).
//!
//! Guarantees:
//! - start-up in the order of INT-10.1: hardening first, then the arguments,
//!   help and version, the crypto self-test, the option checks, the command;
//! - exit code 0 or 1 only (D-INT10-2); stdout carries only data and success
//!   lines, stderr everything else (INT-10.6);
//! - no option or environment variable takes a secret (SR-13, INT-10.16);
//!   passwords are read without echo on a terminal and live only in wiping
//!   types; nothing secret is printed unless the command asks for it.
#![forbid(unsafe_code)]

mod args;
mod commands;
mod hwkey;
mod shell;
mod term;
mod vault;
mod zone;

use std::io::Write;
use std::process::ExitCode;

/// SR-07 (LD-133): every block Rust frees is zeroed before the system gets
/// it back, the copies of crates App does not control included.
#[global_allocator]
static ALLOC: app_platform::memory::Zeroing<std::alloc::System> =
    app_platform::memory::Zeroing(std::alloc::System);

fn main() -> ExitCode {
    // (1) Process hardening (APP-11.1), before arguments, stdin or files.
    app_platform::hardening::harden();
    let words: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = start(&words);
    let _ = std::io::stdout().flush();
    ExitCode::from(code)
}

fn start(words: &[String]) -> u8 {
    // (2) No App settings are read yet (INT-10.9; APP-01 comes with E5-S9).
    // (3) and (4): the top-level flags, the command, help.
    let Some(first) = words.first() else {
        print!("{}", args::overview());
        return 0;
    };
    match first.as_str() {
        "-h" | "--help" | "--help-all" => {
            print!("{}", args::overview());
            return 0;
        }
        "-v" | "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        "--debug-info" => {
            print!("{}", debug_info());
            return 0;
        }
        "--license" => {
            print!("{}", license_notice());
            return 0;
        }
        f if f.starts_with('-') => {
            term::err(&format!(
                "app: unknown option {f}. Run app help to see the commands."
            ));
            return 1;
        }
        _ => {}
    }
    let Some(cmd) = args::lookup(first, false) else {
        term::err(&format!(
            "app: there is no command {first}. Run app help to see the commands."
        ));
        return 1;
    };
    let p = match args::parse_or_report(cmd, &words[1..], false) {
        args::Outcome::Run(p) => p,
        args::Outcome::Help => return 0,
        args::Outcome::Failed => return 1,
    };
    if cmd.name == "help" {
        return u8::from(commands::run(&p, &mut None).is_err());
    }
    // (5) Crypto self-test (APP-11.10), before any prompt.
    if let Err(message) = self_test() {
        term::err(&message);
        return 1;
    }
    // (6) and (7): each command checks its options, then runs.
    let result = if cmd.name == "open" {
        shell::open(&p)
    } else {
        commands::run(&p, &mut None)
    };
    u8::from(result.is_err())
}

/// APP-11.10; `Err` holds M11-02. A debug build started with
/// `APP_TEST_SELF_TEST_FAIL` acts as if the SHA-256 check gave a wrong
/// answer (INT-10.1-a); release builds read no such variable.
fn self_test() -> Result<(), String> {
    let result = app_crypto::selftest::run();
    #[cfg(debug_assertions)]
    let result = if std::env::var_os("APP_TEST_SELF_TEST_FAIL").is_some() {
        Err(app_crypto::selftest::Check::Sha256)
    } else {
        result
    };
    result.map_err(|check| {
        format!(
            "App cannot start: a self-check of its encryption code failed. {} gave a wrong answer.",
            check.name()
        )
    })
}

/// The crypto crates of app-crypto with their pinned versions, except the
/// two behind the OS random source, which come from app-crypto itself
/// (AT-B04). A test keeps this list equal to app-crypto's dependencies.
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

fn crypto_crates() -> Vec<(&'static str, &'static str)> {
    let mut all = [CRYPTO_CRATES, &app_crypto::random::SOURCE_CRATES].concat();
    all.sort_unstable();
    all
}

/// F04 (INT-10.3, APP-09.4): build and system facts; never a path, a
/// setting or vault content.
/// E14-S2: App's license notice (GPL-3.0 section 0, "Appropriate Legal
/// Notices", in the form of the GNU coding standards' `--version` text), the
/// built-in word list's attribution, and where the full texts ship.
fn license_notice() -> String {
    format!(
        "App command line tool {}\n\
         Copyright (C) 2026 [Licensor legal name]\n\
         License GPL-3.0-or-later: GNU General Public License, version 3 or later,\n\
         <https://www.gnu.org/licenses/gpl-3.0.html>.\n\
         This is free software: you are free to change and share it under that license.\n\
         There is NO WARRANTY, to the extent permitted by law.\n\n\
         The license text (LICENSE) and the licenses of the third-party software in App\n\
         (THIRD-PARTY-NOTICES.md) ship with App: in App.app/Contents/Resources, and beside\n\
         this tool in a release folder.\n\n{}\n",
        env!("CARGO_PKG_VERSION"),
        app_core::generator::wordlist::ATTRIBUTION,
    )
}

fn debug_info() -> String {
    use app_platform::macos;
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
    format!(
        "App command line tool {}\nBuild type: {build}\nOperating system: macOS {}\n\
         CPU architecture: {}\nKernel: {kernel}\nFeatures built in: none\nCrypto crates: {}\n",
        env!("CARGO_PKG_VERSION"),
        macos::os_version(),
        std::env::consts::ARCH,
        crypto.join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int10_3_crypto_list_matches_app_crypto() {
        let crypto = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../app-crypto/Cargo.toml"
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
        let listed: Vec<&str> = crypto_crates().iter().map(|(n, _)| *n).collect();
        assert_eq!(listed, used);
        let root =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
                .unwrap();
        for (name, version) in crypto_crates() {
            let pin = root
                .lines()
                .find(|l| {
                    l.strip_prefix(name)
                        .is_some_and(|rest| rest.trim_start().starts_with('='))
                })
                .unwrap();
            assert!(pin.contains(&format!("\"={version}\"")), "{pin}");
        }
    }
}
