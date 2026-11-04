//! `app-server --data <folder> --port <number>`: App's sync server on
//! 127.0.0.1 (E16-S3). It prints its address and its certificate's
//! fingerprint, then serves until it is stopped. Demo data only: it is built
//! and run on this Mac, never hosted without the owner's yes (LD-262 (2)).
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: app-server --data <folder> --port <number>
  --data <folder>  the server's data folder; made at the first start (mode 0700)
  --port <number>  the port on 127.0.0.1 (1 to 65535)";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    data: PathBuf,
    port: u16,
}

/// Reads the flags; `Ok(None)` for `--help`. An argument that is not UTF-8
/// text is refused in words, never a panic (Rust rule 4).
fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    let words = args
        .iter()
        .map(|a| {
            a.to_str()
                .ok_or_else(|| format!("argument {a:?} is not UTF-8 text"))
        })
        .collect::<Result<Vec<&str>, String>>()?;
    let (mut data, mut port) = (None, None);
    let mut rest = words.into_iter();
    while let Some(flag) = rest.next() {
        match flag {
            "--help" | "-h" => return Ok(None),
            "--data" => data = Some(PathBuf::from(rest.next().ok_or("--data needs a folder")?)),
            "--port" => {
                let value = rest.next().ok_or("--port needs a number")?;
                port = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|p| *p != 0)
                        .ok_or("--port takes a number from 1 to 65535")?,
                );
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    match (data, port) {
        (Some(data), Some(port)) => Ok(Some(Options { data, port })),
        (None, _) => Err("--data is required".to_owned()),
        (_, None) => Err("--port is required".to_owned()),
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let options = match parse(&args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(problem) => {
            eprintln!("app-server: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // P14: tokio's current-thread runtime.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("app-server: cannot start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let run = runtime.block_on(async {
        let config = app_server::http::Config::default();
        let server = app_server::Server::start(&options.data, options.port, config).await?;
        println!("App sync server (demo): https://{}", server.address()?);
        println!(
            "Certificate fingerprint (SHA-256): {}",
            server.certificate().fingerprint()
        );
        server.serve().await
    });
    match run {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("app-server: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn flags() {
        let ok = parse(&args(&["--data", "/tmp/d", "--port", "8443"])).unwrap();
        assert_eq!(
            ok,
            Some(Options {
                data: PathBuf::from("/tmp/d"),
                port: 8443
            })
        );
        assert_eq!(parse(&args(&["--help"])), Ok(None));
        for bad in [
            &["--data", "/tmp/d"][..],
            &["--port", "1"],
            &["--data", "/tmp/d", "--port", "0"],
            &["--data", "/tmp/d", "--port", "65536"],
            &["--data", "/tmp/d", "--port", "x"],
            &["--data"],
            &["--listen", "0.0.0.0"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        // A folder name that is not UTF-8: refused in words.
        use std::os::unix::ffi::OsStringExt;
        let mut not_utf8 = args(&["--data", "", "--port", "8443"]);
        not_utf8[1] = OsString::from_vec(b"/tmp/\xff".to_vec());
        let problem = parse(&not_utf8).unwrap_err();
        assert_eq!(problem, r#"argument "/tmp/\xFF" is not UTF-8 text"#);
    }
}
