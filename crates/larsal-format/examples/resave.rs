//! Opens a demo vault and saves it as version 4 to a new path (E3-S7; the
//! G4 interop check runs the reference CLI on the result).
//!
//! Usage: `echo demo-pass-5 | cargo run -q -p larsal-format --example resave -- testdata/rich-v4.larsalvault /tmp/out.larsalvault [key file]`
//! The password is read from the first line of stdin (an empty line means no
//! password); the optional third argument is a key file. The output path must
//! not exist yet, so a vault is never overwritten. Demo vaults only.

use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved, open, save};
use std::error::Error;
use std::io::Write;

fn main() -> Result<(), Box<dyn Error>> {
    let usage = "usage: resave <vault> <new vault> [key file] < password";
    let mut args = std::env::args().skip(1);
    let from = args.next().ok_or(usage)?;
    let to = args.next().ok_or(usage)?;
    let file = std::fs::read(&from)?;

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    // Moved into the secret type, not copied, so no plain copy is left behind.
    line.truncate(line.trim_end_matches(['\r', '\n']).len());
    let password = (!line.is_empty()).then(|| SecretString::new(line));

    let key = match args.next() {
        Some(path) => Some(larsal_format::keyfile::read_key_file(
            std::fs::File::open(path)?,
            &Limits::DEFAULT,
        )?),
        None => None,
    };
    let creds = Credentials {
        password: password.as_ref(),
        key_file: key.as_ref(),
        ..Default::default()
    };
    // A fixed AES speed record so the cost check needs no calibration run.
    let mut host = Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1000,
        }),
    };
    let opened = match open(&file, &creds, &mut host, &Limits::DEFAULT, None)? {
        Opened::Vault(v) => v,
        Opened::Ask(_) => return Err("the key settings of this vault need a yes first".into()),
    };
    let saved = match save(
        &opened.vault,
        &creds,
        Some(&opened.key),
        &mut host,
        &Limits::DEFAULT,
        None,
    )? {
        Saved::File(f) => f,
        Saved::Ask(_) => return Err("the key settings of this vault need a yes first".into()),
    };
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&to)?;
    out.write_all(&saved.bytes)?;
    out.sync_all()?;
    let h = &opened.header;
    println!(
        "{from} (version {}.{}) -> {to} (version {}.{}, {} bytes)",
        h.major,
        h.minor,
        saved.version.major,
        saved.version.minor,
        saved.bytes.len()
    );
    Ok(())
}
