//! Prints the entry titles of a demo vault (Sprint 2 demo).
//!
//! Usage: `echo demo-pass-5 | cargo run -q -p app-format --example titles -- testdata/rich-v4.appvault`
//! The password is read from the first line of stdin (an empty line means no
//! password); an optional second argument is a key file. Demo vaults only.

use app_crypto::kdf::{Host, SpeedRecord};
use app_crypto::secret::SecretString;
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Opened, open};
use app_model::Group;
use std::error::Error;

const SHOW: usize = 25;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let vault_path = args
        .next()
        .ok_or("usage: titles <vault> [key file] < password")?;
    let file = std::fs::read(&vault_path)?;

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    // Moved into the secret type, not copied, so no plain copy is left behind.
    line.truncate(line.trim_end_matches(['\r', '\n']).len());
    let password = (!line.is_empty()).then(|| SecretString::new(line));

    let key = match args.next() {
        Some(path) => Some(app_format::keyfile::read_key_file(
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

    let (h, vault) = (&opened.header, &opened.vault);
    let mut rows = Vec::new();
    collect(&vault.root, "", &mut rows);
    println!(
        "{vault_path}: version {}.{}, {} entries",
        h.major,
        h.minor,
        rows.len()
    );
    for (group, title) in rows.iter().take(SHOW) {
        println!("  {group} / {title}");
    }
    if rows.len() > SHOW {
        println!("  ... and {} more", rows.len() - SHOW);
    }
    Ok(())
}

fn collect(group: &Group, parent: &str, rows: &mut Vec<(String, String)>) {
    let path = if parent.is_empty() {
        group.name.clone()
    } else {
        format!("{parent} / {}", group.name)
    };
    for e in &group.entries {
        rows.push((path.clone(), e.value("Title").to_owned()));
    }
    for g in &group.groups {
        collect(g, &path, rows);
    }
}
