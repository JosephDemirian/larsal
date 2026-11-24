//! Reads and writes unsigned share containers, so the reference CLI can be
//! checked against Larsal both ways (E11-S2; INT-08.8, INT-08.9).
//!
//! Usage (demo vaults only):
//! - `echo <share password> | cargo run -q -p larsal-share --example share -- read <container>`
//!   opens a container (unsigned or zip) with the share key and prints its
//!   name, version, groups and entries (title, user name). It prints no
//!   password (AGENTS rule 4); `larsal show -s` reads those of an unsigned
//!   container.
//! - `printf '%s\n%s\n' <vault password> <share password> | cargo run -q -p larsal-share --example share -- export <vault> <group> <new container> [flat]`
//!   writes the container of `<group>` (32 hex digits, or a group name: the
//!   first in tree order) of `<vault>`; `flat` leaves its subgroups out
//!   (KeepGroups off). The output path must not exist yet.
//!
//! An empty share password line is the empty password, which is a password
//! (INT-08.6); an empty vault password line means no password.

use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, open};
use larsal_model::{Group, Time, Uuid};
use larsal_share::container;
use std::error::Error;

fn line() -> Result<SecretString, Box<dyn Error>> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line.truncate(line.trim_end_matches(['\r', '\n']).len());
    Ok(SecretString::new(line))
}

/// A fixed AES speed record so the cost check needs no calibration run.
fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: None,
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1000,
        }),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn print(g: &Group, depth: usize) {
    let pad = "  ".repeat(depth);
    println!("{pad}group {} {}", hex(&g.uuid.0), g.name);
    for e in &g.entries {
        println!(
            "{pad}  entry {} title={} user={}",
            hex(&e.uuid.0),
            e.value("Title"),
            e.value("UserName")
        );
    }
    for c in &g.groups {
        print(c, depth + 1);
    }
}

fn find(root: &Group, wanted: &str) -> Option<Uuid> {
    root.subtree()
        .into_iter()
        .find(|g| hex(&g.uuid.0) == wanted.to_ascii_lowercase() || g.name == wanted)
        .map(|g| g.uuid)
}

fn main() -> Result<(), Box<dyn Error>> {
    let usage =
        "usage: share read <container> | share export <vault> <group> <new container> [flat]";
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["read", file] => {
            let password = line()?;
            let opened =
                container::open_file(file.as_ref(), &password, &mut host(), &Limits::DEFAULT)
                    .map_err(|e| e.to_string())?;
            let v = &opened.vault;
            let h = &opened.header;
            println!("name {}", v.meta.name);
            println!("version {}.{}", h.major, h.minor);
            print(&v.root, 0);
        }
        ["export", vault, group, to, rest @ ..] if rest.is_empty() || rest == ["flat"] => {
            if std::fs::exists(to)? {
                return Err(format!("{to} exists; pick a new path").into());
            }
            let vault_password = line()?;
            let share_password = line()?;
            let creds = Credentials {
                password: (!vault_password.is_empty()).then_some(&vault_password),
                ..Default::default()
            };
            let file = std::fs::read(vault)?;
            let opened = match open(&file, &creds, &mut host(), &Limits::DEFAULT, None)? {
                Opened::Vault(v) => v,
                Opened::Ask(_) => {
                    return Err("the key settings of this vault need a yes first".into());
                }
            };
            let source = &opened.vault;
            let id = find(&source.root, group).ok_or("no such group")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let now = Time::from_unix(i64::try_from(now)?).ok_or("clock out of range")?;
            let c =
                container::build(id, rest.is_empty(), source, now).map_err(|e| e.to_string())?;
            container::write_file(
                to.as_ref(),
                &c,
                &share_password,
                &mut host(),
                &Limits::DEFAULT,
                &[],
            )
            .map_err(|e| e.to_string())?;
            println!("{to}: container of {} ({})", c.meta.name, hex(&id.0));
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}
