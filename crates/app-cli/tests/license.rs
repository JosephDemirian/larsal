//! E14-S2: App's license (decision D2, LD-262 (3)). Fails when LICENSE is not
//! the exact GPL-3.0 text of https://www.gnu.org/licenses/gpl-3.0.txt (by
//! SHA-256), when one of App's crates has no license field or is not
//! `publish = false`, or when a place that shows the word list's attribution
//! drifts from `ATTRIBUTION`. The one crate under another license is the sync
//! server, AGPL-3.0-or-later (LD-262 (3), LD-303 (4); E16-S3), whose
//! crates/app-server/LICENSE must be the exact AGPL-3.0 text of
//! https://www.gnu.org/licenses/agpl-3.0.txt (LD-335).
#![forbid(unsafe_code)]

use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// SHA-256 of https://www.gnu.org/licenses/gpl-3.0.txt, fetched 2026-10-31.
const GPL_3_0_SHA256: &str = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986";
/// SHA-256 of https://www.gnu.org/licenses/agpl-3.0.txt, fetched 2026-11-01.
const AGPL_3_0_SHA256: &str = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0";
const GPL: &str = "license = \"GPL-3.0-or-later\"";
const AGPL: &str = "license = \"AGPL-3.0-or-later\"";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The trimmed lines of one `[section]` table of a manifest.
fn table<'a>(toml: &'a str, section: &str) -> Vec<&'a str> {
    let mut inside = false;
    let mut lines = Vec::new();
    for line in toml.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == section;
        } else if inside {
            lines.push(line);
        }
    }
    lines
}

/// The SHA-256 of a file, in lower-case hex.
fn sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    app_crypto::hash::sha256(&[&bytes])
        .expose()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[test]
fn e14_2_license_is_the_exact_gpl_3_0_text() {
    assert_eq!(
        sha256_hex(&root().join("LICENSE")),
        GPL_3_0_SHA256,
        "LICENSE is not the GPL-3.0 text from gnu.org"
    );
}

#[test]
fn e16_3_server_license_is_the_exact_agpl_3_0_text() {
    assert_eq!(
        sha256_hex(&root().join("crates/app-server/LICENSE")),
        AGPL_3_0_SHA256,
        "crates/app-server/LICENSE is not the AGPL-3.0 text from gnu.org"
    );
}

#[test]
fn e14_2_every_crate_of_app_says_gpl_3_0_or_later() {
    let root = root();
    let workspace = read(&root.join("Cargo.toml"));
    let package = table(&workspace, "[workspace.package]");
    assert!(package.contains(&GPL), "Cargo.toml [workspace.package]");
    assert!(
        package.contains(&"publish = false"),
        "Cargo.toml [workspace.package]: publish = false"
    );
    let fuzz = read(&root.join("fuzz/Cargo.toml"));
    assert!(table(&fuzz, "[package]").contains(&GPL), "fuzz/Cargo.toml");
    // Every folder in crates/ is a workspace member (members = ["crates/*"]).
    let mut crates = 0;
    for entry in fs::read_dir(root.join("crates")).expect("crates/") {
        let dir = entry.expect("crates/ entry").path();
        if dir.is_dir() {
            let manifest = dir.join("Cargo.toml");
            let toml = read(&manifest);
            let package = table(&toml, "[package]");
            let license = if dir.ends_with("app-server") {
                AGPL
            } else {
                "license.workspace = true"
            };
            assert!(
                package.contains(&license),
                "{}: no {license} in [package]",
                manifest.display()
            );
            assert!(
                package.contains(&"publish.workspace = true"),
                "{}: no publish.workspace = true in [package]",
                manifest.display()
            );
            crates += 1;
        }
    }
    assert!(crates >= 14, "only {crates} crates found");
}

#[test]
fn e14_2_the_license_and_word_list_notices_are_shown() {
    let attribution = app_core::generator::wordlist::ATTRIBUTION;
    let about = read(&root().join("macos/App/Resources/Credits.rtf"));
    assert!(
        about.contains(attribution),
        "About (Credits.rtf) lacks the word list attribution"
    );
    assert!(
        about.contains("GPL-3.0-or-later"),
        "About (Credits.rtf) lacks the license"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_app"))
        .arg("--license")
        .output()
        .expect("app --license");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    for needle in [
        attribution,
        "GPL-3.0-or-later",
        "NO WARRANTY",
        "THIRD-PARTY-NOTICES.md",
    ] {
        assert!(
            text.contains(needle),
            "app --license lacks {needle:?}:\n{text}"
        );
    }
}
