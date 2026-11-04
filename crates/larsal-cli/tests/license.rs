//! First-party license integrity, exhaustive manifest coverage and shipped notices.
#![forbid(unsafe_code)]

use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LICENSE_SHA256: &str = "d34eb24ac75b85beda2934911c76260d752de229c2b45e574d623afbdf4a1a7f";
const LICENSE_NAME: &str = "Larsal Source-Available License 1.0";

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

fn has_alternate_license(lines: &[&str]) -> bool {
    lines.iter().any(|line| {
        let key = line.split('=').next().unwrap_or_default().trim();
        matches!(
            key,
            "license" | "license.workspace" | "\"license\"" | "'license'"
        )
    })
}

/// The SHA-256 of a file, in lower-case hex.
fn sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    larsal_crypto::hash::sha256(&[&bytes])
        .expose()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[test]
fn e14_2_license_has_the_approved_terms_and_integrity() {
    let license = read(&root().join("LICENSE"));
    assert_eq!(sha256_hex(&root().join("LICENSE")), LICENSE_SHA256);
    for required in [
        LICENSE_NAME,
        "read, inspect, download and make unmodified",
        "compile the unmodified source code",
        "personal or private family use",
        "self-hosting solely",
        "customers or the public",
        "modify, adapt, translate or create derivative works",
        "sell, resell, rent, lease or sublicense",
        "competing product or service",
        "Nothing in this license limits rights granted by those third-party licenses.",
        "Nothing here revokes rights already granted under an earlier license",
        "not an open-source license",
        "NO WARRANTY",
    ] {
        assert!(license.contains(required), "license lacks {required:?}");
    }
}

#[test]
fn e16_3_server_uses_the_same_first_party_terms() {
    assert_eq!(
        sha256_hex(&root().join("crates/larsal-server/LICENSE")),
        LICENSE_SHA256
    );
}

#[test]
fn e14_2_every_first_party_crate_resolves_the_license_file() {
    let root = root();
    let workspace = read(&root.join("Cargo.toml"));
    let package = table(&workspace, "[workspace.package]");
    assert!(
        !has_alternate_license(&package),
        "workspace has an alternate grant"
    );
    assert!(
        package.contains(&"license-file = \"LICENSE\""),
        "Cargo.toml [workspace.package]"
    );
    assert!(
        package.contains(&"publish = false"),
        "Cargo.toml [workspace.package]: publish = false"
    );
    let fuzz = read(&root.join("fuzz/Cargo.toml"));
    assert!(
        !has_alternate_license(&table(&fuzz, "[package]")),
        "fuzz has an alternate grant"
    );
    assert!(
        table(&fuzz, "[package]").contains(&"license-file = \"../LICENSE\""),
        "fuzz/Cargo.toml"
    );
    // Every folder in crates/ is a workspace member (members = ["crates/*"]).
    let mut crates = 0;
    for entry in fs::read_dir(root.join("crates")).expect("crates/") {
        let dir = entry.expect("crates/ entry").path();
        if dir.is_dir() {
            let manifest = dir.join("Cargo.toml");
            let toml = read(&manifest);
            let package = table(&toml, "[package]");
            assert!(
                !has_alternate_license(&package),
                "{}: alternate grant",
                manifest.display()
            );
            let license = "license-file.workspace = true";
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
    let attribution = larsal_core::generator::wordlist::ATTRIBUTION;
    let about = read(&root().join("macos/Larsal/Resources/Credits.rtf"));
    assert!(
        about.contains(attribution),
        "About (Credits.rtf) lacks the word list attribution"
    );
    assert!(
        about.contains(LICENSE_NAME),
        "About (Credits.rtf) lacks the license"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_larsal"))
        .arg("--license")
        .output()
        .expect("larsal --license");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    for needle in [
        attribution,
        LICENSE_NAME,
        "NO WARRANTY",
        "THIRD-PARTY-NOTICES.md",
    ] {
        assert!(
            text.contains(needle),
            "larsal --license lacks {needle:?}:\n{text}"
        );
    }
}
