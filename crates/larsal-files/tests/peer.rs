//! FIL-01-T01, FIL-03-T18, story check 2: files made by the published reference
//! command line tool open here, and Larsal's open in it, in both modes. A default run
//! shows the check as ignored, with its reason. A set path always runs, so a mistyped
//! one fails.
//!
//! Point `LARSAL_AGE_TOOL` at the binary of a private copy of the tool, by its whole
//! path, with `age-keygen` and `age-plugin-batchpass` from the same archive beside it.
//! The tool is never installed and never committed. The demo keys are fixed here.
//! The passphrase route needs no terminal: `-j batchpass` is the tool's own plugin
//! route, and it takes the passphrase from `AGE_PASSPHRASE`. The test puts the tool's
//! folder on the tool's `PATH` for that and clears the rest of its environment.
//! This test starts a process because that is what a peer check is: no product code
//! ever starts one.

mod common;

use common::open_all;
use larsal_crypto::secret::SecretString;
use larsal_files::{Identities, Lock, Recipient, Unlock, encrypt_stream};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const ID: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const RECIPIENT: &str = "age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72";
const PHRASE: &str = "demo passphrase for the peer check";

fn demo_payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("binary", (0..=255u8).cycle().take(70_000).collect()),
        ("image-like", b"\xFF\xD8\xFF\xE1Exif\0\0demo".repeat(5000)),
        ("exact chunk", vec![0x5A; 65_536]),
    ]
}

fn command(tool: &Path, args: &[&str], dir: &Path, phrase: Option<&str>) -> Command {
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", tool.parent().unwrap());
    if let Some(phrase) = phrase {
        command.env("AGE_PASSPHRASE", phrase);
    }
    command
}

fn run(tool: &Path, args: &[&str], dir: &Path, phrase: Option<&str>) {
    let status = command(tool, args, dir, phrase).status().unwrap();
    assert!(status.success(), "the tool failed on {args:?}");
}

fn seal(plain: &[u8], lock: &Lock<'_>) -> Vec<u8> {
    let mut sealed = Vec::new();
    encrypt_stream(&mut &*plain, &mut sealed, lock, &mut |_, _| true).unwrap();
    sealed
}

#[test]
#[ignore = "needs LARSAL_AGE_TOOL, a private copy of the published tool with age-keygen and age-plugin-batchpass beside it, never committed; story check 2 is shown only by that run; tests/peer.rs says how"]
fn fil01_t01_fil03_t18_files_open_both_ways_with_the_reference_tool() {
    let tool = std::env::var_os("LARSAL_AGE_TOOL").expect("LARSAL_AGE_TOOL is not set");
    both_ways(Path::new(&tool), "asked");
}

#[test]
fn fil03_t18_a_set_tool_path_runs_or_fails_loudly() {
    if let Some(tool) = std::env::var_os("LARSAL_AGE_TOOL") {
        both_ways(Path::new(&tool), "set");
    }
}

fn both_ways(tool: &Path, run_name: &str) {
    assert!(tool.is_file(), "no tool at {}", tool.display());
    let dir = std::env::temp_dir().join(format!(
        "larsal-files-peer-{run_name}-{}",
        std::process::id()
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let key_file = dir.join("demo.key");
    fs::write(&key_file, format!("{ID}\n")).unwrap();
    let key_path = key_file.to_str().unwrap();
    let keys = Identities::single(&SecretString::from(ID)).unwrap();
    let to = [Recipient::parse(RECIPIENT).unwrap()];
    let phrase = SecretString::from(PHRASE);
    let by_phrase = Unlock::Passphrase(&phrase);

    for (name, plain) in demo_payloads() {
        let plain_path = dir.join(format!("{name}.plain"));
        fs::write(&plain_path, &plain).unwrap();
        let plain_text = plain_path.to_str().unwrap();

        for (form, extra) in [("binary", &[][..]), ("armor", &["--armor"][..])] {
            // The tool writes to a recipient; Larsal reads, binary and armor.
            let sealed = dir.join(format!("{name}.{form}.age"));
            let mut args = vec!["--encrypt", "--recipient", RECIPIENT];
            args.extend_from_slice(extra);
            args.extend_from_slice(&["-o", sealed.to_str().unwrap(), plain_text]);
            run(tool, &args, &dir, None);
            let opened = open_all(&fs::read(&sealed).unwrap(), &Unlock::Identities(&keys)).unwrap();
            assert_eq!(opened.expose(), &plain[..], "{name} {form} from the tool");

            // The tool writes under a passphrase; Larsal reads, binary and armor.
            let sealed = dir.join(format!("{name}.{form}.phrase.age"));
            let mut args = vec!["--encrypt", "-j", "batchpass"];
            args.extend_from_slice(extra);
            args.extend_from_slice(&["-o", sealed.to_str().unwrap(), plain_text]);
            run(tool, &args, &dir, Some(PHRASE));
            let opened = open_all(&fs::read(&sealed).unwrap(), &by_phrase).unwrap();
            assert_eq!(opened.expose(), &plain[..], "{name} {form} phrase, tool");
        }

        // Larsal writes to a recipient; the tool reads.
        let ours = dir.join(format!("{name}.larsal.age"));
        fs::write(&ours, seal(&plain, &Lock::Recipients(&to))).unwrap();
        let back = dir.join(format!("{name}.back"));
        let (ours_text, back_text) = (ours.to_str().unwrap(), back.to_str().unwrap());
        run(
            tool,
            &[
                "--decrypt",
                "--identity",
                key_path,
                "-o",
                back_text,
                ours_text,
            ],
            &dir,
            None,
        );
        assert_eq!(fs::read(&back).unwrap(), plain, "{name} to the tool");

        // Larsal writes under a passphrase, at the cost new files get; the tool reads.
        let ours = dir.join(format!("{name}.larsal.phrase.age"));
        fs::write(&ours, seal(&plain, &Lock::Passphrase(&phrase))).unwrap();
        let back = dir.join(format!("{name}.phrase.back"));
        let (ours_text, back_text) = (ours.to_str().unwrap(), back.to_str().unwrap());
        run(
            tool,
            &["--decrypt", "-j", "batchpass", "-o", back_text, ours_text],
            &dir,
            Some(PHRASE),
        );
        assert_eq!(
            fs::read(&back).unwrap(),
            plain,
            "{name} phrase, to the tool"
        );
    }

    two_recipients(tool, &dir, &keys, to[0]);
    key_files(tool, &dir);
    fs::remove_dir_all(&dir).unwrap();
}

/// Two recipients, both ways: each key opens the file. The second key is the tool's.
fn two_recipients(tool: &Path, dir: &Path, keys: &Identities, first: Recipient) {
    let (second_key_path, second) = new_key(tool, dir, "second");
    let second_keys =
        Identities::read_key_file(&mut fs::File::open(&second_key_path).unwrap(), None).unwrap();
    let plain = b"demo for two recipients\n";
    let plain_path = dir.join("two.plain");
    fs::write(&plain_path, plain).unwrap();

    let sealed = dir.join("two.tool.age");
    run(
        tool,
        &[
            "--encrypt",
            "--recipient",
            &first.to_text().unwrap(),
            "--recipient",
            &second.to_text().unwrap(),
            "-o",
            sealed.to_str().unwrap(),
            plain_path.to_str().unwrap(),
        ],
        dir,
        None,
    );
    let data = fs::read(&sealed).unwrap();
    for each in [keys, &second_keys] {
        let opened = open_all(&data, &Unlock::Identities(each)).unwrap();
        assert_eq!(opened.expose(), plain, "two recipients, from the tool");
    }

    let ours = dir.join("two.larsal.age");
    fs::write(&ours, seal(plain, &Lock::Recipients(&[first, second]))).unwrap();
    let first_key = dir.join("demo.key");
    for (round, key) in [first_key, second_key_path].iter().enumerate() {
        let back = dir.join(format!("two.back.{round}"));
        run(
            tool,
            &[
                "--decrypt",
                "--identity",
                key.to_str().unwrap(),
                "-o",
                back.to_str().unwrap(),
                ours.to_str().unwrap(),
            ],
            dir,
            None,
        );
        assert_eq!(
            fs::read(&back).unwrap(),
            plain,
            "two recipients, to the tool"
        );
    }
}

/// A new key made by the tool's own key maker, and its recipient.
fn new_key(tool: &Path, dir: &Path, name: &str) -> (std::path::PathBuf, Recipient) {
    let keygen = tool.with_file_name("age-keygen");
    assert!(keygen.is_file(), "no age-keygen beside the tool");
    let key = dir.join(format!("{name}.key"));
    run(&keygen, &["-o", key.to_str().unwrap()], dir, None);
    let out = command(&keygen, &["-y", key.to_str().unwrap()], dir, None)
        .output()
        .unwrap();
    assert!(out.status.success(), "age-keygen -y");
    let text = String::from_utf8(out.stdout).unwrap();
    (key, Recipient::parse(text.trim()).unwrap())
}

/// The tool's key file as it comes, and the same file under a passphrase.
fn key_files(tool: &Path, dir: &Path) {
    let (key, recipient) = new_key(tool, dir, "made");
    let plain = b"demo for a key file\n";
    let sealed = seal(plain, &Lock::Recipients(&[recipient]));

    let keys = Identities::read_key_file(&mut fs::File::open(&key).unwrap(), None).unwrap();
    let opened = open_all(&sealed, &Unlock::Identities(&keys)).unwrap();
    assert_eq!(opened.expose(), plain, "the tool's key file");

    let locked = dir.join("made.key.age");
    run(
        tool,
        &[
            "--encrypt",
            "-j",
            "batchpass",
            "-o",
            locked.to_str().unwrap(),
            key.to_str().unwrap(),
        ],
        dir,
        Some(PHRASE),
    );
    let phrase = SecretString::from(PHRASE);
    let keys =
        Identities::read_key_file(&mut fs::File::open(&locked).unwrap(), Some(&phrase)).unwrap();
    assert!(!keys.from_weak_file());
    let opened = open_all(&sealed, &Unlock::Identities(&keys)).unwrap();
    assert_eq!(
        opened.expose(),
        plain,
        "the tool's key file under a passphrase"
    );
}
