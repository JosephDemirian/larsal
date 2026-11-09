//! FIL-02's rows through the exports the Mac app calls, on the demo vault and
//! demo files only. Jobs are one at a time in a process, so these run in turn.

use super::*;
use crate::test_dir::TempDir;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

static SERIAL: StdMutex<()> = StdMutex::new(());

/// One test's turn. Dropped at the test's end, a failed one included, it drops
/// the test hooks no job took and revokes and waits for the job slot's last job,
/// so a red test never holds the tests after it (C2R5-03).
struct One(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Drop for One {
    fn drop(&mut self) {
        lock(&AT_WRITE).take();
        lock(&BETWEEN_READS).take();
        let last = lock(&ACTIVE).clone();
        if let Some(job) = last {
            assert!(
                FileJob { job }.end_within(QUIT_WAIT_MS) || std::thread::panicking(),
                "the test's job never ended"
            );
        }
    }
}

fn serial() -> One {
    One(SERIAL.lock().unwrap_or_else(PoisonError::into_inner))
}

/// A copy of the demo vault, unlocked, with an `out` folder and a source file.
struct Demo {
    dir: TempDir,
    s: Arc<Session>,
    v: u64,
}

impl Demo {
    fn new(tag: &str) -> Self {
        let dir = TempDir::new(&format!("files-{tag}"));
        let path = dir.join("Demo.larsalvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.larsalvault"
            ),
            &path,
        )
        .unwrap();
        std::fs::create_dir(dir.join("out")).unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        Self { dir, s, v }
    }

    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn out(&self) -> String {
        self.dir.join("out").to_string_lossy().into_owned()
    }

    fn out_names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn save(&self, title: &str) -> FileSave {
        FileSave {
            vault: self.v,
            group: None,
            title: title.to_owned(),
        }
    }

    fn entry(&self, title: &str) -> Option<FileKeyChoice> {
        self.s
            .file_key_choices(self.v)
            .unwrap()
            .into_iter()
            .find(|c| c.title == title)
    }

    /// The vault as saved on disk, opened in a fresh session.
    fn on_disk(&self) -> (Arc<Session>, u64) {
        let s = Session::new();
        let v = s
            .open(
                self.dir
                    .join("Demo.larsalvault")
                    .to_string_lossy()
                    .into_owned(),
            )
            .unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        (s, v)
    }
}

fn demo_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ 0x5a).collect()
}

fn started(start: FileStart) -> Arc<FileJob> {
    match start {
        FileStart::Started { job } => job,
        other => panic!("not started: {other:?}"),
    }
}

/// Polls until the job is over, as the sheet does.
fn finish(job: &FileJob) -> FileEnd {
    let until = Instant::now() + Duration::from_secs(120);
    loop {
        let p = job.progress();
        if p.finished {
            return p.end.unwrap();
        }
        assert!(Instant::now() < until, "the job never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Waits until the job is in `step` (or past the point of asking).
fn reach(job: &FileJob, step: FileStep) {
    let until = Instant::now() + Duration::from_secs(120);
    while job.progress().step != step && !job.progress().finished {
        assert!(Instant::now() < until, "never reached {step:?}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn id_of(end: &FileEnd) -> &str {
    match end {
        FileEnd::Failed { id, .. } => id,
        FileEnd::Done { .. } => "done",
        FileEnd::AskWeak { .. } | FileEnd::AskUnprotected { .. } => "ask",
    }
}

fn decrypt(d: &Demo, credential: FileCredential, source: &str, name: &str) -> FileEnd {
    let job = started(
        d.s.decrypt_file(credential, source.to_owned(), d.out(), name.to_owned())
            .unwrap(),
    );
    finish(&job)
}

fn phrase(text: &str) -> FileCredential {
    FileCredential::Passphrase { text: text.into() }
}

/// A question's number.
fn number(end: &FileEnd) -> u64 {
    match end {
        FileEnd::AskWeak { question } | FileEnd::AskUnprotected { question } => *question,
        other => panic!("not a question: {other:?}"),
    }
}

/// The question the job waits on now, if any.
fn asking(job: &FileJob) -> Option<FileEnd> {
    job.progress()
        .end
        .filter(|e| matches!(e, FileEnd::AskWeak { .. } | FileEnd::AskUnprotected { .. }))
}

/// Waits until the job asks the weak-file question, or with `unprotected` the
/// unprotected-disk one; fails if it ends first.
fn wait_ask(job: &FileJob, unprotected: bool) -> FileEnd {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        match asking(job) {
            Some(e @ FileEnd::AskUnprotected { .. }) if unprotected => return e,
            Some(e @ FileEnd::AskWeak { .. }) if !unprotected => return e,
            _ => {}
        }
        let p = job.progress();
        assert!(Instant::now() < until && !p.finished, "never asked: {p:?}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The unprotected test volume (`larsal_files::test_volume`) for one test: every
/// new output reads back as on a disk that cannot keep it private, until dropped.
struct Unprotected;

impl Unprotected {
    fn on() -> Self {
        larsal_files::test_volume::set(true);
        Self
    }
}

impl Drop for Unprotected {
    fn drop(&mut self) {
        larsal_files::test_volume::set(false);
    }
}

/// The published scrypt vector: a file from another conforming tool, work
/// factor 10 (low), passphrase "password".
fn foreign() -> Vec<u8> {
    let vector = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../larsal-files/testdata/age-testkit/scrypt"
    ))
    .unwrap();
    let at = vector.windows(2).position(|w| w == b"\n\n").unwrap();
    vector[at + 2..].to_vec()
}

/// FIL-01-T06 too: the words are the built-in list's, whatever the saved
/// generator options are (`FileDraft::new` reads none).
#[test]
fn fil01_t06_fil02_t03_the_generated_passphrase_is_ten_built_in_words_and_crosses_only_by_show() {
    let draft = FileDraft::new().unwrap();
    let shown = draft.show().unwrap();
    let words: Vec<&str> = shown.split(' ').collect();
    assert_eq!(words.len(), 10);
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && *w == w.to_lowercase())
    );
    let builtin: std::collections::HashSet<&str> = wordlist::builtin().words().collect();
    assert!(
        words.iter().all(|w| builtin.contains(w)),
        "built-in words only"
    );
    assert_ne!(
        FileDraft::new().unwrap().show().unwrap(),
        shown,
        "fresh each time"
    );
    draft.forget();
    assert_eq!(draft.show(), None);
}

#[test]
fn fil02_t04_suggestions_are_cleaned_names_never_paths() {
    assert_eq!(
        file_name_suggestion("photo.jpg".into(), true),
        "photo.jpg.age"
    );
    assert_eq!(
        file_name_suggestion("photo.jpg.age".into(), false),
        "photo.jpg"
    );
    assert_eq!(
        file_name_suggestion("notes.txt.asc".into(), false),
        "notes.txt"
    );
    assert_eq!(
        file_name_suggestion("photo.jpg".into(), false),
        "Decrypted file"
    );
    assert_eq!(file_name_suggestion(".age".into(), false), "Decrypted file");
    let hostile = file_name_suggestion("a\u{1b}b/../\u{202e}c:d".into(), true);
    assert!(
        !hostile.contains('/') && !hostile.contains('\u{1b}'),
        "{hostile}"
    );
    assert!(
        !hostile.contains('\u{202e}') && !hostile.contains(':'),
        "{hostile}"
    );
    assert!(hostile.ends_with(".age"));
}

#[test]
fn fil02_t05_t06_t10_t11_the_generated_passphrase_is_saved_first_and_opens_the_file() {
    let _one = serial();
    let d = Demo::new("generated");
    let plain = demo_bytes(300_000);
    let source = d.file("Mountain photo.jpg", &plain);
    let draft = FileDraft::new().unwrap();
    let title = "File passphrase · Mountain photo.jpg";
    let job = started(
        d.s.encrypt_file_generated(
            draft.clone(),
            d.save(title),
            source.clone(),
            d.out(),
            "Mountain photo.jpg.age".into(),
        )
        .unwrap(),
    );
    let end = finish(&job);
    assert_eq!(
        end,
        FileEnd::Done {
            saved_to: "out / Mountain photo.jpg.age".into(),
            bytes: 300_000
        }
    );
    assert_eq!(draft.show(), None, "the job took the value");
    // On disk before the output: a fresh session reads the entry back.
    let (disk, dv) = d.on_disk();
    let saved = disk
        .file_key_choices(dv)
        .unwrap()
        .into_iter()
        .find(|c| c.title == title)
        .unwrap();
    assert_eq!(saved.recipient, None);
    // FIL-02-T10, T11: the vault entry opens it, to the exact bytes, by id.
    let source = d.dir.join("out/Mountain photo.jpg.age");
    let end = decrypt(
        &d,
        FileCredential::Entry {
            vault: d.v,
            entry: saved.entry,
        },
        source.to_str().unwrap(),
        "Mountain photo.jpg",
    );
    assert_eq!(id_of(&end), "done");
    assert_eq!(
        std::fs::read(d.dir.join("out/Mountain photo.jpg")).unwrap(),
        plain
    );
    // FIL-02-T06: a later failure keeps the saved entry and says so.
    let job = started(
        d.s.encrypt_file_generated(
            FileDraft::new().unwrap(),
            d.save("Second"),
            d.file("again.bin", b"demo"),
            d.out(),
            "Mountain photo.jpg.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(
        finish(&job),
        FileEnd::Failed {
            id: "MSG-FILE-EXISTS".into(),
            text: Error::Exists.to_string(),
            saved_key: true
        }
    );
    assert!(d.entry("Second").is_some());
}

#[test]
fn fil02_t05_no_output_before_the_entry_is_on_disk() {
    use std::os::unix::fs::PermissionsExt;
    let _one = serial();
    let d = Demo::new("unsaved");
    let source = d.file("a.bin", &demo_bytes(1_000));
    // The vault's folder refuses the save; the output folder would take a file.
    let perms = |mode| std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(&*d.dir, perms(0o500)).unwrap();
    let job = started(
        d.s.encrypt_file_generated(
            FileDraft::new().unwrap(),
            d.save("Never on disk"),
            source,
            d.out(),
            "a.bin.age".into(),
        )
        .unwrap(),
    );
    let end = finish(&job);
    std::fs::set_permissions(&*d.dir, perms(0o700)).unwrap();
    assert_eq!(
        end,
        FileEnd::Failed {
            id: "MSG-FILE-ENTRY-UNSAVED".into(),
            text: ENTRY_UNSAVED.into(),
            saved_key: false
        }
    );
    assert!(d.out_names().is_empty(), "no output");
}

#[test]
fn fil01_t07_fil02_t07_a_typed_passphrase_needs_its_repeat_and_a_weak_one_asks() {
    let _one = serial();
    let d = Demo::new("manual");
    let source = d.file("a.bin", &demo_bytes(70_000));
    let start = |p: &str, r: &str, anyway: bool, save: Option<FileSave>| {
        d.s.encrypt_file_passphrase(
            p.into(),
            r.into(),
            anyway,
            save,
            source.clone(),
            d.out(),
            "a.bin.age".into(),
        )
        .unwrap()
    };
    assert!(matches!(
        start("", "", true, None),
        FileStart::Refused { .. }
    ));
    let FileStart::Refused { text } = start("demo-one", "demo-two", true, None) else {
        panic!("a mismatch runs nothing");
    };
    assert_eq!(text, REPEAT);
    assert!(matches!(
        start("short", "short", false, None),
        FileStart::Weak
    ));
    assert!(d.out_names().is_empty());
    // Use Anyway, with the entry saved first.
    let job = started(start("short", "short", true, Some(d.save("Typed"))));
    assert_eq!(id_of(&finish(&job)), "done");
    assert!(d.entry("Typed").is_some());
    let file = d.dir.join("out/a.bin.age");
    let end = decrypt(&d, phrase("short"), file.to_str().unwrap(), "a.bin");
    assert_eq!(id_of(&end), "done");
    assert_eq!(
        std::fs::read(d.dir.join("out/a.bin")).unwrap(),
        demo_bytes(70_000)
    );
}

#[test]
fn fil02_t08_t09_recipients_and_a_new_file_key() {
    let _one = serial();
    let d = Demo::new("recipients");
    let plain = demo_bytes(150_000);
    let source = d.file("a.bin", &plain);
    // T09: the public key only after the private one is on disk.
    let public = d.s.create_file_key(d.save("My file key")).unwrap();
    assert!(public.starts_with("age1"), "{public}");
    assert!(file_recipient_valid(public.clone()));
    let (disk, dv) = d.on_disk();
    let mine = disk
        .file_key_choices(dv)
        .unwrap()
        .into_iter()
        .find(|c| c.title == "My file key")
        .unwrap();
    assert_eq!(mine.recipient.as_deref(), Some(public.as_str()));
    // T08: an invalid key runs nothing; two valid ones, one of them mine.
    let other = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj";
    assert!(!file_recipient_valid("age1notakey".into()));
    let refused =
        d.s.encrypt_file_recipients(
            vec!["age1notakey".into()],
            source.clone(),
            d.out(),
            "x".into(),
        )
        .unwrap();
    assert!(matches!(refused, FileStart::Refused { .. }));
    let job = started(
        d.s.encrypt_file_recipients(
            vec![other.into(), public.clone()],
            source,
            d.out(),
            "a.bin.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let file = d.dir.join("out/a.bin.age");
    let by_key = FileCredential::Entry {
        vault: d.v,
        entry: mine.entry,
    };
    assert_eq!(
        id_of(&decrypt(&d, by_key, file.to_str().unwrap(), "a.bin")),
        "done"
    );
    assert_eq!(std::fs::read(d.dir.join("out/a.bin")).unwrap(), plain);
}

#[test]
fn fil01_t17_fil02_t09_a_file_key_that_cannot_be_saved_is_not_given_out() {
    use std::os::unix::fs::PermissionsExt;
    let _one = serial();
    let d = Demo::new("key-unsaved");
    let perms = |mode| std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(&*d.dir, perms(0o500)).unwrap();
    let made = d.s.create_file_key(d.save("Unsaved key"));
    std::fs::set_permissions(&*d.dir, perms(0o700)).unwrap();
    assert_eq!(made, Err(LarsalError::Refused(KEY_UNSAVED.into())));
}

#[test]
fn fil02_t10_t12_a_foreign_file_with_a_low_work_factor_asks_before_any_output() {
    let _one = serial();
    let d = Demo::new("weak");
    let source = d.file("from another tool.bin", &foreign());
    for (answer, want) in [
        (Some(false), "MSG-FILE-CANCELLED"),
        (None, "MSG-FILE-CANCELLED"),
        (Some(true), "done"),
    ] {
        let job = started(
            d.s.decrypt_file(phrase("password"), source.clone(), d.out(), "plain".into())
                .unwrap(),
        );
        let asked = wait_ask(&job, false);
        assert!(d.out_names().is_empty(), "nothing before the answer");
        match answer {
            Some(save) => job.answer_weak(number(&asked), save),
            None => job.revoke(),
        }
        assert_eq!(id_of(&finish(&job)), want, "{answer:?}");
    }
    assert_eq!(d.out_names(), ["plain"]);
    // A wrong passphrase: the one generic message, nothing saved.
    let end = decrypt(&d, phrase("not it"), &source, "second");
    assert_eq!(id_of(&end), "MSG-FILE-DECRYPT");
    assert_eq!(d.out_names(), ["plain"]);
}

/// A published test file: its `key: value` lines and its bytes.
fn testkit(name: &str) -> (String, Vec<u8>) {
    let row = std::fs::read(format!(
        "{}/../larsal-files/testdata/age-testkit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let at = row.windows(2).position(|w| w == b"\n\n").unwrap();
    (
        String::from_utf8(row[..at].to_vec()).unwrap(),
        row[at + 2..].to_vec(),
    )
}

/// FIL-02.24 (FIL-02-T24): files another conforming tool made open through the
/// app's own job, binary and armored, by passphrase and by a chosen key file,
/// to the published payload hash. The Mac app against the CLI, and the peer
/// tool both ways, are E22-S5's and the lead's run.
#[test]
fn fil02_t24_files_from_another_tool_open_through_the_app_job() {
    let _one = serial();
    let d = Demo::new("foreign");
    for row in [
        "x25519",
        "armor_x25519",
        "x25519_multiple_recipients",
        "scrypt",
        "armor_scrypt",
    ] {
        let (meta, bytes) = testkit(row);
        let value = |key: &str| {
            meta.lines()
                .find_map(|l| l.strip_prefix(key))
                .map(str::to_owned)
        };
        let credential = match value("passphrase: ") {
            Some(text) => FileCredential::Passphrase {
                text: SecretString::new(text),
            },
            None => FileCredential::KeyFile {
                path: d.file(
                    &format!("{row}.key"),
                    value("identity: ").unwrap().as_bytes(),
                ),
                passphrase: None,
            },
        };
        let source = d.file(&format!("{row}.anything"), &bytes);
        let job = started(
            d.s.decrypt_file(credential, source, d.out(), row.into())
                .unwrap(),
        );
        let until = Instant::now() + Duration::from_secs(60);
        let end = loop {
            let p = job.progress();
            if let Some(asked @ FileEnd::AskWeak { .. }) = &p.end {
                job.answer_weak(number(asked), true);
            }
            if p.finished {
                break p.end.unwrap();
            }
            assert!(Instant::now() < until, "{row}");
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(id_of(&end), "done", "{row}");
        let got = std::fs::read(d.dir.join("out").join(row)).unwrap();
        let hash = larsal_crypto::hash::sha256(&[&got]);
        let hash: String = hash.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Some(hash), value("payload: "), "{row}");
    }
}

/// Holds the job between two safe points, and fails unless it is still in
/// `step` with work left: what changes now changes before that step's end.
fn hold(job: &FileJob, step: FileStep) -> MutexGuard<'_, ()> {
    let held = lock(&job.job.gate);
    let p = job.progress();
    assert!(!p.finished && p.step == step, "held too late: {p:?}");
    held
}

/// FIL-02.23 (FIL-02-T23): the credential, the source, the folder and a chosen
/// key file are bound at the confirmation. The worker is held between safe
/// points while another file takes the source's name, another folder the
/// folder's, the entry's password changes and another key the key file's name:
/// the job still reads the chosen file, writes into the chosen folder and opens
/// with the confirmed credential.
#[test]
fn fil02_t23_the_credential_source_and_folder_are_bound_at_the_confirmation() {
    let _one = serial();
    let d = Demo::new("bound");
    let plain = demo_bytes(300_000);
    let source = d.file("a.bin", &plain);
    let pass = "correct horse battery staple demo";
    let encrypt = |save: Option<FileSave>| {
        started(
            d.s.encrypt_file_passphrase(
                pass.into(),
                pass.into(),
                true,
                save,
                source.clone(),
                d.out(),
                "a.age".into(),
            )
            .unwrap(),
        )
    };
    // Another file at the source's name: never read; the job stops with
    // MSG-FILE-CHANGED and writes nothing.
    let job = encrypt(None);
    let held = hold(&job, FileStep::Encrypting);
    std::fs::rename(&source, d.dir.join("chosen.bin")).unwrap();
    d.file("a.bin", b"another demo file at the chosen name");
    drop(held);
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CHANGED");
    assert!(d.out_names().is_empty());
    std::fs::rename(d.dir.join("chosen.bin"), &source).unwrap();
    // Another folder at the folder's name: the output goes to the chosen one.
    let job = encrypt(Some(d.save("Bound")));
    let held = hold(&job, FileStep::SavingPassphrase);
    let chosen = d.dir.join("chosen");
    std::fs::rename(d.dir.join("out"), &chosen).unwrap();
    std::fs::create_dir(d.dir.join("out")).unwrap();
    drop(held);
    assert_eq!(id_of(&finish(&job)), "done");
    assert!(d.out_names().is_empty(), "never the new folder");
    let sealed = chosen.join("a.age").to_string_lossy().into_owned();

    // By the entry, its password changed in the vault after the confirmation.
    let entry = d.entry("Bound").unwrap();
    let by_entry = FileCredential::Entry {
        vault: d.v,
        entry: entry.entry.clone(),
    };
    let job = started(
        d.s.decrypt_file(by_entry, sealed, d.out(), "back.bin".into())
            .unwrap(),
    );
    let held = hold(&job, FileStep::Preparing);
    let id = parse_id(&entry.entry, LarsalError::UnknownEntry).unwrap();
    d.s.with_edit(d.v, |v, _, _, _| {
        let e = v.root.entries.iter_mut().find(|e| e.uuid == id).unwrap();
        e.set_field(
            "Password".into(),
            Field {
                value: SecretString::new("an edited demo password".into()),
                protected: true,
            },
        );
        Ok(())
    })
    .unwrap();
    drop(held);
    assert_eq!(id_of(&finish(&job)), "done");
    assert_eq!(std::fs::read(d.dir.join("out/back.bin")).unwrap(), plain);

    // By a key file, another key put at its name after the confirmation. The
    // file is large, so the key is read only after a long capture.
    let (mine, public) = generate_identity().unwrap();
    let (other, _) = generate_identity().unwrap();
    let big = demo_bytes(24 << 20);
    let to_me = d.file("big.bin", &big);
    let job = started(
        d.s.encrypt_file_recipients(
            vec![public.to_text().unwrap()],
            to_me,
            d.out(),
            "big.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let key = d.file("mine.key", mine.expose().as_bytes());
    let by_file = FileCredential::KeyFile {
        path: key.clone(),
        passphrase: None,
    };
    let sealed = d.dir.join("out/big.age").to_string_lossy().into_owned();
    let job = started(
        d.s.decrypt_file(by_file, sealed, d.out(), "big.back".into())
            .unwrap(),
    );
    let held = hold(&job, FileStep::Preparing);
    std::fs::rename(&key, d.dir.join("moved.key")).unwrap();
    d.file("mine.key", other.expose().as_bytes());
    drop(held);
    assert_eq!(id_of(&finish(&job)), "done");
    assert!(std::fs::read(d.dir.join("out/big.back")).unwrap() == big);
}

/// FIL-01-T19's bridge half, C2R3-03 and C2R2-07: hostile input gets back no
/// secret, a credential's Debug shows none, and this layer reaches larsal-files
/// only by capture and a new file: never the caller's-stream writer, the
/// in-memory snapshot or the fuzz door.
#[test]
fn fil01_t19_the_bridge_gives_back_no_secret_and_uses_capture_only() {
    let _one = serial();
    let d = Demo::new("hostile");
    let secret = "hostile demo passphrase 7";
    let credentials = [
        phrase(secret),
        FileCredential::KeyFile {
            path: d.file("k", secret.as_bytes()),
            passphrase: Some(secret.into()),
        },
    ];
    let sealed = d.file("s.age", &foreign());
    for (i, credential) in credentials.into_iter().enumerate() {
        assert!(!format!("{credential:?}").contains(secret));
        for name in ["out\u{7}name", "../up", secret] {
            let end = decrypt(&d, credential.clone(), &sealed, name);
            assert!(matches!(end, FileEnd::Failed { .. }), "{i} {name:?}");
            assert!(!format!("{end:?}").contains(secret), "{i} {name:?}");
        }
    }
    assert!(d.out_names().is_empty());
    let bridge = include_str!("../files.rs");
    for door in ["write_to", "in_memory", "for_fuzzing", "capture_stream"] {
        assert!(!bridge.contains(door), "{door}");
    }
    assert!(!include_str!("../../Cargo.toml").contains("fuzz-door"));
}

/// C2R2-06 (FIL-02.10, FIL-01.16): a key file under a low work factor asks
/// before it opens anything, as a data file does; only Save Readable File goes
/// on. Fixtures: `testdata/make_weak_key_file.py`.
#[test]
fn fil02_t10_c2r2_06_a_weak_key_file_asks_before_it_opens_anything() {
    let _one = serial();
    let d = Demo::new("weak-key");
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
    let key_file = FileCredential::KeyFile {
        path: format!("{data}weak-key-file"),
        passphrase: Some("demo key file pass".into()),
    };
    let source = format!("{data}to-key-a");
    for (save, want) in [(false, "MSG-FILE-CANCELLED"), (true, "done")] {
        let job = started(
            d.s.decrypt_file(key_file.clone(), source.clone(), d.out(), "plain".into())
                .unwrap(),
        );
        let asked = wait_ask(&job, false);
        assert_eq!(
            job.progress().step,
            FileStep::Preparing,
            "asked before the check"
        );
        assert!(d.out_names().is_empty(), "nothing before the answer");
        job.answer_weak(number(&asked), save);
        assert_eq!(id_of(&finish(&job)), want);
    }
    assert_eq!(
        std::fs::read(d.dir.join("out/plain")).unwrap(),
        b"demo payload for the file vectors\n"
    );
}

#[test]
fn fil02_t12_progress_names_each_step_with_its_own_counts() {
    let _one = serial();
    let d = Demo::new("progress");
    let plain = demo_bytes(3 * 1024 * 1024);
    let source = d.file("a.bin", &plain);
    let job = started(
        d.s.encrypt_file_passphrase(
            "correct horse battery staple demo".into(),
            "correct horse battery staple demo".into(),
            true,
            None,
            source,
            d.out(),
            "a.age".into(),
        )
        .unwrap(),
    );
    let mut seen = Vec::new();
    loop {
        let p = job.progress();
        assert!(p.total == 0 || p.done <= p.total, "{p:?}");
        if seen.last() != Some(&p.step) {
            seen.push(p.step);
        }
        if p.finished {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(seen, [FileStep::Encrypting]);
    let p = job.progress();
    assert_eq!((p.done, p.total), (plain.len() as u64, plain.len() as u64));
    let file = d.dir.join("out/a.age");
    let job = started(
        d.s.decrypt_file(
            phrase("correct horse battery staple demo"),
            file.to_string_lossy().into_owned(),
            d.out(),
            "a.bin".into(),
        )
        .unwrap(),
    );
    let mut seen = Vec::new();
    loop {
        let p = job.progress();
        if p.end.is_none() && seen.last() != Some(&p.step) {
            seen.push(p.step);
        }
        if p.finished {
            break;
        }
    }
    assert_eq!(
        seen.first(),
        Some(&FileStep::Preparing),
        "the copy comes first"
    );
    let order = |s: &FileStep| seen.iter().position(|x| x == s);
    assert!(order(&FileStep::Checking) <= order(&FileStep::Saving));
    let p = job.progress();
    assert_eq!(p.step, FileStep::Saving);
    assert_eq!((p.done, p.total), (plain.len() as u64, plain.len() as u64));
    assert!(matches!(p.end, Some(FileEnd::Done { .. })));
}

#[test]
fn fil02_t13_a_revoke_at_each_step_leaves_no_output() {
    let _one = serial();
    let d = Demo::new("revoke");
    let plain = demo_bytes(24 * 1024 * 1024);
    let source = d.file("a.bin", &plain);
    let pass = "correct horse battery staple demo";
    let job = started(
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source.clone(),
            d.out(),
            "a.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let sealed = d.dir.join("out/a.age").to_string_lossy().into_owned();
    // Encrypt: at once (in the derivation), and in the write.
    for wait in [None, Some(FileStep::Encrypting)] {
        let job = started(
            d.s.encrypt_file_passphrase(
                pass.into(),
                pass.into(),
                true,
                None,
                source.clone(),
                d.out(),
                "b.age".into(),
            )
            .unwrap(),
        );
        if let Some(step) = wait {
            while job.progress().done == 0 && !job.progress().finished {
                reach(&job, step);
            }
        }
        job.revoke();
        // The gate: once revoke returned, no further chunk is written.
        let stopped = job.progress().done;
        assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED", "{wait:?}");
        assert_eq!(
            job.progress().done,
            stopped,
            "{wait:?}: a chunk after the revoke"
        );
        assert_eq!(d.out_names(), ["a.age"], "{wait:?}");
    }
    // Decrypt: in the copy, in the check, in the write.
    for step in [FileStep::Preparing, FileStep::Checking, FileStep::Saving] {
        let job = started(
            d.s.decrypt_file(phrase(pass), sealed.clone(), d.out(), "plain".into())
                .unwrap(),
        );
        reach(&job, step);
        while job.progress().done == 0 && !job.progress().finished {
            std::thread::sleep(Duration::from_micros(200));
        }
        job.revoke();
        let progress = job.progress();
        let end = finish(&job);
        assert_eq!(
            id_of(&end),
            "MSG-FILE-CANCELLED",
            "{step:?} at {progress:?}"
        );
        assert_eq!(
            job.progress().done,
            progress.done,
            "{step:?}: a chunk after the revoke"
        );
        assert_eq!(d.out_names(), ["a.age"], "{step:?}");
        assert!(scratch_is_empty(&d), "{step:?}: the copy stays in scratch");
    }
}

#[test]
fn fil02_t14_a_lock_stops_a_job_that_needs_no_vault() {
    let _one = serial();
    let d = Demo::new("lock");
    let source = d.file("a.bin", &demo_bytes(24 * 1024 * 1024));
    let pass = "correct horse battery staple demo";
    let job = started(
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source,
            d.out(),
            "a.age".into(),
        )
        .unwrap(),
    );
    reach(&job, FileStep::Encrypting);
    // Another session's lock is not this one's.
    Demo::new("lock-other").s.lock_all();
    assert!(!job.job.revoked.load(Ordering::SeqCst));
    d.s.lock_all();
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED");
    assert!(d.out_names().is_empty());
}

#[test]
fn fil02_t17_one_operation_at_a_time() {
    let _one = serial();
    let d = Demo::new("busy");
    let source = d.file("a.bin", &demo_bytes(24 * 1024 * 1024));
    let pass = "correct horse battery staple demo";
    let job = started(
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source.clone(),
            d.out(),
            "a.age".into(),
        )
        .unwrap(),
    );
    assert!(file_busy());
    let second =
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source,
            d.out(),
            "b.age".into(),
        )
        .unwrap();
    assert!(matches!(second, FileStart::Busy));
    let draft = FileDraft::new().unwrap();
    let third =
        d.s.encrypt_file_generated(
            draft.clone(),
            d.save("Busy"),
            d.file("c", b"c"),
            d.out(),
            "c.age".into(),
        )
        .unwrap();
    assert!(matches!(third, FileStart::Busy));
    assert!(draft.show().is_some(), "nothing was replaced or taken");
    assert!(d.entry("Busy").is_none());
    job.revoke();
    finish(&job);
    assert!(!file_busy());
}

#[test]
fn fil02_t02_only_one_regular_file_is_a_source() {
    let _one = serial();
    let d = Demo::new("input");
    let pass = "correct horse battery staple demo";
    let folder = d.dir.join("a folder");
    std::fs::create_dir(&folder).unwrap();
    let link = d.dir.join("a link");
    std::os::unix::fs::symlink(d.file("t.bin", b"t"), &link).unwrap();
    for source in [folder, link] {
        let job = started(
            d.s.encrypt_file_passphrase(
                pass.into(),
                pass.into(),
                true,
                None,
                source.to_string_lossy().into_owned(),
                d.out(),
                "x.age".into(),
            )
            .unwrap(),
        );
        assert_eq!(id_of(&finish(&job)), "MSG-FILE-INPUT", "{source:?}");
    }
    assert!(d.out_names().is_empty());
}

/// Polls until the job is over, for jobs of gigabytes.
fn finish_within(job: &FileJob, secs: u64) -> FileEnd {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        let p = job.progress();
        if p.finished {
            return p.end.unwrap();
        }
        assert!(Instant::now() < until, "the job never ended");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The scratch folder holds nothing (or is gone): no copy, no plaintext.
fn scratch_is_empty(d: &Demo) -> bool {
    std::fs::read_dir(d.s.scratch_folder()).map_or(true, |mut names| names.next().is_none())
}

/// E22-S4 checks 2 and 3: a 4 GiB demo file round-trips byte for byte through
/// the jobs the sheet starts, and a revoke at several points of a 4 GiB job
/// leaves no output, no staging folder and nothing in the scratch folder.
/// Ignored: it writes about 16 GiB of demo data. Run it on purpose with
/// `cargo test -p larsal-ffi --lib files::tests::s4_ -- --ignored --nocapture`.
#[test]
#[ignore = "writes about 16 GiB of demo data; run on purpose"]
fn s4_a_4_gib_demo_file_round_trips_and_a_revoke_anywhere_leaves_nothing() {
    use std::io::{Read, Write};
    const SIZE: u64 = 4 << 30;
    const MIB: usize = 1 << 20;
    let _one = serial();
    let d = Demo::new("4gib");
    let source = d.dir.join("big.bin");
    let mut writer =
        std::io::BufWriter::with_capacity(MIB, std::fs::File::create(&source).unwrap());
    let mut block = demo_bytes(MIB);
    for index in 0..(SIZE >> 20) {
        block[..8].copy_from_slice(&index.to_le_bytes());
        writer.write_all(&block).unwrap();
    }
    writer.into_inner().unwrap().sync_all().unwrap();
    let source = source.to_string_lossy().into_owned();
    let pass = "four gibibyte demo passphrase for the round trip";
    let clock = Instant::now();
    let job = started(
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source.clone(),
            d.out(),
            "big.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish_within(&job, 1_800)), "done");
    println!("encrypt 4 GiB: {:.1} s", clock.elapsed().as_secs_f64());
    let sealed = d.dir.join("out/big.age").to_string_lossy().into_owned();
    let clock = Instant::now();
    let job = started(
        d.s.decrypt_file(phrase(pass), sealed.clone(), d.out(), "big.out".into())
            .unwrap(),
    );
    let end = finish_within(&job, 1_800);
    assert!(
        matches!(end, FileEnd::Done { bytes, .. } if bytes == SIZE),
        "{end:?}"
    );
    println!("decrypt 4 GiB: {:.1} s", clock.elapsed().as_secs_f64());
    // Byte for byte.
    let (mut a, mut b) = (
        std::fs::File::open(&source).unwrap(),
        std::fs::File::open(d.dir.join("out/big.out")).unwrap(),
    );
    let (mut x, mut y) = (vec![0u8; MIB], vec![0u8; MIB]);
    let mut total = 0u64;
    loop {
        let n = a.read(&mut x).unwrap();
        b.read_exact(&mut y[..n]).unwrap();
        assert!(x[..n] == y[..n], "differs in the MiB at {total}");
        total += n as u64;
        if n == 0 {
            break;
        }
    }
    assert_eq!(total, SIZE);
    assert_eq!(b.read(&mut y).unwrap(), 0, "the output is longer");
    println!("round trip: {total} bytes equal");
    std::fs::remove_file(d.dir.join("out/big.out")).unwrap();
    assert!(scratch_is_empty(&d));
    // A revoke at a quarter of each step, and at once.
    let encrypt = || {
        started(
            d.s.encrypt_file_passphrase(
                pass.into(),
                pass.into(),
                true,
                None,
                source.clone(),
                d.out(),
                "new.age".into(),
            )
            .unwrap(),
        )
    };
    let decrypt = || {
        started(
            d.s.decrypt_file(phrase(pass), sealed.clone(), d.out(), "new.bin".into())
                .unwrap(),
        )
    };
    type Start<'a> = &'a dyn Fn() -> Arc<FileJob>;
    let points: [(&str, Start<'_>, Option<FileStep>); 6] = [
        ("encrypt at once", &encrypt, None),
        ("encrypt in the write", &encrypt, Some(FileStep::Encrypting)),
        ("decrypt at once", &decrypt, None),
        ("decrypt in the copy", &decrypt, Some(FileStep::Preparing)),
        ("decrypt in the check", &decrypt, Some(FileStep::Checking)),
        ("decrypt in the write", &decrypt, Some(FileStep::Saving)),
    ];
    for (name, start, step) in points {
        let job = start();
        if let Some(step) = step {
            let until = Instant::now() + Duration::from_secs(1_800);
            loop {
                let p = job.progress();
                if p.finished || (p.step == step && p.done >= SIZE / 4) {
                    break;
                }
                assert!(Instant::now() < until, "{name}: never reached");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let at = job.progress();
        job.revoke();
        let end = finish_within(&job, 600);
        println!(
            "{name}: revoked at {:?} {} of {}",
            at.step, at.done, at.total
        );
        assert_eq!(id_of(&end), "MSG-FILE-CANCELLED", "{name} at {at:?}");
        assert_eq!(d.out_names(), ["big.age"], "{name}");
        assert!(scratch_is_empty(&d), "{name}");
    }
}

/// The Mac app's quit bound (`FileFlow.quitWait`, FIL-02.14): 30 s.
const QUIT_WAIT_MS: u64 = 30_000;

/// The readable bytes in the output's staging folder now.
fn staged_bytes(d: &Demo) -> u64 {
    d.out_names()
        .iter()
        .filter(|n| n.starts_with(".larsal-staging-"))
        .map(|n| {
            std::fs::metadata(d.dir.join("out").join(n).join("incomplete")).map_or(0, |m| m.len())
        })
        .sum()
}

/// Arms the worker to stop once, right after the first readable chunk of the
/// next decrypt is written and before its safe point takes the gate: `paused`
/// says it stopped, a send on `go` lets it on. The caller takes the gate in
/// between, so the job is held in its write with readable bytes on disk.
fn pause_in_write() -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (stopped, paused) = std::sync::mpsc::channel();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    *lock(&AT_WRITE) = Some(Box::new(move || {
        let _ = stopped.send(());
        let _ = wait.recv();
    }));
    (paused, go)
}

/// Waits until the job stopped in its write ([`pause_in_write`]); a job that ends
/// first fails the test, never hangs it (C2R5-03).
fn in_write(paused: &std::sync::mpsc::Receiver<()>, job: &FileJob) {
    let until = Instant::now() + Duration::from_secs(120);
    while paused.recv_timeout(Duration::from_millis(10)).is_err() {
        let p = job.progress();
        assert!(
            !p.finished && Instant::now() < until,
            "never held in its write: {p:?}"
        );
    }
}

/// A demo file of `len` bytes encrypted to `out/a.age` with `pass`; its path.
fn sealed_demo(d: &Demo, len: usize, pass: &str) -> String {
    let source = d.file("a.bin", &demo_bytes(len));
    let job = started(
        d.s.encrypt_file_passphrase(
            pass.into(),
            pass.into(),
            true,
            None,
            source,
            d.out(),
            "a.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    d.dir.join("out/a.age").to_string_lossy().into_owned()
}

/// C1-01 (Checker 1's attack C1-Q1, kept as a test), FIL-02.14, FIL-02-T14: a quit
/// in the middle of a decrypt's readable write, as the app quits: the job is
/// marked and the quit waits for its safe cleanup (`end_within`). The worker is
/// held between two safe points, readable bytes on disk, while the quit starts,
/// so a quit that returns without waiting returns here. When the quit's call
/// returns, nothing readable stays: no staging folder, no incomplete file, no
/// output.
#[test]
fn fil02_t14_c1_01_a_quit_in_the_readable_write_waits_for_the_cleanup() {
    let _one = serial();
    let d = Demo::new("quit");
    let pass = "correct horse battery staple demo";
    let sealed = sealed_demo(&d, 48 * 1024 * 1024, pass);
    let (paused, go) = pause_in_write();
    let job = started(
        d.s.decrypt_file(phrase(pass), sealed, d.out(), "plain".into())
            .unwrap(),
    );
    in_write(&paused, &job);
    let held = lock(&job.job.gate);
    go.send(()).unwrap();
    assert!(
        staged_bytes(&d) > 0,
        "readable bytes are on disk in the write"
    );
    let quitting = job.clone();
    let out = d.dir.join("out");
    let quit = std::thread::spawn(move || {
        let ended = quitting.end_within(QUIT_WAIT_MS);
        let mut left: Vec<String> = std::fs::read_dir(out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        (ended, quitting.progress().finished, left)
    });
    while !job.job.revoked.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    // Still held in the write: a quit that does not wait returns now.
    let until = Instant::now() + Duration::from_millis(500);
    while !quit.is_finished() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(held);
    let (ended, finished, left) = quit.join().unwrap();
    assert!(ended && finished, "the quit returned before the cleanup");
    assert_eq!(
        left,
        ["a.age"],
        "no staging folder, no incomplete file, no output"
    );
    assert_eq!(id_of(&job.progress().end.unwrap()), "MSG-FILE-CANCELLED");
}

/// S2-02 (Checker 2's probe, kept as a test): in each of five rounds a quit comes
/// in a decrypt's readable write; when the quit's call returns the worker is over
/// and nothing is staged. Before the fix the call only marked the job, and the
/// staging folder still held readable bytes in 4 of 5 rounds.
#[test]
fn fil02_t14_s2_02_a_quit_returns_only_after_the_partial_output_is_gone() {
    let _one = serial();
    let d = Demo::new("quit-rounds");
    let pass = "correct horse battery staple demo";
    let sealed = sealed_demo(&d, 24 * 1024 * 1024, pass);
    for round in 0..5 {
        let job = started(
            d.s.decrypt_file(phrase(pass), sealed.clone(), d.out(), "q.plain".into())
                .unwrap(),
        );
        reach(&job, FileStep::Saving);
        while job.progress().done == 0 && !job.progress().finished {
            std::hint::spin_loop();
        }
        assert!(job.end_within(QUIT_WAIT_MS), "round {round}");
        assert!(job.progress().finished, "round {round}: the worker runs");
        assert_eq!(staged_bytes(&d), 0, "round {round}: staged readable bytes");
        let _ = std::fs::remove_file(d.dir.join("out/q.plain"));
        assert_eq!(d.out_names(), ["a.age"], "round {round}");
    }
}

/// FIL-02.14's bound: a worker that cannot reach its next safe point holds the
/// quit no longer than the bound, and the quit says so; its cleanup still runs
/// once it can.
#[test]
fn fil02_t14_the_quit_wait_is_bounded() {
    let _one = serial();
    let d = Demo::new("quit-bound");
    let pass = "correct horse battery staple demo";
    let sealed = sealed_demo(&d, 8 * 1024 * 1024, pass);
    let (paused, go) = pause_in_write();
    let job = started(
        d.s.decrypt_file(phrase(pass), sealed, d.out(), "plain".into())
            .unwrap(),
    );
    in_write(&paused, &job);
    let held = lock(&job.job.gate);
    go.send(()).unwrap();
    let start = Instant::now();
    assert!(!job.end_within(200), "a held worker is not over");
    // The bound holds both ways; the ceiling is generous, never a race.
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(200), "{waited:?}");
    assert!(
        waited < Duration::from_secs(20),
        "the wait is bounded: {waited:?}"
    );
    drop(held);
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED");
    assert_eq!(d.out_names(), ["a.age"]);
}

/// S2-03, FIL-01.17 and FIL-02.5 on disk (Checker 2's probe, kept as a test): a
/// file key's private string is a protected field; the generated passphrase is a
/// protected Password, and the notes name the purpose and never hold it.
#[test]
fn fil01_t17_fil02_t05_saved_secrets_are_protected_and_the_notes_hold_none() {
    let _one = serial();
    let d = Demo::new("protected");
    // The vault's own Password protection off: the saved passphrase must still
    // be a protected field by itself, not by the vault's setting.
    d.s.with_edit(d.v, |v, _, _, _| {
        v.meta.memory_protection.password = false;
        Ok(())
    })
    .unwrap();
    d.s.create_file_key(d.save("Probe key")).unwrap();
    let draft = FileDraft::new().unwrap();
    let shown = draft.show().unwrap();
    let source = d.file("p.bin", &demo_bytes(1000));
    let job = started(
        d.s.encrypt_file_generated(
            draft,
            d.save("Probe pass"),
            source,
            d.out(),
            "p.bin.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let (disk, dv) = d.on_disk();
    disk.with_vault(dv, |v| {
        assert!(
            !v.meta.memory_protection.password,
            "the vault's setting is off"
        );
        let mut stack = vec![&v.root];
        let mut seen = 0;
        while let Some(g) = stack.pop() {
            stack.extend(g.groups.iter());
            for e in &g.entries {
                if e.value("Title") == "Probe key" {
                    assert!(e.field(KEY_FIELD).unwrap().protected, "file key protected");
                    seen += 1;
                }
                if e.value("Title") == "Probe pass" {
                    assert!(e.field("Password").unwrap().protected, "password protected");
                    assert!(!e.value("Notes").is_empty(), "the notes name the purpose");
                    assert!(
                        !e.value("Notes").contains(&shown),
                        "notes hold no duplicate"
                    );
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, 2);
        Ok(())
    })
    .unwrap();
}

/// C1-05, FIL-02.6: after a collision in generated mode the saved entry stays and
/// the job names it; encrypting again with that entry makes no new entry and
/// opens with the same passphrase. A new generation makes a new entry.
#[test]
fn fil02_t06_c1_05_a_retry_uses_the_saved_entry_and_a_new_generation_a_new_one() {
    let _one = serial();
    let d = Demo::new("retry");
    let plain = demo_bytes(2_000);
    let source = d.file("r.bin", &plain);
    std::fs::write(d.dir.join("out/r.bin.age"), b"sentinel demo").unwrap();
    let title = "File passphrase \u{b7} r.bin";
    let count = || {
        d.s.file_key_choices(d.v)
            .unwrap()
            .iter()
            .filter(|c| c.title == title)
            .count()
    };
    let job = started(
        d.s.encrypt_file_generated(
            FileDraft::new().unwrap(),
            d.save(title),
            source.clone(),
            d.out(),
            "r.bin.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(
        finish(&job),
        FileEnd::Failed {
            id: "MSG-FILE-EXISTS".into(),
            text: Error::Exists.to_string(),
            saved_key: true
        }
    );
    let saved = job.saved_entry().expect("the saved entry is named");
    assert_eq!(d.entry(title).unwrap().entry, saved);
    assert_eq!(count(), 1);
    // Choose Another Name: the same saved entry, no new generation.
    let again = started(
        d.s.encrypt_file_entry(
            d.v,
            saved.clone(),
            source.clone(),
            d.out(),
            "other.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&again)), "done");
    assert_eq!(again.saved_entry(), Some(saved.clone()));
    assert_eq!(count(), 1, "no second entry");
    let sealed = d.dir.join("out/other.age");
    let by_entry = FileCredential::Entry {
        vault: d.v,
        entry: saved,
    };
    assert_eq!(
        id_of(&decrypt(&d, by_entry, sealed.to_str().unwrap(), "r.bin")),
        "done"
    );
    assert_eq!(std::fs::read(d.dir.join("out/r.bin")).unwrap(), plain);
    // A new generation: a new entry.
    let fresh = started(
        d.s.encrypt_file_generated(
            FileDraft::new().unwrap(),
            d.save(title),
            source,
            d.out(),
            "third.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&fresh)), "done");
    assert_eq!(count(), 2);
    assert_eq!(
        std::fs::read(d.dir.join("out/r.bin.age")).unwrap(),
        b"sentinel demo"
    );
}

/// C1-07, FIL-03.1, FIL-03-T01: a typed passphrase is taken up to 1,048,576 bytes,
/// through the sheet's typed slots; one byte more says MSG-FILE-PASSPHRASE's words
/// before any work, for encrypt, decrypt and a key file's passphrase.
#[test]
fn fil03_t01_c1_07_a_typed_passphrase_is_taken_up_to_one_mebibyte() {
    let _one = serial();
    let d = Demo::new("long");
    let plain = demo_bytes(1_000);
    let source = d.file("l.bin", &plain);
    let at = "a".repeat(MAX_PASSPHRASE);
    let over = "a".repeat(MAX_PASSPHRASE + 1);
    let words = Error::Passphrase.to_string();
    let typed = FileTyped::new();
    let encrypt = |text: &str, name: &str| {
        typed.set(FileSlot::Passphrase, text.to_owned());
        typed.set(FileSlot::Repeated, text.to_owned());
        d.s.encrypt_file_typed(
            typed.clone(),
            true,
            None,
            source.clone(),
            d.out(),
            name.into(),
        )
        .unwrap()
    };
    let FileStart::Refused { text } = encrypt(&over, "over.age") else {
        panic!("one byte over runs nothing");
    };
    assert_eq!(text, words);
    assert_eq!(id_of(&finish(&started(encrypt(&at, "l.age")))), "done");
    let sealed = d.dir.join("out/l.age").to_string_lossy().into_owned();
    let decrypt_typed = |text: &str, key_file: Option<String>, name: &str| {
        typed.set(FileSlot::Decrypt, text.to_owned());
        d.s.decrypt_file_typed(
            typed.clone(),
            key_file,
            sealed.clone(),
            d.out(),
            name.into(),
        )
        .unwrap()
    };
    let FileStart::Refused { text } = decrypt_typed(&over, None, "over") else {
        panic!("one byte over runs nothing");
    };
    assert_eq!(text, words);
    let key_file = Some(d.file("k", b"demo"));
    let FileStart::Refused { text } = decrypt_typed(&over, key_file, "over") else {
        panic!("one byte over runs nothing");
    };
    assert_eq!(text, words);
    assert_eq!(
        id_of(&finish(&started(decrypt_typed(&at, None, "l.bin")))),
        "done"
    );
    assert_eq!(std::fs::read(d.dir.join("out/l.bin")).unwrap(), plain);
    assert_eq!(d.out_names(), ["l.age", "l.bin"]);
}

/// C1-06, FIL-03.12: the free-space estimate says short only when the volume
/// cannot hold the work: a demo file fits; a sparse file of 1 PiB (no room taken)
/// does not, for encrypt and for decrypt. It never starts or refuses anything.
#[test]
fn fil03_t12_c1_06_the_free_space_estimate_says_short_only_when_it_is() {
    let _one = serial();
    let d = Demo::new("space");
    let small = d.file("small.bin", b"demo");
    assert!(!d.s.file_space_short(small.clone(), d.out(), true));
    assert!(!d.s.file_space_short(small, d.out(), false));
    let big = d.dir.join("big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(1 << 50)
        .unwrap();
    let big = big.to_string_lossy().into_owned();
    assert!(d.s.file_space_short(big.clone(), d.out(), true));
    assert!(d.s.file_space_short(big.clone(), d.out(), false));
    std::fs::remove_file(big).unwrap();
    assert!(d.out_names().is_empty());
}

/// S2-04: the typed slots hold what the sheet's fields send, and clear drops it.
#[test]
fn s2_04_the_typed_slots_hold_the_text_until_cleared() {
    let typed = FileTyped::new();
    assert!(typed.set(FileSlot::Decrypt, "demo typed".into()));
    assert!(!typed.set(FileSlot::Passphrase, String::new()));
    assert_eq!(typed.text(FileSlot::Decrypt).expose(), "demo typed");
    assert_eq!(typed.text(FileSlot::Passphrase).expose(), "");
    // C1R3-03, C2R3-06 (Y6): an emptied field wipes its slot, not only its Bool.
    assert!(typed.set(FileSlot::Repeated, "demo old text".into()));
    assert!(!typed.set(FileSlot::Repeated, String::new()));
    assert!(
        typed.text(FileSlot::Repeated).is_empty(),
        "the old text is gone"
    );
    typed.clear();
    assert_eq!(typed.text(FileSlot::Decrypt).expose(), "");
}

/// C1R3-03 (F3), FIL-02.7: the sheet's typed path compares the repeat and refuses
/// an empty passphrase before any work (Checker 1's probe c1r3_t1).
#[test]
fn fil02_t07_c1r3_03_the_typed_path_checks_the_repeat() {
    let _one = serial();
    let d = Demo::new("typed-repeat");
    let source = d.file("r.bin", b"demo");
    let typed = FileTyped::new();
    typed.set(FileSlot::Passphrase, "demo typed one two three four".into());
    typed.set(FileSlot::Repeated, "demo typed one two three five".into());
    let FileStart::Refused { text } =
        d.s.encrypt_file_typed(
            typed.clone(),
            true,
            None,
            source.clone(),
            d.out(),
            "r.age".into(),
        )
        .unwrap()
    else {
        panic!("a mismatched repeat ran");
    };
    assert_eq!(text, REPEAT);
    typed.clear();
    let FileStart::Refused { text } =
        d.s.encrypt_file_typed(typed, true, None, source, d.out(), "r.age".into())
            .unwrap()
    else {
        panic!("an empty passphrase ran");
    };
    assert_eq!(text, Error::Passphrase.to_string());
    assert!(d.out_names().is_empty());
}

/// C1R3-03 (F14, F13), FIL-02.10: the sheet's typed decrypt uses the chosen key
/// file: a native identity file with the slot empty (Checker 1's probe c1r3_t2),
/// and an encrypted key file with its passphrase typed in the slot.
#[test]
fn fil02_t10_c1r3_03_a_typed_decrypt_takes_the_chosen_key_file() {
    let _one = serial();
    let d = Demo::new("typed-key-file");
    let (meta, bytes) = testkit("x25519");
    let identity = meta
        .lines()
        .find_map(|l| l.strip_prefix("identity: "))
        .unwrap()
        .to_owned();
    let key = d.file("id.key", identity.as_bytes());
    let source = d.file("x.anything", &bytes);
    let typed = FileTyped::new();
    let job = started(
        d.s.decrypt_file_typed(typed.clone(), Some(key), source, d.out(), "x.out".into())
            .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
    typed.set(FileSlot::Decrypt, "demo key file pass".into());
    let job = started(
        d.s.decrypt_file_typed(
            typed,
            Some(format!("{data}weak-key-file")),
            format!("{data}to-key-a"),
            d.out(),
            "plain".into(),
        )
        .unwrap(),
    );
    let asked = wait_ask(&job, false);
    job.answer_weak(number(&asked), true);
    assert_eq!(id_of(&finish(&job)), "done");
    assert_eq!(
        std::fs::read(d.dir.join("out/plain")).unwrap(),
        b"demo payload for the file vectors\n"
    );
}

/// C2R3-03 (X3), FIL-02.7: a typed passphrase saved on request is a protected
/// field by itself, with the vault's own Password protection off (Checker 2's
/// probe), and the notes hold no copy.
#[test]
fn fil02_t07_c2r3_03_a_typed_passphrase_saved_on_request_is_protected_by_itself() {
    let _one = serial();
    let d = Demo::new("typed-saved");
    d.s.with_edit(d.v, |v, _, _, _| {
        v.meta.memory_protection.password = false;
        Ok(())
    })
    .unwrap();
    let typed = FileTyped::new();
    let pass = "c2r3 demo typed passphrase horse battery staple";
    assert!(typed.set(FileSlot::Passphrase, pass.into()));
    assert!(typed.set(FileSlot::Repeated, pass.into()));
    let source = d.file("t.bin", &demo_bytes(1000));
    let job = started(
        d.s.encrypt_file_typed(
            typed,
            true,
            Some(d.save("Typed pass")),
            source,
            d.out(),
            "t.bin.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    let (disk, dv) = d.on_disk();
    disk.with_vault(dv, |v| {
        assert!(!v.meta.memory_protection.password, "setting off on disk");
        let mut stack = vec![&v.root];
        let mut seen = 0;
        while let Some(g) = stack.pop() {
            stack.extend(g.groups.iter());
            for e in &g.entries {
                if e.value("Title") == "Typed pass" {
                    let f = e.field("Password").unwrap();
                    assert!(f.protected, "typed password protected");
                    assert_eq!(f.value.expose(), pass);
                    assert!(!e.value("Notes").contains(pass), "notes hold no copy");
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, 1);
        Ok(())
    })
    .unwrap();
}

/// C1R3-02, C2R3-02 (FIL-03-T08, MSG-FILE-UNPROTECTED's warned consent) through the
/// app's own job: on a disk that cannot keep the readable file private the job
/// asks AskUnprotected, never the weak-file question, before any byte. An answer
/// to another question number is not taken; Cancel writes nothing; a revoke is a
/// no and writes nothing (C2R3-06, Y2); only Save Readable File writes.
#[test]
fn fil03_t08_c1r3_02_an_unprotected_disk_asks_in_the_app_job_before_any_byte() {
    let _one = serial();
    let d = Demo::new("unprotected");
    let pass = "correct horse battery staple demo";
    let sealed = sealed_demo(&d, 300_000, pass);
    let _volume = Unprotected::on();
    for (how, want) in [
        ("cancel", "MSG-FILE-UNPROTECTED"),
        ("revoke", "MSG-FILE-UNPROTECTED"),
        ("save", "done"),
    ] {
        let job = started(
            d.s.decrypt_file(phrase(pass), sealed.clone(), d.out(), "plain".into())
                .unwrap(),
        );
        let asked = wait_ask(&job, true);
        let p = job.progress();
        assert_eq!((p.step, p.done), (FileStep::Saving, 0), "{how}");
        assert_eq!(staged_bytes(&d), 0, "{how}: asked before any byte");
        job.answer_weak(number(&asked) + 1, true);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            asking(&job),
            Some(asked.clone()),
            "{how}: another number is not taken"
        );
        match how {
            "cancel" => job.answer_weak(number(&asked), false),
            "revoke" => job.revoke(),
            _ => job.answer_weak(number(&asked), true),
        }
        assert_eq!(id_of(&finish(&job)), want, "{how}");
        if how != "save" {
            assert_eq!(job.progress().done, 0, "{how}: no readable byte written");
            assert_eq!(d.out_names(), ["a.age"], "{how}");
        }
    }
    assert_eq!(
        std::fs::read(d.dir.join("out/plain")).unwrap(),
        demo_bytes(300_000)
    );
}

/// C2R3-05, FIL-02.10: an answer counts only for the question the user saw. A
/// file with a low work factor going to an unprotected disk asks twice; a second
/// press meant for the first question, coming while the second is asked, is not
/// taken, and nothing is written until the second is answered.
#[test]
fn fil02_t10_c2r3_05_an_answer_counts_only_for_its_own_question() {
    let _one = serial();
    let d = Demo::new("two-questions");
    let source = d.file("from another tool.bin", &foreign());
    let _volume = Unprotected::on();
    let job = started(
        d.s.decrypt_file(phrase("password"), source, d.out(), "plain".into())
            .unwrap(),
    );
    let weak = wait_ask(&job, false);
    job.answer_weak(number(&weak), true);
    let unprotected = wait_ask(&job, true);
    assert_ne!(number(&weak), number(&unprotected));
    job.answer_weak(number(&weak), true);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        asking(&job),
        Some(unprotected.clone()),
        "a late answer is not taken"
    );
    assert_eq!(staged_bytes(&d), 0, "no readable byte written");
    assert!(!d.out_names().contains(&"plain".to_owned()));
    job.answer_weak(number(&unprotected), false);
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-UNPROTECTED");
    assert!(d.out_names().is_empty());
}

/// C1R5-01, C1R5-02 (Checker 1's probe P6, kept as a test), FIL-02.10: once an
/// answer is taken the job no longer reports its question, so the sheet cannot
/// show it again; a second answer to it is not taken, and the first stands. An
/// answer after a revoke closed the question is not taken either: the end stands.
#[test]
fn fil02_t10_c1r5_01_a_second_answer_to_the_same_question_is_not_taken() {
    let _one = serial();
    let d = Demo::new("second-answer");
    let source = d.file("from another tool.bin", &foreign());
    for round in 0..5 {
        let job = started(
            d.s.decrypt_file(phrase("password"), source.clone(), d.out(), "plain".into())
                .unwrap(),
        );
        let asked = wait_ask(&job, false);
        job.answer_weak(number(&asked), false);
        assert_ne!(
            asking(&job),
            Some(asked.clone()),
            "round {round}: asked again"
        );
        job.answer_weak(number(&asked), true);
        assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED", "round {round}");
        assert!(d.out_names().is_empty(), "round {round}");
    }
    let job = started(
        d.s.decrypt_file(phrase("password"), source, d.out(), "plain".into())
            .unwrap(),
    );
    let asked = wait_ask(&job, false);
    job.revoke();
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED");
    job.answer_weak(number(&asked), true);
    let p = job.progress();
    assert_eq!(
        p.end.as_ref().map(id_of),
        Some("MSG-FILE-CANCELLED"),
        "{p:?}"
    );
    assert!(d.out_names().is_empty());
}

/// C1R5-03, FIL-02.12: a reading taken while the worker stores its end is one
/// snapshot: finished only with its end. The worker's two stores land between
/// the reading's two reads.
#[test]
fn fil02_t12_c1r5_03_a_finished_reading_always_carries_its_end() {
    let _one = serial();
    let job = Arc::new(Job::default());
    let worker = job.clone();
    *lock(&BETWEEN_READS) = Some(Box::new(move || {
        *lock(&worker.end) = Some(failed(Error::Cancelled, false));
        worker.finished.store(true, Ordering::SeqCst);
    }));
    let p = job.progress();
    assert!(
        !p.finished || p.end.is_some(),
        "finished with no end: {p:?}"
    );
    let p = job.progress();
    assert!(p.finished && p.end.is_some(), "{p:?}");
}

/// The entries in every vault `s` has open whose Password is `pass`.
fn entries_with(s: &Session, pass: &str) -> usize {
    s.vaults()
        .iter()
        .map(|info| {
            s.with_vault(info.id, |v| {
                let mut stack = vec![&v.root];
                let mut n = 0;
                while let Some(g) = stack.pop() {
                    stack.extend(g.groups.iter());
                    n += g
                        .entries
                        .iter()
                        .filter(|e| e.value("Password") == pass)
                        .count();
                }
                Ok(n)
            })
            .unwrap()
        })
        .sum()
}

/// C2R5-01 (Checker 2's probe, kept as a test), FIL-02.7: a typed passphrase is
/// saved as an entry only when the user asks. With saving off no open vault gains
/// one, in memory or on disk, and a decrypt never saves one; asked, it is saved once.
#[test]
fn fil02_t07_c2r5_01_a_typed_passphrase_is_saved_only_when_asked() {
    let _one = serial();
    let d = Demo::new("save-asked");
    let pass = "c2r5 demo typed quartz walnut harbor violet anchor";
    let source = d.file("s.bin", &demo_bytes(5000));
    let typed = FileTyped::new();
    typed.set(FileSlot::Passphrase, pass.into());
    typed.set(FileSlot::Repeated, pass.into());
    let saved = || (entries_with(&d.s, pass), entries_with(&d.on_disk().0, pass));
    let job = started(
        d.s.encrypt_file_typed(
            typed.clone(),
            true,
            None,
            source.clone(),
            d.out(),
            "s.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    assert!(job.saved_entry().is_none());
    assert_eq!(saved(), (0, 0), "not asked, not saved");
    typed.set(FileSlot::Decrypt, pass.into());
    let sealed = d.dir.join("out/s.age").to_string_lossy().into_owned();
    let job = started(
        d.s.decrypt_file_typed(typed.clone(), None, sealed, d.out(), "plain".into())
            .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    assert_eq!(saved(), (0, 0), "a decrypt saves nothing");
    typed.set(FileSlot::Passphrase, pass.into());
    typed.set(FileSlot::Repeated, pass.into());
    let job = started(
        d.s.encrypt_file_typed(
            typed,
            true,
            Some(d.save("Asked")),
            source,
            d.out(),
            "s2.age".into(),
        )
        .unwrap(),
    );
    assert_eq!(id_of(&finish(&job)), "done");
    assert_eq!(saved(), (1, 1), "asked, saved once");
}

/// C2R3-06 (Y2), FIL-02.14: a revoke while a question waits is a no on both
/// question paths; the job goes no further than its question. Asked about a file's
/// low work factor it never reaches the readable step; asked about a key file's,
/// never the check. (The unprotected-disk question: the test above.)
#[test]
fn fil02_t14_c2r3_06_a_revoke_during_a_question_is_a_no() {
    let _one = serial();
    let d = Demo::new("revoke-asked");
    let source = d.file("from another tool.bin", &foreign());
    let job = started(
        d.s.decrypt_file(phrase("password"), source, d.out(), "plain".into())
            .unwrap(),
    );
    wait_ask(&job, false);
    job.revoke();
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED");
    assert_eq!(
        job.progress().step,
        FileStep::Checking,
        "never past the question"
    );
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
    let key_file = FileCredential::KeyFile {
        path: format!("{data}weak-key-file"),
        passphrase: Some("demo key file pass".into()),
    };
    let job = started(
        d.s.decrypt_file(key_file, format!("{data}to-key-a"), d.out(), "plain".into())
            .unwrap(),
    );
    wait_ask(&job, false);
    job.revoke();
    assert_eq!(id_of(&finish(&job)), "MSG-FILE-CANCELLED");
    assert_eq!(
        job.progress().step,
        FileStep::Preparing,
        "never past the question"
    );
    assert!(d.out_names().is_empty());
}

/// C1R3-06 (F12), FIL-03.12: a decrypt whose scratch copy goes to the output's own
/// volume needs room for both. A sparse source of three quarters of the free room
/// fits as an encrypt there, not as a decrypt.
#[test]
fn fil03_t12_c1r3_06_a_decrypt_on_one_volume_counts_the_scratch_copy() {
    use std::os::unix::fs::MetadataExt;
    let _one = serial();
    let d = Demo::new("space-one");
    let scratch = d.s.scratch_folder();
    let near = scratch.ancestors().find(|p| p.exists()).unwrap();
    let dev = |p: &Path| std::fs::metadata(p).unwrap().dev();
    assert_eq!(
        dev(near),
        dev(Path::new(&d.out())),
        "scratch on the output's volume"
    );
    let out = std::fs::File::open(d.out()).unwrap();
    let free = larsal_platform::macos::free_bytes(&out).unwrap();
    let source = d.dir.join("three-quarters.bin");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(free / 4 * 3)
        .unwrap();
    let source = source.to_string_lossy().into_owned();
    assert!(
        !d.s.file_space_short(source.clone(), d.out(), true),
        "an encrypt fits"
    );
    assert!(
        d.s.file_space_short(source.clone(), d.out(), false),
        "a decrypt and its scratch copy do not"
    );
    std::fs::remove_file(source).unwrap();
}
