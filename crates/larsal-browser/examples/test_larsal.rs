//! A stand-in for Larsal in the browser extension's tests (story E7-S7c;
//! INT-11.43): Larsal's own browser side from larsal-browser (the channel's
//! [`Bridge`], the vault side [`VaultSide`], the dialog line [`Prompts`] and
//! the bridge socket [`Server`]) over one demo vault in memory, started and
//! stopped by `extension/test/test_extension.py`. Larsal.app runs the same
//! larsal-browser code; the Connect dialog is answered through standard input
//! (the test seam). Demo data only; nothing is written but the files named
//! below, and the caller keeps every path under /tmp (INT-01.10).
//!
//! Usage:
//! - `test_larsal setup HOME PROGRAM ID`: writes Larsal's Chrome setup file
//!   under the test HOME with larsal-browser's [`Manifests`] (INT-01.8 to
//!   INT-01.10), naming `PROGRAM` (S-BRW-24, a relay program) for the
//!   development extension id `ID` (INT-01.9's debug id); prints its path.
//! - `test_larsal run FOLDER SITE`: runs as Larsal with the test instance
//!   folder `FOLDER`: Larsal's instance socket there, and, while the test
//!   settings file `FOLDER/settings.json` has `"browser.enabled": true`
//!   (S-BRW-01), the bridge socket too. One vault `demo-vault`, shown and
//!   unlocked, holds one entry for the page `SITE`. Standard output gets one
//!   line per event: `ready`; `request <type> url=… top_url=… identity=…`
//!   before a request runs and `reply <type> ok` or `reply <type> error <n>`
//!   after; `question <id> connect <words>` when the Connect dialog shows;
//!   `sessions <n>` when the number of live sessions changes.
//!   Standard input takes `allow <id> <name>`, `deny <id>`, `lock` and
//!   `unlock` (each sends Larsal's notice, INT-01.46); its end quits.
//! - `test_larsal vectors`: prints larsal-crypto's channel values of
//!   INT-01.50 (C, A, CV-4, CV-5, CV-6, CV-9) as one JSON object, so the
//!   test compares them byte for byte with the extension's WebCrypto.

use larsal_browser::{
    ADDON_ID, Answer, BRIDGE_SOCKET, Bridge, Browser, Changed, Manifests, OpenVault, Options,
    Prompts, Question, Request, Route, Server, SharedHandler, VaultSide, Vaults,
};
use larsal_crypto::base64::{self, Form};
use larsal_crypto::bridge::{self, Secret};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_model::json::{self, Map, Value};
use larsal_model::{Entry, Field, Group, Time, Uuid, Vault};
use std::error::Error;
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Larsal's single-instance socket (APP-09.7), which `larsal-bridge` asks to
/// tell 45 from 44 (INT-01.5); debug builds have their own name.
const INSTANCE_SOCKET: &str = if cfg!(debug_assertions) {
    "app.larsal.desktop-debug.sock"
} else {
    "app.larsal.desktop.sock"
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn now() -> Time {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Time::from_unix(i64::try_from(secs).unwrap_or(0)).unwrap_or_else(|| Time::from_unix(0).unwrap())
}

/// The one demo vault, shown; `unlocked` is the lock state.
struct Demo {
    vault: Mutex<Vault>,
    unlocked: AtomicBool,
}

impl Vaults for Demo {
    fn list(&self) -> Vec<OpenVault> {
        vec![OpenVault {
            id: 1,
            name: "demo-vault".into(),
            shown: true,
            unlocked: self.unlocked.load(Ordering::SeqCst),
        }]
    }
    fn with(&self, id: u64, f: &mut dyn FnMut(&mut Vault, &str) -> Changed) -> bool {
        if id != 1 || !self.unlocked.load(Ordering::SeqCst) {
            return false;
        }
        let mut vault = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = f(&mut vault, "/tmp");
        true
    }
    fn options(&self) -> Options {
        Options::default()
    }
    fn now(&self) -> Time {
        now()
    }
    fn computer(&self) -> String {
        "Test Mac".into()
    }
    fn notify(&self, _: &str) {}
}

fn demo_vault(site: &str) -> Vault {
    let t = now();
    let mut entry = Entry::new(Uuid([0x11; 16]), t);
    for (name, value) in [
        ("Title", "Site A demo"),
        ("UserName", "demo"),
        ("Password", "demo-site-a-password"),
        ("URL", site),
    ] {
        let field = Field {
            value: SecretString::new(value.into()),
            protected: name == "Password",
        };
        entry.set_field(name.into(), field);
    }
    let mut root = Group::new(Uuid([0x80; 16]), "demo-vault".into(), t);
    root.entries.push(entry);
    let mut vault = Vault::new(root, t);
    vault.meta.name = "demo-vault".into();
    vault
}

/// The vault side, with each request written to standard output (the
/// test's request log): its type, the URLs it names and the identity the
/// session proved. Demo data only.
struct Logged(VaultSide);

impl SharedHandler for Logged {
    fn handle(&self, r: &Request<'_>) -> std::result::Result<Map, u8> {
        let field = |k: &str| r.content.get(k).and_then(Value::as_str).unwrap_or("");
        let identity = r
            .identity
            .map(|k| base64::encode(Form::Padded, k))
            .unwrap_or_default();
        say(&format!(
            "request {} url={} top_url={} identity={identity}",
            r.kind,
            field("url"),
            field("top_url")
        ));
        let result = self.0.handle(r);
        match &result {
            Ok(_) => say(&format!("reply {} ok", r.kind)),
            Err(n) => say(&format!("reply {} error {n}", r.kind)),
        }
        result
    }
}

fn setup(home: &str, program: &str, id: &str) -> Result<()> {
    let manifests = Manifests::new(Path::new(home), Path::new(program), &[id], ADDON_ID);
    manifests
        .turn_on(Browser::Chrome)
        .map_err(|t| format!("{}: {}", t.id, t.text))?;
    say(&manifests.file(Browser::Chrome).display().to_string());
    Ok(())
}

fn run(folder: &str, site: &str) -> Result<()> {
    let folder = Path::new(folder);
    let settings = std::fs::read(folder.join("settings.json"))?;
    let enabled = json::from_slice(&settings)
        .ok()
        .and_then(|s| s.get("browser.enabled").and_then(Value::as_bool))
        .unwrap_or(false);
    let demo = Arc::new(Demo {
        vault: Mutex::new(demo_vault(site)),
        unlocked: AtomicBool::new(true),
    });
    let prompts = Arc::new(Prompts::new(Arc::new(Instant::now), Box::new(|| {})));
    let handler = Arc::new(Logged(VaultSide::new(demo.clone(), prompts.clone())));
    let bridge = Arc::new(Mutex::new(Bridge::shared(
        env!("CARGO_PKG_VERSION"),
        handler,
    )));
    let instance = folder.join(INSTANCE_SOCKET);
    let _listening = UnixListener::bind(&instance)?;
    let server = if enabled {
        let clock = Arc::new(Instant::now);
        Some(Server::start(
            &folder.join(BRIDGE_SOCKET),
            Route::Port,
            bridge.clone(),
            clock,
        )?)
    } else {
        None
    };
    // The window's side of the dialog line: each new Connect dialog is told
    // once; and each change in the number of live sessions (a hello opens
    // one, a closed connection or a new hello ends one).
    let shown = prompts.clone();
    std::thread::spawn(move || {
        let (mut last, mut sessions) = (None, 0);
        loop {
            if let Some((id, Question::Connect(c))) = shown.current()
                && last != Some(id)
            {
                last = Some(id);
                say(&format!("question {id} connect {}", c.words));
            }
            let now = bridge.lock().map_or(sessions, |b| b.sessions());
            if now != sessions {
                sessions = now;
                say(&format!("sessions {now}"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    say("ready");
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        let words: Vec<&str> = line.splitn(3, ' ').collect();
        match words.as_slice() {
            ["allow", id, name] => {
                let done = prompts.answer(id.parse()?, Answer::Connect((*name).into()));
                say(&format!("answered {id} {done}"));
            }
            ["deny", id] => {
                let done = prompts.answer(id.parse()?, Answer::Deny { remember: false });
                say(&format!("answered {id} {done}"));
            }
            [event @ ("lock" | "unlock")] => {
                demo.unlocked.store(*event == "unlock", Ordering::SeqCst);
                let notice = if *event == "lock" {
                    "locked"
                } else {
                    "unlocked"
                };
                if let Some(server) = &server {
                    server.notify(notice, |key| key.is_some());
                }
                say(notice);
            }
            _ => say(&format!("unknown {line}")),
        }
    }
    drop(server); // stops serving and removes the bridge socket
    std::fs::remove_file(&instance)?;
    Ok(())
}

fn vectors() -> Result<()> {
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
            .collect()
    };
    let secret = |s: &str| Secret::from_bytes(SecretBytes::new(hex(s)));
    // INT-01.50: c is RFC 7748's Alice, a its Bob, and the identification key i.
    let c = secret("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?;
    let a = secret("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")?;
    let i = secret("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
    let (cp, ap, ip) = (c.public(), a.public(), i.public());
    let z = c.agree(&ap).ok_or("all-zero X25519")?;
    let z_id = i.agree(&ap).ok_or("all-zero X25519")?;
    let request = bridge::request_key(&z, &cp, &ap)?;
    let reply = bridge::reply_key(&z, &cp, &ap)?;
    let proof = bridge::proof_key(&z_id, &cp, &ap, &ip)?;
    let mut n1 = [0u8; 12];
    n1[11] = 1;
    let mut n2 = [0u8; 12];
    n2[11] = 2;
    let hexed = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut out = Map::new();
    for (name, bytes) in [
        ("C", cp.to_vec()),
        ("A", ap.to_vec()),
        (
            "CV4",
            bridge::seal(&request, &n1, br#"{"type":"status","req":1}"#)?,
        ),
        (
            "CV5",
            bridge::seal(&reply, &n1, br#"{"type":"status","req":1,"vaults":[]}"#)?,
        ),
        ("CV6", ip.to_vec()),
        ("CV9", bridge::seal(&proof, &n2, &cp)?),
    ] {
        out.insert(name.into(), Value::String(hexed(&bytes)));
    }
    say(&json::to_string(&Value::Object(out)));
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["setup", home, program, id] => setup(home, program, id),
        ["run", folder, site] => run(folder, site),
        ["vectors"] => vectors(),
        _ => Err("usage: test_larsal setup HOME PROGRAM ID | run FOLDER SITE | vectors".into()),
    }
}
