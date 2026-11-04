//! E6-S6 (SR-07, LD-133): the findings F-034, F-042, F-048 and F-053, and
//! APP-11.9-c, run under the zeroing allocator the `larsal` tool and the Mac
//! app install. A probe outside it shows the blocks freed with the value
//! still in them (the finding, reproduced); a probe inside it shows what the
//! system gets back: every block all zero. No freed memory is read.
//!
//! One test only: the probes count every block the process frees.

use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::{SecretBytes, SecretString};
use larsal_format::keys::Credentials;
use larsal_format::limits::Limits;
use larsal_format::{Opened, Saved, open, save};
use larsal_platform::memory::{Probe, Seen, Zeroing, set_needle};
use std::alloc::System;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

static BEFORE: Seen = Seen::new();
static AFTER: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<Zeroing<Probe<System>>> = Probe(Zeroing(Probe(System, &AFTER)), &BEFORE);

/// Runs `f` with `needle` searched in every freed block. Asserts the value
/// was freed in plain at least once outside the wipe and never reached the
/// system: every block handed back was all zero.
fn scenario<T>(name: &str, needle: [u8; 8], f: impl FnOnce() -> T) -> T {
    set_needle(needle);
    BEFORE.reset();
    AFTER.reset();
    let out = f();
    let (plain, largest) = (
        BEFORE.with_needle.load(Relaxed),
        BEFORE.largest_with_needle.load(Relaxed),
    );
    let (freed, left, dirty) = (
        AFTER.freed.load(Relaxed),
        AFTER.with_needle.load(Relaxed),
        AFTER.not_zero.load(Relaxed),
    );
    set_needle([0; 8]);
    println!(
        "{name}: {plain} freed blocks held the value before the wipe (largest {largest} bytes); \
         after it {freed} blocks freed, {left} with the value, {dirty} not all zero"
    );
    assert!(plain > 0, "{name}: the finding did not reproduce");
    assert_eq!(
        (left, dirty),
        (0, 0),
        "{name}: a block reached the system unwiped"
    );
    out
}

fn testdata(name: &str) -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/").to_owned() + name)
        .unwrap()
}

fn quick_host() -> Host {
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

#[test]
fn findings_leave_no_plain_value_in_freed_memory() {
    // F-034: open a compressed demo vault; the gzip window holds the end of
    // the payload. The needle is the start of its user name `demo-user`.
    let file = testdata("password-only.larsalvault");
    let pw = SecretString::new("demo-pass-1".to_owned());
    let creds = Credentials {
        password: Some(&pw),
        ..Default::default()
    };
    let mut host = quick_host();
    let opened = scenario("F-034 open", *b"demo-use", || {
        match open(&file, &creds, &mut host, &Limits::DEFAULT, None).unwrap() {
            Opened::Vault(v) => v,
            Opened::Ask(r) => panic!("cost question {r:?}"),
        }
    });

    // F-042: save it; the compressor's state holds the whole payload.
    let saved = scenario("F-042 save", *b"demo-use", || {
        let key = Some(&opened.key);
        match save(
            &opened.vault,
            &creds,
            key,
            &mut host,
            &Limits::DEFAULT,
            None,
        )
        .unwrap()
        {
            Saved::File(f) => f,
            Saved::Ask(r) => panic!("cost question {r:?}"),
        }
    });
    assert!(saved.bytes.len() > 1000);
    drop((opened, saved));

    // F-048: a strength estimate; the estimator copies the password.
    let typed = SecretString::new("qzhorsestapledemo".to_owned());
    let bits = scenario("F-048 strength", *b"qzhorses", || {
        larsal_core::health::zxcvbn_bits(typed.expose(), &[])
    });
    assert!(bits > 0.0);

    // F-053: a JSON import with a PIN written as a number; the reader keeps
    // it as an f64, and the member list grows after it.
    const PIN: f64 = 271_828_182.0;
    let json = r#"{"encrypted":false,"folders":[],"items":[{"type":1,"name":"Demo bank",
        "login":{"username":"demo-user","password":"demo-bank-1"},
        "fields":[{"name":"PIN","value":271828182,"type":1,"linkedId":null,"note":"demo"}]}]}"#;
    let cancel = AtomicBool::new(false);
    let zone = larsal_core::time::Utc;
    let ctx = larsal_core::import::Context::new(larsal_model::Time(0), &zone, &cancel);
    let imported = scenario("F-053 JSON import", PIN.to_le_bytes(), || {
        larsal_core::import::bitwarden::read(json.as_bytes(), None, &ctx).unwrap()
    });
    drop(imported);

    // APP-11.9-c: a buffer grown from 16 to 4,096 bytes before it became a
    // secret; the blocks left behind by the growth were never the secret
    // type's to wipe.
    scenario("APP-11.9-c growth", *b"demo-key", || {
        let mut grown = Vec::with_capacity(16);
        while grown.len() < 4096 {
            grown.extend_from_slice(b"demo-key");
        }
        drop(SecretBytes::new(grown));
    });

    // F-270: a share item's value holds the share password in base64 inside
    // base64 (FMT-14.17, INT-08.39); the group editor's Save writes it into
    // the group and a lock drops it. The needle is 8 characters of the value
    // that carry part of demo-share-1's base64.
    let mut share = larsal_format::share_item::Settings::new();
    share.import = true;
    share.path = "team.larsalvault".to_owned();
    share.password = SecretString::new("demo-share-1".to_owned());
    let first = share.write().unwrap();
    let xml = larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, &first).unwrap();
    let at = xml
        .windows(16)
        .position(|w| w == b"ZGVtby1zaGFyZS0x")
        .unwrap()
        .div_ceil(3)
        * 4;
    let needle: [u8; 8] = first.as_bytes()[at..at + 8].try_into().unwrap();
    drop((first, xml));
    let key = String::from_utf8(larsal_format::share_item::KEY.to_vec()).unwrap();
    scenario("F-270 share item", needle, || {
        let mut team = larsal_model::Group::new(
            larsal_model::Uuid([0x20; 16]),
            "Team".into(),
            larsal_model::Time(0),
        );
        team.custom_data.items.push(larsal_model::CustomDataItem {
            key,
            value: share.write().unwrap(),
            last_modified: None,
            unknown: Vec::new(),
        });
        drop(team);
    });
}
