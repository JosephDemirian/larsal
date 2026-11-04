//! The Option A demo vaults (design/option-a/mockup.js `VAULTS`, `GROUPS`,
//! `ENTRIES`): fake data only, made by our own code. `make_option_a_vaults`
//! writes them (run it by hand, it is ignored); the other tests check the
//! stored files. Passwords are in testdata/README.md.
//!
//!   cargo test -p app-ffi --test option_a -- --ignored make_option_a_vaults

use app_crypto::kdf::Host;
use app_crypto::secret::{SecretBytes, SecretString};
use app_ffi::session::{AppError, Session, UnlockResult};
use app_ffi::views::{EntryKind, ListView};
use app_format::keys::Credentials;
use app_format::limits::Limits;
use app_format::{Saved, save};
use app_model::entry::Field;
use app_model::{
    Argon2Kind, Attachment, Encryption, Entry, Group, Icon, Kdf, PublicItem, Time, Uuid, Vault,
};
use std::path::PathBuf;
use std::sync::Arc;

/// The vaults: file, password, public colour, public icon.
const VAULTS: [(&str, &str, &str, i32); 3] = [
    ("option-a-personal.appvault", "demo-pass-7", "#22a6bd", 0),
    ("option-a-work.appvault", "demo-pass-8", "#ff9500", 1),
    ("option-a-family.appvault", "demo-pass-9", "#f2385a", 2),
];

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

/// Unix seconds of a wall-clock time in Central European time, as the
/// mockup's times read on the owner's Mac: +2 h from the last Sunday of
/// March to the last Sunday of October (01:00 UTC), else +1 h.
fn cet(text: &str) -> Time {
    let n = |a: usize, b: usize| text[a..b].parse::<i64>().unwrap();
    let (y, mo, d, h, mi) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16));
    let days = |y: i64, m: i64, d: i64| {
        // Days since 1970-01-01 (civil from days, proleptic Gregorian).
        let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * m + 2) / 5 + d - 1;
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    };
    let last_sunday = |m: i64| {
        let last = days(y, m, 31);
        last - (last + 4).rem_euclid(7)
    };
    let local = days(y, mo, d) * 86_400 + h * 3600 + mi * 60;
    let summer = (last_sunday(3) * 86_400 + 3600 + 3600..last_sunday(10) * 86_400 + 3600 + 7200)
        .contains(&local);
    Time::from_unix(local - if summer { 7200 } else { 3600 }).unwrap()
}

/// A fixed id per name, so every run writes the same tree.
fn id(name: &str) -> Uuid {
    let mut out = [0u8; 16];
    for (i, b) in name.bytes().enumerate() {
        out[i % 16] = out[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    out[15] = out[15].wrapping_add(1);
    Uuid(out)
}

fn field(value: &str, protected: bool) -> Field {
    Field {
        value: SecretString::new(value.to_owned()),
        protected,
    }
}

fn attachment(name: &str, data: Vec<u8>) -> Attachment {
    Attachment {
        name: name.to_owned(),
        data: Arc::new(SecretBytes::new(data)),
    }
}

/// `text` repeated and cut to exactly `len` bytes.
fn filled(text: &str, len: usize) -> Vec<u8> {
    text.bytes().cycle().take(len).collect()
}

/// A demo OpenSSH public key line of 98 bytes: not a key anyone holds.
fn demo_public_key() -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend((0u8..32).map(|i| i.wrapping_mul(37).wrapping_add(11)));
    let b64 = app_format::document::encode::base64_encode(&blob);
    format!("ssh-ed25519 {b64} alex@morgan-labs\n").into_bytes()
}

struct Spec<'a> {
    title: &'a str,
    user: &'a str,
    password: &'a str,
    url: &'a str,
    group: &'a str,
    tags: &'a [&'a str],
    created: &'a str,
    modified: &'a str,
    totp: &'a str,
    passkey: &'a str,
    notes: &'a str,
    hist: usize,
    icon: i32,
}

const BASE: Spec<'static> = Spec {
    title: "",
    user: "",
    password: "",
    url: "",
    group: "",
    tags: &[],
    created: "",
    modified: "",
    totp: "",
    passkey: "",
    notes: "",
    hist: 0,
    icon: 0,
};

/// The mockup's entries (mockup.js `ENTRIES`), in its order; "" group is
/// the root group, "bin" the recycle bin. Favorites carry the tag Favorite.
fn specs() -> Vec<Spec<'static>> {
    vec![
        Spec {
            title: "GitHub",
            user: "alex-dev",
            password: "x9!Lq#4vT@m2Zr8&Wk5p",
            url: "https://github.com/login",
            group: "work",
            tags: &["2fa", "dev", "Favorite"],
            created: "2024-03-03T10:12",
            modified: "2026-10-22T08:49",
            totp: "DEMOGITHUB234567",
            passkey: "github.com",
            notes: "Recovery codes are in the attachment.\nOrganization: morgan-labs",
            hist: 3,
            ..BASE
        },
        Spec {
            title: "Apple Account",
            user: "alex.morgan@icloud.com",
            password: "Ap4!Kz8@Rq2#Wn6$",
            url: "https://account.apple.com",
            tags: &["Favorite"],
            created: "2022-11-02T12:00",
            modified: "2026-10-21T18:02",
            passkey: "apple.com",
            hist: 2,
            ..BASE
        },
        Spec {
            title: "Google",
            user: "alex.morgan@gmail.com",
            password: "Hn7$wQ2!cV9#tR4@yB6x",
            url: "https://accounts.google.com",
            group: "email",
            tags: &["2fa", "Favorite"],
            created: "2021-05-14T09:30",
            modified: "2026-10-20T14:31",
            totp: "DEMOGOOGLE234567",
            hist: 4,
            ..BASE
        },
        Spec {
            title: "Hetzner Cloud",
            user: "alex@morgan-labs.dev",
            password: "Vm2#Kq8!Rt5@Ls9$Xw",
            url: "https://console.hetzner.cloud",
            group: "servers",
            tags: &["2fa", "dev"],
            created: "2025-02-11T16:45",
            modified: "2026-10-18T11:05",
            totp: "DEMOHETZNER23456",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "Proton Mail",
            user: "alex.morgan@proton.me",
            password: "violet anchor mosaic tundra lantern quill harbor",
            url: "https://account.proton.me/login",
            group: "email",
            tags: &["2fa", "Favorite"],
            created: "2023-08-19T20:10",
            modified: "2026-10-14T20:40",
            totp: "DEMOPROTON234567",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "Server root · web-01",
            user: "root",
            password: "glacier pepper canyon ribbon falcon",
            url: "ssh://203.0.113.10",
            group: "servers",
            tags: &["dev", "ssh"],
            created: "2025-06-02T08:00",
            modified: "2026-10-11T16:20",
            notes: "Falkenstein, 2 vCPU.\nThe password unlocks the private key.",
            icon: 30,
            ..BASE
        },
        Spec {
            title: "PayPal",
            user: "alex.morgan@posteo.de",
            password: "Gk3@vN8!sL5#qT1$",
            url: "https://www.paypal.com/signin",
            group: "banking",
            tags: &["finance"],
            created: "2019-04-20T10:00",
            modified: "2026-10-09T09:15",
            hist: 2,
            ..BASE
        },
        Spec {
            title: "Instagram",
            user: "alex.morgan.photos",
            password: "Pb5$Lx9!Wd3@Nz7#",
            url: "https://www.instagram.com",
            group: "social",
            tags: &["2fa"],
            created: "2020-07-07T21:00",
            modified: "2026-10-02T19:44",
            totp: "DEMOINSTAGRAM234",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "Wise",
            user: "alex.morgan@posteo.de",
            password: "Tz4#pW9@kM2!xF7&",
            url: "https://wise.com/login",
            group: "banking",
            tags: &["2fa", "finance"],
            created: "2022-01-10T11:00",
            modified: "2026-09-28T17:05",
            totp: "DEMOWISE23456723",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "Figma",
            user: "alex@morgan-labs.dev",
            password: "Fy6@Tn1!Qp8#Hc4$",
            url: "https://www.figma.com/login",
            group: "work",
            created: "2023-04-01T09:00",
            modified: "2026-09-22T10:10",
            ..BASE
        },
        Spec {
            title: "Mastodon",
            user: "@alex@mastodon.social",
            url: "https://mastodon.social",
            group: "social",
            created: "2026-09-18T22:00",
            modified: "2026-09-18T22:00",
            passkey: "mastodon.social",
            ..BASE
        },
        Spec {
            title: "Linear",
            user: "alex@morgan-labs.dev",
            password: "Lr3#Vb7!Mk1@Zp5$",
            url: "https://linear.app/login",
            group: "work",
            created: "2024-09-09T09:00",
            modified: "2026-09-15T14:00",
            passkey: "linear.app",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "Visa Debit",
            user: "Card ending 1111",
            group: "banking",
            tags: &["finance"],
            created: "2024-10-01T09:00",
            modified: "2026-09-10T08:30",
            notes: "Lost card: call the number on the back.",
            ..BASE
        },
        Spec {
            title: "Zalando",
            user: "alex.morgan@posteo.de",
            password: "Rq8!nV3@hK6#",
            url: "https://www.zalando.de/login",
            group: "shopping",
            created: "2021-03-15T18:00",
            modified: "2026-09-02T12:30",
            ..BASE
        },
        Spec {
            title: "Amazon",
            user: "alex.morgan@posteo.de",
            password: "Summer2024!",
            url: "https://www.amazon.de/ap/signin",
            group: "shopping",
            created: "2018-12-01T12:00",
            modified: "2026-08-27T20:15",
            hist: 2,
            ..BASE
        },
        Spec {
            title: "Deutsche Bahn",
            user: "alex.morgan@posteo.de",
            password: "Db5@Hx1!Mq7#Tv3$",
            url: "https://www.bahn.de",
            created: "2022-06-06T07:00",
            modified: "2026-08-19T07:45",
            ..BASE
        },
        Spec {
            title: "Slack",
            user: "alex@morgan-labs.dev",
            password: "morganlabs2024",
            url: "https://morgan-labs.slack.com",
            group: "work",
            created: "2023-02-02T09:00",
            modified: "2026-08-04T09:30",
            ..BASE
        },
        Spec {
            title: "eBay",
            user: "alexmorgan88",
            password: "Summer2024!",
            url: "https://signin.ebay.de",
            group: "shopping",
            created: "2017-05-05T15:00",
            modified: "2026-07-21T18:00",
            hist: 1,
            ..BASE
        },
        Spec {
            title: "AWS root account",
            user: "alex@morgan-labs.dev",
            password: "Aw7$Pq3!Zr9@Lm5#Ty2&",
            url: "https://console.aws.amazon.com",
            group: "servers",
            tags: &["2fa", "dev"],
            created: "2024-01-15T10:00",
            modified: "2026-07-08T13:20",
            totp: "DEMOAWSROOT23456",
            notes: "Use IAM users for daily work. Root only for billing.",
            hist: 2,
            ..BASE
        },
        Spec {
            title: "Netflix",
            user: "family.morgan@posteo.de",
            password: "Nf8#Qr2!Lz6@Pv4$",
            url: "https://www.netflix.com/login",
            tags: &["shared"],
            created: "2020-02-14T20:00",
            modified: "2026-06-30T21:10",
            ..BASE
        },
        Spec {
            title: "Reddit",
            user: "alex_m",
            password: "sunshine2019",
            url: "https://www.reddit.com/login",
            group: "social",
            created: "2019-03-03T23:00",
            modified: "2026-06-12T22:40",
            ..BASE
        },
        Spec {
            title: "Home Wi-Fi",
            user: "Morgan-Home 5G",
            password: "harbor velvet orchid meteor pine",
            group: "devices",
            tags: &["shared", "Favorite"],
            created: "2024-05-03T18:00",
            modified: "2026-05-03T18:20",
            notes: "Guest network: Morgan-Guest",
            icon: 12,
            ..BASE
        },
        Spec {
            title: "Router admin",
            user: "admin",
            password: "admin1234",
            url: "http://192.168.178.1",
            group: "devices",
            created: "2021-09-09T09:00",
            modified: "2026-02-14T10:00",
            icon: 3,
            ..BASE
        },
        Spec {
            title: "Twitter (old account)",
            user: "@alexmorgan",
            password: "Tw9!xK2@pL7#",
            url: "https://x.com/login",
            group: "bin",
            created: "2014-06-01T12:00",
            modified: "2026-10-03T19:00",
            ..BASE
        },
        Spec {
            title: "MySpace",
            user: "alexm1999",
            password: "qwerty123",
            url: "https://myspace.com",
            group: "bin",
            created: "2008-01-01T12:00",
            modified: "2026-09-12T08:00",
            ..BASE
        },
    ]
}

fn entry(s: &Spec<'_>) -> Entry {
    let mut e = Entry::new(id(s.title), cet(s.modified));
    for (name, value, protected) in [
        ("Title", s.title, false),
        ("UserName", s.user, false),
        ("Password", s.password, true),
        ("URL", s.url, false),
        ("Notes", s.notes, false),
    ] {
        e.set_field(name.to_owned(), field(value, protected));
    }
    if !s.totp.is_empty() {
        let otp = format!(
            "otpauth://totp/{}?secret={}&period=30&digits=6",
            s.title.replace(' ', "%20"),
            s.totp
        );
        e.set_field("otp".to_owned(), field(&otp, true));
    }
    if !s.passkey.is_empty() {
        for (name, value, protected) in [
            ("KPEX_PASSKEY_RELYING_PARTY", s.passkey, false),
            ("KPEX_PASSKEY_USERNAME", s.user, false),
            (
                "KPEX_PASSKEY_CREDENTIAL_ID",
                "ZGVtby1jcmVkZW50aWFsLWlk",
                false,
            ),
            ("KPEX_PASSKEY_USER_HANDLE", "ZGVtby11c2VyLWhhbmRsZQ", false),
            (
                "KPEX_PASSKEY_PRIVATE_KEY_PEM",
                "demo data, not a private key",
                true,
            ),
        ] {
            e.set_field(name.to_owned(), field(value, protected));
        }
    }
    e.set_tags(s.tags.iter().map(|t| (*t).to_owned()).collect());
    e.icon = Icon::Standard(s.icon);
    e.times.creation = cet(s.created);
    match s.title {
        "Visa Debit" => {
            for (name, value, protected) in [
                ("Cardholder", "ALEX MORGAN", false),
                ("Card number", "4111 1111 1111 1111", true),
                ("Expires", "09/29", false),
                ("Security code", "123", true),
                ("PIN", "4821", true),
            ] {
                e.set_field(name.to_owned(), field(value, protected));
            }
        }
        "Home Wi-Fi" => {
            e.set_field("Security".to_owned(), field("WPA3 Personal", false));
        }
        "Server root · web-01" => {
            e.attachments = vec![
                attachment("id_ed25519", filled("demo data, not a private key\n", 464)),
                attachment("id_ed25519.pub", demo_public_key()),
            ];
        }
        "GitHub" => {
            e.attachments = vec![attachment(
                "github-recovery-codes.txt",
                filled("demo-recovery-code-0000-0000\n", 1229),
            )];
        }
        "Zalando" => {
            e.times.expires = true;
            e.times.expiry = cet("2026-10-01T00:00");
        }
        // The Browser report (INT-02.32): mockup.js `allow` and `deny`.
        "Google" => site_access(&mut e, &["accounts.google.com"], &[]),
        "Figma" => site_access(&mut e, &["www.figma.com"], &[]),
        "Amazon" => site_access(&mut e, &[], &["www.amazon.com"]),
        _ => {}
    }
    if s.title == "GitHub" {
        github_editor_data(&mut e);
        return e;
    }
    // Earlier versions: copies a few weeks apart, oldest first.
    for k in (1..=s.hist).rev() {
        let mut old = e.duplicate(false);
        let at = Time(old.times.last_modification.0 - 86_400 * 21 * i64::try_from(k).unwrap());
        old.times.last_modification = at;
        old.times.last_access = at;
        e.history.push(old);
    }
    e
}

/// The site access item's key (INT-02.16), as hex bytes of its ASCII text
/// (AGENTS.md rule 1).
fn site_access_key() -> String {
    String::from_utf8(vec![
        0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x58, 0x43, 0x2D, 0x42, 0x72, 0x6F, 0x77, 0x73,
        0x65, 0x72, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73,
    ])
    .unwrap()
}

fn site_access(e: &mut Entry, allow: &[&str], deny: &[&str]) {
    let list = |l: &[&str]| {
        l.iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    e.custom_data
        .items
        .push(app_model::custom_data::CustomDataItem {
            key: site_access_key(),
            value: format!(
                r#"{{"Allow":[{}],"Deny":[{}],"Realm":""}}"#,
                list(allow),
                list(deny)
            ),
            last_modified: Some(e.times.last_modification),
            unknown: Vec::new(),
        });
}

/// The editor frames' GitHub (mockup.js `EDP`, `HISTORY`): the identifier,
/// times used and last use of the Properties page, the Auto-Type sequence
/// and windows, a custom data item, and three earlier versions whose
/// differences read "Entry created", "Password changed" and, for the
/// current entry, "Passkey added".
fn github_editor_data(e: &mut Entry) {
    e.uuid = Uuid([
        0x3f, 0x2a, 0x9c, 0x1e, 0x77, 0xb4, 0x4c, 0x0d, 0x9a, 0x51, 0x6e, 0x0b, 0x2d, 0x8c, 0x4f,
        0x17,
    ]);
    e.times.usage_count = 214;
    e.times.last_access = cet("2026-10-27T09:12");
    e.auto_type.default_sequence = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}".to_owned();
    for (window, sequence) in [
        ("*GitHub*", ""),
        (
            "Sign in to GitHub · GitHub — Safari",
            "{USERNAME}{TAB}{PASSWORD}{ENTER}",
        ),
    ] {
        e.auto_type
            .associations
            .push(app_model::autotype::Association {
                window: window.to_owned(),
                sequence: sequence.to_owned(),
                unknown: Vec::new(),
            });
    }
    // The Browser page (INT-02.16, INT-02.14, INT-02.9). The site access
    // key as hex bytes of its ASCII text (AGENTS.md rule 1).
    let site_access = site_access_key();
    for (key, value) in [
        ("browser.last_fill", "2026-10-27 09:12"),
        (
            site_access.as_str(),
            r#"{"Allow":["gist.github.com","github.com"],"Deny":[],"Realm":""}"#,
        ),
        ("BrowserSkipAutoSubmit", "true"),
        (
            "BrowserLastUse",
            r#"{"Firefox on MacBook":"2026-10-27T08:12:00Z","Safari":"2026-10-20T16:05:00Z"}"#,
        ),
    ] {
        e.custom_data
            .items
            .push(app_model::custom_data::CustomDataItem {
                key: key.to_owned(),
                value: value.to_owned(),
                last_modified: Some(cet("2026-10-27T09:12")),
                unknown: Vec::new(),
            });
    }
    // Oldest first: created; notes added; password changed (before the
    // passkey came on Oct 22).
    let version = |at: &str, password: &str, notes: &str| {
        let mut old = e.duplicate(false);
        for name in e.fields().map(|(n, _)| n.to_owned()).collect::<Vec<_>>() {
            if name.starts_with("KPEX_PASSKEY") {
                old.remove_field(&name);
            }
        }
        old.set_field("Password".to_owned(), field(password, true));
        old.set_field("Notes".to_owned(), field(notes, false));
        old.custom_data.items.clear();
        old.times.last_modification = cet(at);
        old.times.last_access = cet(at);
        old
    };
    let notes = "Recovery codes are in the attachment.\nOrganization: morgan-labs";
    e.history = vec![
        version("2024-03-03T10:12", "m8@Ty3!Kq6#Pv1$Zr4&", ""),
        version("2025-09-14T09:30", "m8@Ty3!Kq6#Pv1$Zr4&", notes),
        version("2026-06-03T11:20", "x9!Lq#4vT@m2Zr8&Wk5p", notes),
    ];
}

fn group(key: &str, name: &str, icon: i32) -> Group {
    let mut g = Group::new(id(key), name.to_owned(), cet("2018-01-01T12:00"));
    g.icon = Icon::Standard(icon);
    g
}

fn personal() -> Vault {
    let mut root = Group::new(
        id("personal-root"),
        "Personal".to_owned(),
        cet("2017-05-05T12:00"),
    );
    let mut groups: Vec<(&str, Group)> = vec![
        ("email", group("email", "Email", 19)),
        ("banking", group("banking", "Banking", 37)),
        ("social", group("social", "Social", 5)),
        ("shopping", group("shopping", "Shopping", 47)),
        ("work", group("work", "Work", 59)),
        ("devices", group("devices", "Devices", 12)),
        ("bin", group("bin", "Recycle Bin", 43)),
    ];
    let mut servers = group("servers", "Servers", 3);
    for s in specs() {
        let mut e = entry(&s);
        match s.group {
            "" => root.entries.push(e),
            "servers" => servers.entries.push(e),
            key => {
                if key == "bin" {
                    let deleted = cet(s.modified);
                    e.previous_parent = Some(id("social"));
                    e.times.location_changed = deleted;
                }
                let slot = groups.iter_mut().find(|(k, _)| *k == key).unwrap();
                slot.1.entries.push(e);
            }
        }
    }
    for (key, mut g) in groups {
        if key == "work" {
            g.groups
                .push(std::mem::replace(&mut servers, group("x", "x", 0)));
        }
        root.groups.push(g);
    }
    let mut vault = Vault::new(root, cet("2017-05-05T12:00"));
    vault.meta.name = "Personal".to_owned();
    // Two connected browsers (INT-02.1, mockup.js vault settings and the
    // Browser report): the association prefix as hex bytes of its ASCII
    // text (AGENTS.md rule 1), demo keys that no extension holds.
    let prefix = String::from_utf8(vec![
        0x4B, 0x50, 0x58, 0x43, 0x5F, 0x42, 0x52, 0x4F, 0x57, 0x53, 0x45, 0x52, 0x5F,
    ])
    .unwrap();
    for (name, key, created, used) in [
        (
            "Firefox on MacBook",
            "ZGVtby1rZXktZmlyZWZveC1ub3QtYS1yZWFsLWtleSE=",
            "2026-10-12T08:00:00Z",
            "2026-10-27T08:12:00Z",
        ),
        (
            "Safari",
            "ZGVtby1rZXktc2FmYXJpLS1ub3QtYS1yZWFsLWtleSE=",
            "2026-09-03T08:00:00Z",
            "2026-10-20T16:05:00Z",
        ),
    ] {
        for (k, value) in [
            (format!("{prefix}{name}"), key),
            (format!("_CREATED_{name}"), created),
            (format!("_LAST_USED_{name}"), used),
        ] {
            vault
                .meta
                .custom_data
                .items
                .push(app_model::custom_data::CustomDataItem {
                    key: k,
                    value: value.to_owned(),
                    last_modified: None,
                    unknown: Vec::new(),
                });
        }
    }
    vault.meta.recycle_bin_enabled = true;
    vault.meta.recycle_bin = Some(id("bin"));
    vault
}

fn work() -> Vault {
    let mut root = Group::new(id("work-root"), "Work".to_owned(), cet("2024-01-08T09:00"));
    root.entries.push(entry(&Spec {
        title: "Team wiki",
        user: "alex@morgan-labs.dev",
        password: "Wk4!Tm8@Qz2#Lp6$",
        url: "https://wiki.example.com",
        created: "2024-01-08T09:00",
        modified: "2026-09-30T10:00",
        ..BASE
    }));
    Vault::new(root, cet("2024-01-08T09:00"))
}

/// Empty, as right after the wizard: the mockup's "now" minus 10 seconds.
fn family() -> Vault {
    let made = Time(cet("2026-10-27T10:30").0 - 10);
    let mut vault = Vault::new(
        Group::new(id("family-root"), "Family".to_owned(), made),
        made,
    );
    vault.meta.name = "Family".to_owned();
    vault
}

fn host() -> Host {
    Host {
        physical_memory: 8 << 30,
        logical_processors: 4,
        argon2_record: None,
        aes_record: None,
    }
}

#[test]
#[ignore = "writes testdata/option-a-*.appvault; run by hand"]
fn make_option_a_vaults() {
    for ((file, password, colour, icon), mut vault) in
        VAULTS.into_iter().zip([personal(), work(), family()])
    {
        // A fast KDF: these are demo vaults for screen tests.
        vault.encryption = Encryption {
            kdf: Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 2,
                memory_kib: 1024,
                lanes: 1,
            },
            ..Encryption::default()
        };
        // FMT-03.23's public colour and icon keys, as hex bytes (AGENTS.md
        // rule 1).
        let prefix = [
            0x4B, 0x50, 0x58, 0x43, 0x5F, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x5F,
        ];
        vault.public_custom_data = vec![
            PublicItem {
                kind: 0x18,
                name: [&prefix[..], &[0x43, 0x4F, 0x4C, 0x4F, 0x52]].concat(),
                value: colour.as_bytes().to_vec(),
            },
            PublicItem {
                kind: 0x0C,
                name: [&prefix[..], &[0x49, 0x43, 0x4F, 0x4E]].concat(),
                value: icon.to_le_bytes().to_vec(),
            },
        ];
        let secret = SecretString::new(password.to_owned());
        let credentials = Credentials {
            password: Some(&secret),
            key_file: None,
            hardware_key: None,
        };
        let Ok(Saved::File(saved)) = save(
            &vault,
            &credentials,
            None,
            &mut host(),
            &Limits::DEFAULT,
            None,
        ) else {
            panic!("save {file}");
        };
        std::fs::write(testdata(file), &saved.bytes).unwrap();
    }
}

fn unlocked(index: usize) -> (Arc<Session>, u64) {
    let (file, password, _, _) = VAULTS[index];
    let session = Session::new();
    let id = session
        .open(testdata(file).to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(
        session.unlock(id, Some(password.into()), None).unwrap(),
        UnlockResult::Unlocked
    );
    (session, id)
}

#[test]
fn personal_matches_the_mockup() {
    let (session, id) = unlocked(0);
    let info = &session.vaults()[0];
    assert_eq!((info.colour, info.icon), (Some(0x22a6bd), 0));
    while !session.rate(id, 50, 3600).unwrap() {}
    let side = session.sidebar(id).unwrap();
    let groups: Vec<(&str, u32)> = side
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.count))
        .collect();
    assert_eq!(
        groups,
        [
            ("Email", 2),
            ("Banking", 3),
            ("Social", 3),
            ("Shopping", 3),
            ("Work", 7),
            ("Servers", 3),
            ("Devices", 2)
        ]
    );
    let tags: Vec<&str> = side.tags.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(tags, ["2fa", "dev", "finance", "shared", "ssh"]);
    assert_eq!(
        (
            side.all,
            side.favorites,
            side.codes,
            side.passkeys,
            side.bin
        ),
        (23, 5, 7, 4, Some(2))
    );
    let rows = session.list(id, ListView::All).unwrap().rows;
    let attention: Vec<(&str, &str)> = rows
        .iter()
        .filter_map(|r| {
            r.rating
                .as_ref()
                .filter(|x| x.attention)
                .map(|x| (r.title.as_str(), x.word.as_str()))
        })
        .collect();
    // FEA-05.4 and FEA-05.15: the mockup's six, plus the server's
    // passphrase, which the card's estimator rates Weak (below 75 bits).
    let mut words = attention.clone();
    words.sort_unstable();
    assert_eq!(
        words,
        [
            ("Amazon", "Reused"),
            ("Reddit", "Poor"),
            ("Router admin", "Poor"),
            ("Server root · web-01", "Weak"),
            ("Slack", "Poor"),
            ("Zalando", "Expired"),
            ("eBay", "Reused"),
        ]
    );
    assert_eq!(side.attention, Some(7));
    let mut kinds: Vec<(&str, EntryKind)> = rows
        .iter()
        .filter(|r| r.kind != EntryKind::Login)
        .map(|r| (r.title.as_str(), r.kind))
        .collect();
    kinds.sort_unstable_by_key(|k| k.0);
    assert_eq!(
        kinds,
        [
            ("Home Wi-Fi", EntryKind::WiFi),
            ("Server root · web-01", EntryKind::Ssh),
            ("Visa Debit", EntryKind::Card)
        ]
    );
    let web = rows.iter().find(|r| r.kind == EntryKind::Ssh).unwrap();
    let detail = session.entry(id, web.id.clone()).unwrap();
    let ssh = detail.ssh.unwrap();
    assert_eq!(ssh.kind, "ED25519");
    assert!(
        ssh.fingerprint.starts_with("SHA256:") && ssh.fingerprint.len() == 50,
        "{}",
        ssh.fingerprint
    );
    let bin = session.list(id, ListView::Bin).unwrap().rows;
    let twitter = session.entry(id, bin[0].id.clone()).unwrap();
    assert_eq!(twitter.deleted_from.as_deref(), Some("Social"));
    let codes = session
        .codes(
            id,
            rows.iter()
                .filter(|r| r.has_totp)
                .map(|r| r.id.clone())
                .collect(),
        )
        .unwrap();
    assert_eq!(codes.len(), 7);
    assert!(
        codes
            .iter()
            .all(|c| c.as_ref().is_some_and(|c| c.code.len() == 7))
    );
}

#[test]
fn family_is_empty_and_work_is_locked_look() {
    let (session, id) = unlocked(2);
    assert_eq!(session.sidebar(id).unwrap().all, 0);
    let other = session
        .open(testdata(VAULTS[1].0).to_string_lossy().into_owned())
        .unwrap();
    let work = session
        .vaults()
        .into_iter()
        .find(|v| v.id == other)
        .unwrap();
    assert!(work.locked);
    assert_eq!((work.colour, work.icon), (Some(0xff9500), 1));
}

/// A vault with `entries` in a fresh temp file, opened and unlocked, with a
/// fast KDF. The file is removed when the guard drops.
struct Probe(PathBuf);

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn probe(name: &str, entries: Vec<Entry>) -> (Arc<Session>, u64, Probe) {
    let made = cet("2026-01-01T00:00");
    let mut root = Group::new(id("probe-root"), "Probe".to_owned(), made);
    root.entries = entries;
    let mut vault = Vault::new(root, made);
    vault.encryption = Encryption {
        kdf: Kdf::Argon2 {
            kind: Argon2Kind::Id,
            iterations: 2,
            memory_kib: 1024,
            lanes: 1,
        },
        ..Encryption::default()
    };
    let secret = SecretString::new("demo-probe".to_owned());
    let credentials = Credentials {
        password: Some(&secret),
        key_file: None,
        hardware_key: None,
    };
    let Ok(Saved::File(saved)) = save(
        &vault,
        &credentials,
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    ) else {
        panic!("save probe");
    };
    let path = std::env::temp_dir().join(format!("app-ffi-{name}-{}.appvault", std::process::id()));
    std::fs::write(&path, &saved.bytes).unwrap();
    let session = Session::new();
    let id = session.open(path.to_string_lossy().into_owned()).unwrap();
    assert_eq!(
        session.unlock(id, Some("demo-probe".into()), None).unwrap(),
        UnlockResult::Unlocked
    );
    (session, id, Probe(path))
}

fn plain_entry(title: &str) -> Entry {
    let mut e = Entry::new(id(title), cet("2026-01-01T00:00"));
    e.set_field("Title".to_owned(), field(title, false));
    e
}

/// Checker E5-S4 (1): an attachment that only looks like a key line is never
/// echoed; only known OpenSSH types with a matching blob are keys.
#[test]
fn ssh_key_names_only_known_types() {
    let mut fake = plain_entry("API notes");
    fake.attachments = vec![attachment(
        "keys.txt",
        b"sk-proj-TOPSECRETAPIKEY1 sk-proj-TOPSECRETAPIKEY2\n".to_vec(),
    )];
    // A known type whose blob names another type.
    let mut blob = Vec::new();
    blob.extend_from_slice(&7u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-rsa");
    let line = format!(
        "ssh-ed25519 {} x\n",
        app_format::document::encode::base64_encode(&blob)
    );
    let mut mismatch = plain_entry("Mismatch");
    mismatch.attachments = vec![attachment("id.pub", line.into_bytes())];
    let mut real = plain_entry("Real key");
    real.attachments = vec![attachment("id_ed25519.pub", demo_public_key())];
    let (session, id, _probe) = probe("ssh", vec![fake, mismatch, real]);
    let rows = session.list(id, ListView::All).unwrap().rows;
    for row in &rows {
        let detail = session.entry(id, row.id.clone()).unwrap();
        let text = format!("{row:?} {detail:?}");
        assert!(
            !text.contains("TOPSECRET") && !text.contains("SK-PROJ"),
            "{text}"
        );
        let want = row.title == "Real key";
        assert_eq!(row.kind == EntryKind::Ssh, want, "{}", row.title);
        assert_eq!(
            detail.ssh.map(|k| k.kind),
            want.then(|| "ED25519".to_owned()),
            "{}",
            row.title
        );
    }
}

/// Checker E5-S4 (7), MOD-01.8: a row's second line never shows a passkey
/// field.
#[test]
fn row_second_line_skips_passkey_fields() {
    let mut e = plain_entry("Passkey site");
    e.set_field(
        "KPEX_PASSKEY_RELYING_PARTY".to_owned(),
        field("passkey.example.com", false),
    );
    e.set_field("Note".to_owned(), field("demo hint", false));
    let (session, id, _probe) = probe("subtitle", vec![e]);
    let rows = session.list(id, ListView::All).unwrap().rows;
    assert_eq!(rows[0].subtitle, "demo hint");
}

/// Checker E5-S4 (6): the recent list's look never opens a FIFO, which
/// would block.
#[test]
fn vault_look_skips_a_fifo() {
    let path = std::env::temp_dir().join(format!("app-ffi-fifo-{}.appvault", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let given = path.to_string_lossy().into_owned();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || send.send(app_ffi::session::vault_look(given)));
    let look = receive.recv_timeout(std::time::Duration::from_secs(3));
    let _ = std::fs::remove_file(&path);
    let look = look.expect("vault_look blocked on a FIFO");
    assert_eq!((look.colour, look.icon), (None, -1));
}

/// Checker E5-S4 (2): a search returns ids only, each one an All Entries
/// row.
#[test]
fn search_returns_ids_of_all_rows() {
    let (session, id) = unlocked(0);
    let all: Vec<String> = session
        .list(id, ListView::All)
        .unwrap()
        .rows
        .into_iter()
        .map(|r| r.id)
        .collect();
    let hits = session.search(id, "posteo".into()).unwrap();
    assert_eq!(hits.ids.len(), 6, "{hits:?}");
    assert!(hits.ids.iter().all(|h| all.contains(h)));
    assert_eq!(session.search(id, "zzz-none".into()).unwrap().ids.len(), 0);
}

#[test]
fn typed_is_weak_matches_the_weak_view() {
    // FEA-01.17, FEA-01.28: the tip `is:weak` finds what the Weak view shows.
    // big-10000 has weak passwords (the Option A vaults have none by FEA-05.10).
    let session = Session::new();
    let id = session
        .open(
            testdata("big-10000.appvault")
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap();
    assert_eq!(
        session
            .unlock(id, Some("demo-pass-6".into()), None)
            .unwrap(),
        UnlockResult::Unlocked
    );
    let mut weak: Vec<String> = session
        .list(id, ListView::Weak)
        .unwrap()
        .rows
        .into_iter()
        .map(|r| r.id)
        .collect();
    let mut typed = session.search(id, "is:weak".into()).unwrap().ids;
    weak.sort();
    typed.sort();
    assert!(!weak.is_empty());
    assert_eq!(typed, weak);
}

#[test]
fn show_and_copy_refuse_passkey_fields() {
    // MOD-01.8, F-057: a passkey row's private key and user handle stay in Rust.
    let (session, id) = unlocked(0);
    let rows = session.list(id, ListView::Passkeys).unwrap().rows;
    let row = rows.first().expect("a passkey entry");
    for field in ["KPEX_PASSKEY_PRIVATE_KEY_PEM", "KPEX_PASSKEY_USER_HANDLE"] {
        assert_eq!(
            session.show_field(id, row.id.clone(), field.into()),
            Err(AppError::UnknownField),
            "{field}"
        );
        assert_eq!(
            session.copy_field(id, row.id.clone(), field.into()),
            Err(AppError::UnknownField),
            "{field}"
        );
    }
}
