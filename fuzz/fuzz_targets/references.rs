//! Fuzz target `references` (E4-S6): the placeholder and reference resolver
//! (MOD-08) on arbitrary text against a demo vault of 20 entries with
//! fields up to 72 KiB (MOD-08 security notes; past the regex text bound of
//! 65,536 characters, LD-113). Must never panic, hang or
//! grow past the bounds: every result is the raw input (a bound was hit)
//! or at most 1,048,576 characters, and every call returns quickly.
//!
//! Input: the text to resolve (a leading `!` resolves for display), then
//! records separated by byte 0x1E: an entry byte (mod 20), a field code
//! (`T` Title, `U` UserName, `P` Password (protected), `A` URL, `N` Notes,
//! `S` a custom field written `name=value`) and the value. A value that
//! starts with `*` and a count byte n stands for the rest repeated
//! (n + 1) × 256 times, so small inputs reach large values.
#![no_main]

use app_core::refs::{Context, MAX_OUTPUT, resolve};
use app_crypto::secret::SecretString;
use app_model::{Entry, Field, Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;

const SEPARATOR: u8 = 0x1E;
const MAX_VALUE: usize = 72 * 1024;

fn vault(records: &[&[u8]]) -> Vault {
    let mut entries: Vec<Entry> = (0..20u8)
        .map(|i| Entry::new(Uuid([i + 1; 16]), Time(0)))
        .collect();
    for r in records {
        let (Some(&e), Some(&f)) = (r.first(), r.get(1)) else {
            continue;
        };
        let raw = &r[2..];
        let mut value = match raw {
            [b'*', n, rest @ ..] if !rest.is_empty() => {
                String::from_utf8_lossy(rest).repeat((usize::from(*n) + 1) * 256)
            }
            _ => String::from_utf8_lossy(raw).into_owned(),
        };
        value.truncate(value.floor_char_boundary(MAX_VALUE));
        let (name, value) = match f {
            b'T' => ("Title".to_owned(), value),
            b'U' => ("UserName".to_owned(), value),
            b'P' => ("Password".to_owned(), value),
            b'A' => ("URL".to_owned(), value),
            b'N' => ("Notes".to_owned(), value),
            _ => match value.split_once('=') {
                Some((n, v)) if !n.is_empty() => (n.to_owned(), v.to_owned()),
                _ => continue,
            },
        };
        entries[usize::from(e) % 20].set_field(
            name,
            Field {
                value: SecretString::new(value),
                protected: f == b'P',
            },
        );
    }
    let mut sub = Group::new(Uuid([0xEE; 16]), "Sub".into(), Time(0));
    sub.entries = entries.split_off(10);
    let mut root = Group::new(Uuid([0xFF; 16]), "Root".into(), Time(0));
    root.entries = entries;
    root.groups.push(sub);
    Vault::new(root, Time(0))
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&b| b == SEPARATOR);
    let text = String::from_utf8_lossy(parts.next().unwrap_or(&[])).into_owned();
    let records: Vec<&[u8]> = parts.take(40).collect();
    let v = vault(&records);
    let (display, text) = match text.strip_prefix('!') {
        Some(t) => (true, t.to_owned()),
        None => (false, text),
    };
    let mut ctx = Context::new(Some(&v), Time(63_928_466_236));
    ctx.display = display;
    let check = |t: &str, e: &Entry| {
        let started = std::time::Instant::now();
        let r = resolve(t, e, &ctx);
        // Wall clock in a sanitizer build on a busy Mac: the worst known input
        // takes about 0.7 s here and 0.28 s without the sanitizer, so 5 s
        // still catches a broken budget (LD-123: 250 ms in release) without
        // false alarms. Release timing is checked by the MOD-08 timed tests.
        assert!(started.elapsed().as_secs() < 5, "a resolve took too long");
        let out = r.text.expose();
        if r.bounded {
            assert_eq!(out, t, "a bound gives the raw input");
        } else {
            assert!(out.chars().count() <= MAX_OUTPUT);
        }
    };
    check(&text, &v.root.entries[0]);
    for g in v.root.subtree() {
        for e in &g.entries {
            for (_, f) in e.fields() {
                check(f.value.expose(), e);
            }
        }
    }
});
