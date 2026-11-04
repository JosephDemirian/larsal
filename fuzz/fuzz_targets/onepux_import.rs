//! Fuzz target `onepux_import` (E4-S13): the .1pux import (FEA-08 section
//! C), App's ZIP reader and the `export.data` mapping. Must never panic,
//! hang or allocate by a hostile number (FEA-08.65, FEA-08.67; ZIP members
//! inflate only up to their declared size and limit). A result keeps the
//! model invariants, also after placement into an open vault.
//!
//! Input: a mode byte, then the rest. Mode bit 0 clear: the rest is the
//! .1pux file. Set: the rest is split at byte 0x1E into `export.data` and
//! `files/` members, which the target zips (bit 1: `export.data`
//! deflated), so the JSON mapping is reached with any content.
#![no_main]

use app_core::import::{self, Context, onepux};
use app_core::time::Utc;
use app_model::{Group, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use std::sync::atomic::AtomicBool;

fn zip(members: &[(String, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, content, deflate) in members {
        let body = if *deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(content).unwrap();
            e.finish().unwrap()
        } else {
            content.to_vec()
        };
        let mut crc = flate2::Crc::new();
        crc.update(content);
        let method: u16 = if *deflate { 8 } else { 0 };
        let offset = out.len() as u32;
        let head = |v: &mut Vec<u8>| {
            v.extend(method.to_le_bytes());
            v.extend([0u8; 4]);
            v.extend(crc.sum().to_le_bytes());
            v.extend((body.len() as u32).to_le_bytes());
            v.extend((content.len() as u32).to_le_bytes());
            v.extend((name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        head(&mut out);
        out.extend(name.as_bytes());
        out.extend(&body);
        cd.extend(0x0201_4b50u32.to_le_bytes());
        cd.extend([20, 0, 20, 0, 0, 0]);
        head(&mut cd);
        cd.extend([0u8; 10]);
        cd.extend(offset.to_le_bytes());
        cd.extend(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend([0u8; 2]);
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let file = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        let mut parts = rest.split(|&b| b == 0x1E);
        let export = parts.next().unwrap_or(&[]);
        let mut members = vec![("export.data".to_owned(), export, mode & 2 != 0)];
        for (i, p) in parts.take(8).enumerate() {
            let name = match i {
                0 => "files/avatar.png".to_owned(),
                n => format!("files/doc{n}__note.txt"),
            };
            members.push((name, p, false));
        }
        zip(&members)
    };
    let cancel = AtomicBool::new(false);
    let now = Time(63_900_000_000);
    let ctx = Context::new(now, &Utc, &cancel);
    let Ok(r) = onepux::read(&file, &ctx) else {
        return;
    };
    assert_eq!(app_model::invariants::check(&r.vault), Ok(()));
    let _ = import::preview(&r);
    let mut root = Group::new(Uuid([1; 16]), "Root".into(), now);
    root.groups
        .push(Group::new(Uuid([2; 16]), "Work".into(), now));
    let mut target = Vault::new(root, now);
    if import::into_group(&mut target, Uuid([2; 16]), r, now).is_ok() {
        assert_eq!(app_model::invariants::check(&target), Ok(()));
    }
});
