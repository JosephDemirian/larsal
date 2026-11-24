//! INT-08 test cases for E11-S3's pass rules in larsal-share's run module:
//! which shares run (INT-08.15, INT-08.35), the path conflicts
//! (INT-08.18, D-INT08-7), the export order (INT-08.17), the 5 KiB hash
//! (INT-08.15) and the banner (INT-08.20); the write's own path guard
//! (INT-08.34, F-162) and the bounded merge records (F-164).

mod common;

use common::*;
use larsal_core::merge::{Kind, Options, PATH_BYTES, merge};
use larsal_format::limits::Limits;
use larsal_model::{Entry, Group, Uuid};
use larsal_share::run::{self, Level, Line, Share};
use larsal_share::{Error, container};
use std::path::Path;

/// V's shares with Team on `team` and Other(22) at the root on `other`.
fn two(team: (bool, bool, &str), other: (bool, bool, &str)) -> Vec<Share> {
    let mut v = v();
    let set = |g: &mut larsal_model::Group, (import, export, path): (bool, bool, &str)| {
        let key = share_key();
        g.custom_data.items.retain(|i| i.key != key);
        let mut s = export_to(path);
        (s.import, s.export) = (import, export);
        set_share(g, &mut s);
    };
    set(&mut v.root.groups[0], team);
    let mut o = larsal_model::Group::new(id(0x22), "Other".into(), T0);
    set(&mut o, other);
    v.root.groups.push(o);
    run::shares(&v, Some(Path::new("/demo/v.larsalvault")))
}

fn names(plan: &run::Plan, of: &[usize]) -> Vec<String> {
    of.iter().map(|&i| plan.shares[i].name.clone()).collect()
}

#[test]
fn int08_15_shares_resolve_beside_the_vault_and_skip_the_bin_and_no_file() {
    let shares = two(
        (true, false, "team.larsalvault"),
        (false, true, "/x/o.larsalvault"),
    );
    let paths: Vec<_> = shares.iter().map(|s| s.path.clone()).collect();
    assert_eq!(
        paths,
        [
            Path::new("/demo/team.larsalvault"),
            Path::new("/x/o.larsalvault")
        ]
    );
    // A vault without a file has no shares (INT-08.5).
    assert!(run::shares(&v(), None).is_empty());
    // A share in the recycle bin is inactive (INT-08.35).
    let mut v = v();
    let team = v.root.groups.remove(0);
    let mut bin = larsal_model::Group::new(id(0x50), "Bin".into(), T0);
    bin.groups.push(team);
    v.root.groups.push(bin);
    v.meta.recycle_bin_enabled = true;
    v.meta.recycle_bin = Some(id(0x50));
    assert!(run::shares(&v, Some(Path::new("/demo/v.larsalvault"))).is_empty());
}

#[test]
fn int08_7_allow_settings_off_run_nothing() {
    let plan = run::plan(two((true, true, "a"), (true, true, "b")), false, false);
    assert!(plan.imports.is_empty() && plan.exports.is_empty());
    let plan = run::plan(two((true, true, "a"), (true, true, "b")), true, false);
    assert_eq!((plan.imports.len(), plan.exports.len()), (2, 0));
}

#[test]
fn int08_17_exports_run_in_path_text_order() {
    let plan = run::plan(
        two(
            (false, true, "z.larsalvault"),
            (false, true, "a.larsalvault"),
        ),
        true,
        true,
    );
    assert_eq!(names(&plan, &plan.exports), ["Other", "Team"]);
}

#[test]
fn t31_int08_18_one_export_conflict_blocks_every_export() {
    let plan = run::plan(
        two(
            (false, true, "t.larsalvault"),
            (false, true, "t.larsalvault"),
        ),
        true,
        true,
    );
    assert!(plan.exports.is_empty());
    assert_eq!(plan.export_lines.len(), 1);
    assert_eq!(plan.export_lines[0].level, Level::Error);
}

#[test]
fn t32_d_int08_7_an_import_conflict_imports_neither() {
    let plan = run::plan(
        two(
            (true, false, "t.larsalvault"),
            (true, false, "t.larsalvault"),
        ),
        true,
        true,
    );
    assert!(plan.imports.is_empty());
    assert_eq!(plan.import_lines.len(), 1);
    assert_eq!(plan.import_lines[0].level, Level::Warning);
    // One imports and the other exports the same path: no conflict
    // (only the editor warns, MI08-13).
    let plan = run::plan(
        two(
            (true, false, "t.larsalvault"),
            (false, true, "t.larsalvault"),
        ),
        true,
        true,
    );
    assert_eq!((plan.imports.len(), plan.exports.len()), (1, 1));
    assert!(plan.import_lines.is_empty() && plan.export_lines.is_empty());
}

#[test]
fn int08_15_the_hash_reads_the_first_5_kib_only() {
    let mut a = vec![7u8; 9_000];
    let h = run::head(&a);
    a[6_000] = 8;
    assert_eq!(run::head(&a), h);
    a[5_119] = 8;
    assert_ne!(run::head(&a), h);
    assert_eq!(run::head(&a[..run::HEAD]), run::head(&a));
}

#[test]
fn t34_int08_20_one_banner_successes_first_and_quiet_drops_them() {
    let failed = run::export_failed("b", &Error::Io(std::io::ErrorKind::NotFound));
    let lines: Vec<Line> = vec![
        failed.clone(),
        run::several_import("c", &["X".into(), "Y".into()]),
        run::imported("a"),
    ];
    let b = run::banner(&lines, false).unwrap();
    assert_eq!(b.level, Level::Error);
    assert_eq!(
        b.lines,
        [
            lines[2].text.clone(),
            lines[1].text.clone(),
            failed.text.clone()
        ]
    );
    // E11-S5: each line's stored path, for the screen's mono font.
    assert_eq!(b.paths, ["a", "c", "b"]);
    let quiet = run::banner(&lines, true).unwrap();
    assert_eq!(quiet.lines, [lines[1].text.clone(), failed.text]);
    assert_eq!(quiet.paths, ["c", "b"]);
    assert_eq!(run::banner(&[run::imported("a")], true), None);
    let ok = run::banner(&[run::imported("a")], false).unwrap();
    assert_eq!(ok.level, Level::Success);
}

#[test]
fn int08_31_an_approval_names_the_vault_group_mode_and_path() {
    let v = v();
    let [a] = &run::shares(&v, Some(Path::new("/demo/v.larsalvault")))[..] else {
        panic!("one share");
    };
    let key = a.approval(&v);
    assert!(
        key.starts_with(&format!("{}:{}:", "01".repeat(16), "20".repeat(16))),
        "{key}"
    );
    assert!(!key.contains("team") && !key.contains(SHARE_PASSWORD));
    let b = run::shares(&v, Some(Path::new("/other/v.larsalvault")));
    assert_ne!(b[0].approval(&v), key, "another resolved path");
}

/// F-162 (INT-08.34, AT-I04): the export checks the open vaults' files in
/// the folder it really writes, after the KDF. The share's folder is now a
/// link to V's own folder: nothing is written, V's file is as it was and
/// no temp file stays behind; another file name in that folder is written.
#[test]
fn f162_int08_34_a_write_through_a_swapped_folder_never_replaces_an_open_vault() {
    let d = Dir::new("f162");
    let (home, shared) = (d.path("home"), d.path("shared"));
    std::fs::create_dir_all(&home).unwrap();
    let file = home.join("x.larsalvault");
    std::fs::write(&file, b"demo vault V").unwrap();
    std::os::unix::fs::symlink(&home, &shared).unwrap();
    let c = container::build(id(0x20), true, &v(), T0).unwrap();
    let pw = secret(SHARE_PASSWORD);
    let open = [file.clone()];
    let write =
        |to: &Path| container::write_file(to, &c, &pw, &mut host(), &Limits::DEFAULT, &open);
    assert_eq!(
        write(&shared.join("x.larsalvault")),
        Err(Error::Io(std::io::ErrorKind::PermissionDenied))
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"demo vault V");
    let names = || -> Vec<String> {
        let mut n: Vec<String> = std::fs::read_dir(&home)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    };
    assert_eq!(names(), ["x.larsalvault"]);
    write(&shared.join("team.larsalvault")).unwrap();
    assert_eq!(names(), ["team.larsalvault", "x.larsalvault"]);
}

/// F-164 (INT-08.38, AT-A08), Checker 2's two probes: a new group named
/// with 262,144 and 524,288 'A' holding 1,000 and 4,000 new entries. Each
/// record of the shared-group import keeps at most `PATH_BYTES` of the
/// path, then `…`, so the records cost bytes per item, not name length
/// times items.
#[test]
fn f164_at_a08_record_paths_stay_bounded_however_long_a_group_name() {
    let cut = format!(
        "/Root/Team/{}…",
        "A".repeat(PATH_BYTES - "/Root/Team/".len())
    );
    for (len, n) in [(262_144, 1_000_u32), (524_288, 4_000)] {
        let mut member = v();
        let mut long = Group::new(id(0x30), "A".repeat(len), T0);
        for i in 0..n {
            let mut u = [0x77; 16];
            u[..4].copy_from_slice(&i.to_le_bytes());
            long.entries.push(Entry::new(Uuid(u), T0));
        }
        member.root.groups[0].groups.push(long);
        let c = container::build(id(0x20), true, &member, T0).unwrap();
        let mut target = v();
        let o = Options {
            target_start: Some(id(0x20)),
            ..Options::new(Kind::SharedImport)
        };
        let records = merge(&mut target, &c, &o, NOW).unwrap().changes;
        assert_eq!(records.len(), n as usize + 1, "the group and its entries");
        assert!(records.iter().all(|r| r.path == cut), "{len}");
        let bytes: usize = records.iter().map(|r| r.path.len()).sum();
        assert_eq!(bytes, records.len() * (PATH_BYTES + '…'.len_utf8()));
        assert_eq!(
            group(&target, id(0x30)).name.len(),
            len,
            "the name itself is whole"
        );
    }
}
