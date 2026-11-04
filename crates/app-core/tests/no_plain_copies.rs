//! E4-B1 guard: app-core reads field values in place and never copies one
//! out of its secret type into a plain string. A counting allocator would
//! prove it at run time but needs unsafe code, which the unsafe gate allows
//! only in app-platform and app-hwkey; this check stops the copying patterns
//! from coming back instead.

#[test]
fn e4_b1_no_plain_copies_of_values() {
    let banned = [
        "expose().to_owned()",
        "expose().to_string()",
        "expose().into()",
        "expose().clone()",
        "expose().chars()",
    ];
    // A case change of a text makes a new plain string; only a single
    // character named `c` may be changed (a char: no allocation).
    let case = [
        ".to_lowercase(",
        ".to_uppercase(",
        ".to_ascii_lowercase(",
        ".to_ascii_uppercase(",
    ];
    let mut dirs = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    ))];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for file in std::fs::read_dir(dir).unwrap() {
            let path = file.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 20, "the walk found the source files");
    for path in files {
        let src = std::fs::read_to_string(&path).unwrap();
        for b in banned {
            assert!(!src.contains(b), "{}: {b}", path.display());
        }
        for f in case {
            for (i, _) in src.match_indices(f) {
                let receiver = src[..i]
                    .rsplit(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                    .next();
                assert_eq!(receiver, Some("c"), "{}: {f} on a text", path.display());
            }
        }
    }
}
