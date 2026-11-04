//! Fuzz target `search_query` (E4-S8): the search language (FEA-01) on
//! arbitrary query text against a demo vault with a recycle bin, search
//! flags, tags, custom fields, references and one-time password settings.
//! Must never panic or hang: the parser accepts every text (FEA-01.32),
//! a longer text than 1,024 characters or more than 16 pattern terms is
//! refused, every result is a list of live entry ids outside the bin, and
//! the run's work stays inside its meter (LD-126): never more than
//! `RUN_BUDGET`, and a run that empties it shows the notice. The wall-time
//! guard is only for real hangs: the sanitizer build runs about 50 times
//! slower than release, where a run stays under 250 ms.
//!
//! The vault here and the one in larsal-core's `fea01_32_fuzz_regressions`
//! test are the same; change both together.
//!
//! Input: a flag byte (bit 0 case-sensitive, bit 1 limit to group `Sub`,
//! bit 2 also run the text as exact tag terms split on `,`), then the
//! query text.
#![no_main]

use larsal_core::search::{Options, QueryError, RUN_BUDGET, search, search_tags};
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Group, Switch, Time, Uuid, Vault};
use libfuzzer_sys::fuzz_target;

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.to_owned(),
        Field {
            value: SecretString::new(value.to_owned()),
            protected: name == "Password",
        },
    );
}

fn entry(b: u8, fields: &[(&str, &str)], tags: &[&str]) -> Entry {
    let mut e = Entry::new(Uuid([b; 16]), Time(0));
    for (n, v) in fields {
        set(&mut e, n, v);
    }
    e.set_tags(tags.iter().map(|t| (*t).to_owned()).collect());
    e
}

fn vault() -> Vault {
    let mut root = Group::new(Uuid([1; 16]), "Vault".into(), Time(0));
    root.entries.push(entry(
        0x11,
        &[
            ("Title", "GitHub"),
            ("UserName", "alex@example.com"),
            ("Password", "Tr0ub4dor&3"),
            ("URL", "https://github.com/login"),
            ("Notes", "Work account\nrecovery codes"),
        ],
        &["work", "dev"],
    ));
    root.entries.push(entry(
        0x12,
        &[
            ("Title", "Ref {USERNAME}"),
            ("UserName", "{REF:U@I:11111111111111111111111111111111}"),
            ("Password", "{S:Secret}"),
            ("Secret", "blue whale"),
            ("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
        ],
        &["say \"hi\"", "a\\"],
    ));
    let mut sub = Group::new(Uuid([2; 16]), "Sub".into(), Time(0));
    let mut e = entry(
        0x13,
        &[("Title", "Éclair 🔑"), ("Notes", &"ab".repeat(2_000))],
        &["x*"],
    );
    e.times.expires = true;
    sub.entries.push(e);
    let mut off = Group::new(Uuid([3; 16]), "Off".into(), Time(0));
    off.searching = Switch::Off;
    off.entries.push(entry(0x14, &[("Title", "hidden")], &[]));
    let mut bin = Group::new(Uuid([4; 16]), "Bin".into(), Time(0));
    bin.searching = Switch::On;
    bin.entries
        .push(entry(0x15, &[("Title", "deleted GitHub")], &["work"]));
    root.groups.extend([sub, off, bin]);
    let mut v = Vault::new(root, Time(0));
    v.meta.recycle_bin = Some(Uuid([4; 16]));
    v
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let query = String::from_utf8_lossy(rest);
    let v = vault();
    let o = Options {
        case_sensitive: flags & 1 != 0,
        base: (flags & 2 != 0).then_some(Uuid([2; 16])),
        ..Options::new(Time(63_928_466_236))
    };
    let started = std::time::Instant::now();
    let parsed = larsal_core::search::parse::parse(&query);
    let result = search(&v, &query, &o);
    assert_eq!(parsed.is_ok(), result.is_ok());
    let too_long = query.chars().count() > 1_024;
    match &result {
        Err(QueryError::TooLong) => assert!(too_long),
        Err(QueryError::TooManyTerms) | Ok(_) => assert!(!too_long),
    }
    if let Ok(found) = result {
        for id in &found.ids {
            assert!(
                [0x11, 0x12, 0x13].contains(&id.0[0]),
                "only live, searchable entries"
            );
        }
        assert!(
            found.spent <= RUN_BUDGET,
            "the meter never goes past its budget"
        );
        if found.spent == RUN_BUDGET {
            assert!(found.invalid, "an empty meter shows the notice");
        }
    }
    if flags & 4 != 0 {
        let tags: Vec<&str> = query.split(',').take(16).collect();
        let found = search_tags(&v, &tags, &o);
        assert!(found.ids.iter().all(|id| id.0[0] != 0x15), "never the bin");
        assert!(found.spent <= RUN_BUDGET);
    }
    assert!(started.elapsed().as_secs() < 30, "a search hung");
});
