//! INT-03's URL matching cases (story E7-S3): T01 to T90 on the matcher
//! level, the list project's `test_psl.txt` (LD-303 (6)), and AT-F05. The
//! cases INT-03 runs "through `logins.find`" call the same functions the
//! bridge's handler calls (E7-S2): [`Page::read`] (error 14), [`Page::rank`]
//! for each entry of a vault walked in INT-02.13's order, then [`order`].
//! Hosts are reserved demo names (RFC 2606, RFC 6761); `github.io` and
//! `co.uk` appear only as public suffixes. Demo data only.

use larsal_browser::{
    MAX_ENTRY_URL, MAX_PATTERN_LABELS, MAX_STARS, MAX_URLS, NOT_A_PAGE, Note, Page, Site,
    extra_url_order, list_version, note, order, registrable_domain,
};
use larsal_core::refs::{COPY_BUDGET, Context, EntryIndex};
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Group, Time, Uuid, Vault};
use std::cell::Cell;
use std::time::Duration;

fn set(e: &mut Entry, name: &str, value: &str) {
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected: false,
        },
    );
}

/// An entry with main URL `main` and additional URLs `KP2A_URL`,
/// `KP2A_URL_1`, … in that order.
fn entry(main: &str, extra: &[&str]) -> Entry {
    let mut e = Entry::new(Uuid([0x11; 16]), Time(0));
    set(&mut e, "URL", main);
    for (i, v) in extra.iter().enumerate() {
        let name = if i == 0 {
            "KP2A_URL".to_owned()
        } else {
            format!("KP2A_URL_{i}")
        };
        set(&mut e, &name, v);
    }
    e
}

/// The rank of `e` on `page` (S-BRW-11 on, no form URL, no site data).
fn rank(e: &Entry, page: &str) -> Option<u8> {
    rank_with(e, page, None, true, &Site::NONE)
}

fn rank_with(
    e: &Entry,
    page: &str,
    form: Option<&str>,
    match_scheme: bool,
    site: &Site<'_>,
) -> Option<u8> {
    Page::read(page, form, match_scheme)
        .unwrap()
        .rank(e, &Context::new(None, Time(0)), site)
}

/// Main URL `url` on `page`.
fn main_on(url: &str, page: &str) -> Option<u8> {
    rank(&entry(url, &[]), page)
}

/// One additional URL `url` on `page`.
fn extra_on(url: &str, page: &str) -> Option<u8> {
    rank(&entry("", &[url]), page)
}

fn cpu() -> Duration {
    larsal_platform::macos::thread_cpu_time()
}

// --- INT-03.3, INT-03.5: reading entry URLs, schemes ---

#[test]
fn t01_to_t05_int03_3_and_int03_5_schemes_and_the_default_https() {
    assert_eq!(
        main_on("https://example.com", "https://example.com/"),
        Some(100),
        "T01"
    );
    assert_eq!(
        main_on("example.com", "https://example.com/login"),
        Some(85),
        "T02"
    );
    assert_eq!(main_on("example.com", "http://example.com/"), None, "T03");
    let e = entry("example.com", &[]);
    assert_eq!(
        rank_with(&e, "http://example.com/", None, false, &Site::NONE),
        Some(0),
        "T04"
    );
    assert_eq!(
        main_on("http://example.com", "https://example.com/"),
        None,
        "T05"
    );
    // The scheme is read without letter case.
    assert_eq!(
        main_on("HTTPS://example.com", "https://example.com/"),
        Some(100)
    );
}

#[test]
fn t63_t87_int03_3_other_schemes_never_fit() {
    for url in [
        "cmd://open https://example.com",
        "ftp://example.com",
        "ssh://example.com",
        "file:///Users/demo/page.html",
        "mailto:alex@example.com",
        "tel:+15550100",
        "data:text/html,example.com",
        "javascript:alert(1)",
    ] {
        assert_eq!(main_on(url, "https://example.com/"), None, "main {url}");
        assert_eq!(extra_on(url, "https://example.com/"), None, "add. {url}");
    }
    // A host with a port is not a scheme.
    assert_eq!(
        main_on("localhost:3000", "https://localhost:3000/"),
        Some(100)
    );
    assert_eq!(
        main_on("example.com:8443/x", "https://example.com:8443/x"),
        Some(100)
    );
}

#[test]
fn t16_t64_int03_3_forbidden_characters_never_fit() {
    for url in [
        "https://exa mple.com",
        "https://example.com/<x>",
        "https://example.com/a^b",
        "https://example.com/a`b",
        "https://example.com/{S:x}",
        "https://example.com/a|b",
        "https://example.com/a\tb",
        "https://example.com/a\u{3000}b",
        "https://example.com/a\nb",
    ] {
        assert_eq!(main_on(url, "https://example.com/"), None, "{url:?}");
    }
    // LD-322 (3): a newline inside never fits, not even a quoted exact URL
    // or a file URL that equals its page character for character.
    let page = "https://example.com/a\nb";
    assert_eq!(extra_on("\"https://example.com/a\nb\"", page), None);
    let file = "file:///Users/demo/a\nb.html";
    assert_eq!(main_on(file, file), None);
    // Spaces and tabs at both ends are removed.
    assert_eq!(
        main_on(" \thttps://example.com\t ", "https://example.com/"),
        Some(100)
    );
    // F-239: only spaces and tabs are trimmed; other white space at an end
    // never fits.
    for url in ["https://example.com\n", "https://example.com\u{a0}"] {
        assert_eq!(main_on(url, "https://example.com/"), None, "{url:?}");
    }
    // LD-328 (3): a control character inside never fits either.
    for url in [
        "https://example.com/a\u{0}b",
        "https://example.com/a\u{7f}b",
    ] {
        assert_eq!(main_on(url, "https://example.com/"), None, "{url:?}");
    }
}

#[test]
fn t65_int03_3_user_info_and_fragment_are_ignored() {
    assert_eq!(
        main_on("https://user:pw@example.com", "https://example.com/"),
        Some(100),
        "T65"
    );
    assert_eq!(
        main_on("https://example.com/#top", "https://example.com/"),
        Some(100)
    );
    assert_eq!(
        main_on("https://example.com", "https://u:p@example.com/#x"),
        Some(100)
    );
    // The last `@` ends the user info, as in WHATWG: the host is the one
    // after it.
    assert_eq!(
        main_on("https://example.com@evil.example", "https://example.com/"),
        None
    );
    // `\` ends the authority (WHATWG for http and https), so the text after
    // it is no host of the entry.
    assert_eq!(
        main_on(
            "https://example.com\\@evil.example/",
            "https://evil.example/"
        ),
        None
    );
    assert_eq!(
        main_on(
            "https://example.com\\@evil.example/",
            "https://example.com/"
        ),
        Some(80)
    );
    assert_eq!(
        main_on("https://evil.example#@example.com", "https://example.com/"),
        None
    );
}

// --- INT-03.4: hosts ---

#[test]
fn t11_to_t15_int03_4_hosts_compare_in_ascii_form() {
    assert_eq!(
        main_on("https://example.com", "https://xn--exmple-4nf.com/"),
        None,
        "T11"
    );
    assert_eq!(
        main_on("https://bücher.example", "https://xn--bcher-kva.example/"),
        Some(100),
        "T12"
    );
    assert_eq!(
        main_on("https://BÜCHER.example/", "https://xn--bcher-kva.example/"),
        Some(100),
        "T13"
    );
    assert_eq!(
        main_on("https://EXAMPLE.com", "https://example.com/"),
        Some(100),
        "T14"
    );
    assert_eq!(
        main_on("https://example.com.", "https://example.com/"),
        Some(100),
        "T15"
    );
    // The page's own trailing dot is removed too.
    assert_eq!(
        main_on("https://example.com", "https://example.com./"),
        Some(100)
    );
    // A Cyrillic `а` entry is its own host, never `example.com`.
    assert_eq!(main_on("https://exаmple.com", "https://example.com/"), None);
    assert_eq!(
        main_on("https://exаmple.com", "https://xn--exmple-4nf.com/"),
        Some(100)
    );
}

#[test]
fn t24_int03_4_invalid_hosts_never_fit() {
    for url in [
        "http://192.168.001.001",
        "http://0x7f.1",
        "http://3232235777",
        "http://127.1",
        "https://example.123",
        "https://example..com",
        "https://example.com..",
        "https://.example.com",
        "https://[::1]x",
        "https://[example.com]",
        "https://ex!ample.com",
        "https://example.com:65536",
        "https://example.com:44x",
        "https://example。com",
        "https://\u{3000}example.com",
        "https://\u{200b}example.com",
    ] {
        assert_eq!(main_on(url, "https://example.com/"), None, "{url:?}");
        assert_eq!(main_on(url, "http://192.168.1.1/"), None, "{url:?}");
        assert_eq!(main_on(url, "http://127.0.0.1/"), None, "{url:?}");
    }
    // DNS limits after encoding (LD-112): a label of 63 octets fits, 64 not.
    let label = "a".repeat(63);
    let ok = format!("https://{label}.example");
    assert_eq!(main_on(&ok, &format!("{ok}/")), Some(100));
    let long = format!("https://{label}a.example");
    assert_eq!(main_on(&long, "https://example/"), None);
    // F-235: a host of 253 octets fits, 254 not (LD-112).
    let h253 = format!("{label}.{label}.{label}.{}", "d".repeat(61));
    let h254 = format!("{label}.{label}.{label}.{}", "d".repeat(62));
    assert_eq!((h253.len(), h254.len()), (253, 254));
    assert_eq!(
        main_on(&format!("https://{h253}"), &format!("https://{h253}/")),
        Some(100)
    );
    assert_eq!(
        Page::read(&format!("https://{h254}/"), None, true).err(),
        Some(NOT_A_PAGE)
    );
    assert_eq!(registrable_domain(&h254), None);
    // `_` is a host character.
    assert_eq!(
        main_on("https://a_b.example.com", "https://a_b.example.com/"),
        Some(100)
    );
}

#[test]
fn t22_t23_t25_int03_4_and_int03_7_ip_addresses_by_equality() {
    assert_eq!(
        main_on("http://192.168.1.1", "http://192.168.1.1/"),
        Some(100),
        "T22"
    );
    assert_eq!(
        main_on("http://192.168.1.1", "http://192.168.1.10/"),
        None,
        "T23"
    );
    assert_eq!(
        main_on("http://[0:0:0:0:0:0:0:1]:8080", "http://[::1]:8080/"),
        Some(100),
        "T25"
    );
    assert_eq!(main_on("http://[::1]", "http://[::2]/"), None);
    assert_eq!(
        main_on("http://1.168.192.in-addr.arpa", "http://192.168.1.1/"),
        None
    );
}

// --- INT-03.6: ports ---

#[test]
fn t17_to_t21_int03_6_effective_ports() {
    assert_eq!(
        main_on("https://example.com:8443", "https://example.com:8443/x"),
        Some(85),
        "T17"
    );
    assert_eq!(
        main_on("https://example.com:8443", "https://example.com/"),
        None,
        "T18"
    );
    assert_eq!(
        main_on("https://example.com", "https://example.com:8443/"),
        None,
        "T19"
    );
    assert_eq!(
        main_on("https://example.com:443", "https://example.com/"),
        Some(100),
        "T20"
    );
    let e = entry("example.com", &[]);
    assert_eq!(
        rank_with(&e, "http://example.com:8080/", None, false, &Site::NONE),
        None,
        "T21"
    );
    assert_eq!(
        rank_with(&e, "http://example.com/", None, false, &Site::NONE),
        Some(0)
    );
}

// --- INT-03.7, INT-03.10: hosts below, registrable domains ---

#[test]
fn t06_to_t10_int03_7_subdomains_by_whole_labels_in_one_registrable_domain() {
    assert_eq!(
        main_on("https://example.com", "https://mail.example.com/"),
        Some(60),
        "T06"
    );
    assert_eq!(
        main_on("https://example.com", "https://a.b.example.com/x"),
        Some(60),
        "T07"
    );
    assert_eq!(
        main_on("https://mail.example.com", "https://example.com/"),
        None,
        "T08"
    );
    assert_eq!(
        main_on("https://b.example.com", "https://ab.example.com/"),
        None,
        "T09"
    );
    assert_eq!(
        main_on(
            "https://example.com",
            "https://example.com.attacker.example/"
        ),
        None,
        "T10"
    );
}

#[test]
fn t26_to_t28_int03_7_one_label_hosts_by_equality() {
    assert_eq!(
        main_on("https://localhost:3000", "https://localhost:3000/"),
        Some(100),
        "T26"
    );
    assert_eq!(main_on("https://nas", "https://nas/"), Some(100), "T27");
    assert_eq!(main_on("https://nas", "https://x.nas/"), None, "T28");
    assert_eq!(
        main_on("https://localhost", "https://localhost:3000/"),
        None
    );
}

#[test]
fn t29_to_t32_int03_10_a_public_suffix_fits_nothing() {
    assert_eq!(main_on("https://co.uk", "https://bank.co.uk/"), None, "T29");
    assert_eq!(main_on("https://co.uk", "https://co.uk/"), None);
    assert_eq!(
        main_on("https://name.github.io", "https://name.github.io/"),
        Some(100),
        "T30"
    );
    assert_eq!(
        main_on("https://name.github.io", "https://other.github.io/"),
        None,
        "T31"
    );
    assert_eq!(
        main_on("https://github.io", "https://name.github.io/"),
        None,
        "T32"
    );
    assert_eq!(main_on("https://github.io", "https://github.io/"), None);
}

#[test]
fn t78_int03_10_registrable_domains() {
    for (host, want) in [
        ("mail.example.com", Some("example.com")),
        ("a.b.bank.co.uk", Some("bank.co.uk")),
        ("user.github.io", Some("user.github.io")),
        ("a.b.example", Some("b.example")),
        ("co.uk", None),
        ("192.0.2.1", None),
        ("localhost", None),
        ("[::1]", None),
        ("MAIL.Example.COM.", Some("example.com")),
        ("bücher.example", Some("xn--bcher-kva.example")),
        ("a..example.com", None),
        // No Unicode mapping (D-INT03-5): white space is refused, not trimmed.
        ("\u{3000}example.com", None),
        ("example.com\u{3000}", None),
        ("", None),
    ] {
        assert_eq!(registrable_domain(host).as_deref(), want, "{host}");
    }
}

/// `test_psl.txt` of the list project (CC0), the same commit as the list
/// (LD-303 (6)): every `checkPublicSuffix(input, expected)` line, with the
/// input and the expected value in ASCII form (INT-11.44, T83 there).
#[test]
fn int03_10_the_list_projects_test_psl_cases_all_pass() {
    let text = include_str!("../../../vendor/public-suffix-list/test_psl.txt");
    let value = |s: &str| match s.trim() {
        "null" => None,
        quoted => Some(quoted.trim_matches('\'').to_owned()),
    };
    let mut cases = 0;
    for line in text.lines() {
        let Some(args) = line
            .strip_prefix("checkPublicSuffix(")
            .and_then(|l| l.strip_suffix(");"))
        else {
            continue;
        };
        let (input, expected) = args.split_once(", ").unwrap();
        let (input, expected) = (value(input), value(expected));
        let want = expected.map(|e| larsal_core::url::site_host(&e).unwrap());
        let got = input.as_deref().and_then(registrable_domain);
        assert_eq!(got, want, "{line}");
        cases += 1;
    }
    // SOURCE.txt: 82 checkPublicSuffix cases, 4 of them commented out.
    assert_eq!(cases, 78);
}

/// LD-330 (4): every rule of the list, behind a few prefixes, against an
/// independent run of the list's formal algorithm that walks every label
/// of the host (no bound of its own), so a walk that stops one suffix
/// short of the longest rule fails here.
#[test]
fn int03_10_registrable_domain_equals_a_label_by_label_run_of_every_rule() {
    use std::collections::HashSet;
    let list = include_str!("../../../vendor/public-suffix-list/public_suffix_list.dat");
    let ascii = |s: &str| larsal_core::url::site_host(s).unwrap();
    let (mut plain, mut wild, mut except) = (HashSet::new(), HashSet::new(), HashSet::new());
    let mut rules = Vec::new();
    for rule in list.lines().filter_map(|l| l.split_whitespace().next()) {
        if rule.starts_with("//") {
            continue;
        }
        if let Some(n) = rule.strip_prefix('!') {
            except.insert(ascii(n));
        } else if let Some(n) = rule.strip_prefix("*.") {
            wild.insert(ascii(n));
        } else {
            plain.insert(ascii(rule));
        }
        rules.push(rule);
    }
    // The formal algorithm, label by label from the right: the matching
    // rule with the most labels, `*` standing for one label; an exception
    // wins and loses its leftmost label; no match is the rule `*`.
    let expected = |host: &str| -> Option<String> {
        let labels: Vec<&str> = host.split('.').collect();
        let suffix = |k: usize| labels[labels.len() - k..].join(".");
        let mut matched = 1;
        let mut exception = None;
        for k in 1..=labels.len() {
            let s = suffix(k);
            if except.contains(&s) {
                exception = Some(k - 1);
            }
            if plain.contains(&s) || (k > 1 && wild.contains(&suffix(k - 1))) {
                matched = k;
            }
        }
        let k = exception.unwrap_or(matched);
        (labels.len() > k).then(|| suffix(k + 1))
    };
    let mut cases = 0;
    for rule in &rules {
        let name = ascii(&rule.trim_start_matches('!').replace('*', "w"));
        for prefix in ["", "a.", "b.a.", "x.y.z."] {
            let host = format!("{prefix}{name}");
            if host.len() > 253 {
                continue;
            }
            assert_eq!(
                registrable_domain(&host),
                expected(&host),
                "{rule} as {host}"
            );
            cases += 1;
        }
    }
    assert!(cases > 40_000, "{cases}");
}

#[test]
fn t89_int03_19_the_build_carries_the_list_and_its_version() {
    let source = include_str!("../../../vendor/public-suffix-list/SOURCE.txt");
    assert_eq!(list_version(), "73f8cc701c084fe07d888ec552b2f0b53281a674");
    assert!(source.contains(list_version()));
    // Rules from both sections, wildcards and exceptions are in.
    assert_eq!(
        registrable_domain("a.b.bank.co.uk").as_deref(),
        Some("bank.co.uk")
    );
    assert_eq!(
        registrable_domain("x.y.github.io").as_deref(),
        Some("y.github.io")
    );
    assert_eq!(registrable_domain("a.b.c.mm").as_deref(), Some("b.c.mm"));
    assert_eq!(registrable_domain("www.www.ck").as_deref(), Some("www.ck"));
}

#[test]
fn t90_int03_19_a_suffix_missing_from_the_list_still_keeps_tenants_apart() {
    assert_eq!(
        registrable_domain("a.tenant.example").as_deref(),
        Some("tenant.example")
    );
    assert_eq!(
        registrable_domain("b.tenant.example").as_deref(),
        Some("tenant.example")
    );
    assert_eq!(
        main_on("https://a.tenant.example", "https://b.tenant.example/"),
        None
    );
}

// --- INT-03.8, INT-03.9 ---

#[test]
fn t58_int03_8_paths_never_decide_a_plain_url() {
    assert_eq!(
        main_on("https://example.com/login", "https://example.com/other"),
        Some(80)
    );
    assert_eq!(
        extra_on("https://example.com/login", "https://example.com/other"),
        Some(80),
        "T58"
    );
}

#[test]
fn t33_to_t35_int03_9_one_leading_www_with_the_group_option() {
    let www = Site {
        omit_www: true,
        ..Site::NONE
    };
    let e = entry("https://www.example.com", &[]);
    assert_eq!(
        rank_with(&e, "https://example.com/", None, true, &www),
        Some(100),
        "T33"
    );
    assert_eq!(
        rank_with(&e, "https://mail.example.com/", None, true, &www),
        Some(60)
    );
    assert_eq!(rank(&e, "https://example.com/"), None, "T34");
    let e = entry("https://www.mywww.example.com", &[]);
    assert_eq!(
        rank_with(&e, "https://mywww.example.com/", None, true, &www),
        Some(100),
        "T35"
    );
    assert_eq!(
        rank_with(&e, "https://myexample.com/", None, true, &www),
        None
    );
    // Only a whole first label.
    let e = entry("https://wwwx.example.com", &[]);
    assert_eq!(
        rank_with(&e, "https://x.example.com/", None, true, &www),
        None
    );
    // F-246: `www` is kept when what is left has no registrable domain
    // (INT-03.10): a one-label host or a public suffix.
    let e = entry("https://www.example", &[]);
    assert_eq!(
        rank_with(&e, "https://example/", None, true, &www),
        None,
        "F-246"
    );
    for host in ["www.example", "www.github.io", "www.co.uk"] {
        let e = entry(&format!("https://{host}"), &[]);
        assert_eq!(
            rank_with(&e, &format!("https://{host}/"), None, true, &www),
            Some(100),
            "F-246 {host}"
        );
    }
}

// --- INT-03.11: quoted exact URLs and patterns ---

#[test]
fn t36_t37_int03_11_quoted_exact_urls() {
    let q = "\"https://example.com/login.php\"";
    assert_eq!(
        extra_on(q, "https://example.com/login.php"),
        Some(100),
        "T36"
    );
    assert_eq!(
        extra_on(q, "https://example.com/login.php?x=1"),
        None,
        "T37"
    );
    assert_eq!(extra_on(q, "https://example.com/login.php#top"), Some(100));
    // F-237: the page text keeps `?` and the query.
    assert_eq!(
        extra_on(
            "\"https://example.com/login.php?x=1\"",
            "https://example.com/login.php?x=1"
        ),
        Some(100)
    );
    // F-234: the fragment is ignored on both sides (INT-03.1, INT-03.3).
    assert_eq!(
        extra_on("\"https://example.com/a#top\"", "https://example.com/a#top"),
        Some(100)
    );
    assert_eq!(
        extra_on("\"https://example.com/a#top\"", "https://example.com/a"),
        Some(100)
    );
    assert_eq!(extra_on("\"\"", "https://example.com/"), None);
    // LD-323 (3): character for character, so the case counts.
    assert_eq!(
        extra_on("\"https://example.com/Admin\"", "https://example.com/admin"),
        None
    );
    assert_eq!(
        extra_on("\"https://example.com/*\"", "https://example.com/*"),
        None
    );
    // In the main URL, quotes have no meaning.
    assert_eq!(main_on(q, "https://example.com/login.php"), None);
}

#[test]
fn t38_to_t44_int03_11_host_patterns_are_anchored_with_a_registrable_tail() {
    let p = "https://*.example.com";
    assert_eq!(extra_on(p, "https://a.example.com/x"), Some(40), "T38");
    assert_eq!(extra_on(p, "https://a.b.example.com/"), Some(40), "T39");
    assert_eq!(extra_on(p, "https://example.com/"), None, "T40");
    assert_eq!(
        extra_on(p, "https://x.example.com.attacker.example/"),
        None,
        "T41"
    );
    assert_eq!(
        extra_on("https://*.com/*", "https://shop.com/"),
        None,
        "T42"
    );
    assert_eq!(
        extra_on("https://*.github.io", "https://name.github.io/"),
        None,
        "T43"
    );
    assert_eq!(
        extra_on("https://example.*", "https://example.org/"),
        None,
        "T44"
    );
    for refused in [
        "https://*.co.uk",
        "https://*example.com",
        "https://a.*",
        "https://*.example.123",
        "https://*.tenant.*.example",
        "https://*.localhost",
    ] {
        assert_eq!(
            extra_on(refused, "https://a.example.com/"),
            None,
            "{refused}"
        );
        assert_eq!(note(refused), Some(Note::RefusedPattern), "{refused}");
    }
    // Fixed labels are in host form.
    assert_eq!(
        extra_on("https://*.EXAMPLE.com", "https://a.example.com/"),
        Some(40)
    );
    assert_eq!(
        extra_on(
            "https://*.bücher.example",
            "https://a.xn--bcher-kva.example/"
        ),
        Some(40)
    );
    assert_eq!(
        extra_on("https://bü*.example.com", "https://xn--b-xga.example.com/"),
        None
    );
}

/// F-230: a name pattern fits only pages in its tail's registrable domain
/// (INT-03.7, AT-F05 attacker subdomains). `srcf.net` is a registrable
/// domain with the private suffix `user.srcf.net` below it, so
/// `alex.user.srcf.net` is another tenant's site, as is each
/// `execute-api.<region>.amazonaws.com` tenant.
#[test]
fn f230_int03_7_int03_11_at_f05_a_pattern_stays_in_its_tails_registrable_domain() {
    let tenant = "https://alex.user.srcf.net/";
    assert_eq!(
        registrable_domain("alex.user.srcf.net").as_deref(),
        Some("alex.user.srcf.net")
    );
    assert_eq!(main_on("https://srcf.net", tenant), None);
    assert_eq!(extra_on("https://*.srcf.net", tenant), None);
    assert_eq!(extra_on("https://*.srcf.net/*", tenant), None);
    assert_eq!(extra_on("https://alex.*.srcf.net", tenant), None);
    assert_eq!(
        extra_on("https://*.srcf.net", "https://www.srcf.net/"),
        Some(40)
    );
    assert_eq!(
        extra_on(
            "https://*.amazonaws.com",
            "https://tenant.execute-api.af-south-1.amazonaws.com/"
        ),
        None
    );
    // A tail longer than its registrable domain still fits below it.
    assert_eq!(
        extra_on("https://*.mail.example.com", "https://a.mail.example.com/"),
        Some(40)
    );
}

#[test]
fn t45_to_t49_int03_11_labels_and_paths() {
    let p = "https://sub.*.example.com/*/second";
    assert_eq!(
        extra_on(p, "https://sub.x.example.com/a/second"),
        Some(40),
        "T45"
    );
    assert_eq!(
        extra_on(p, "https://sub.x.y.example.com/a/b/second"),
        Some(40)
    );
    assert_eq!(
        extra_on(p, "https://sub.x.example.com/a/second/more"),
        None,
        "T46"
    );
    assert_eq!(extra_on(p, "https://sub.example.com/a/second"), None);
    assert_eq!(extra_on(p, "https://x.sub.y.example.com/a/second"), None);
    // F-231: each middle `*` label stands for one label or more, never none.
    let p = "https://a.*.b.*.example.com";
    assert_eq!(extra_on(p, "https://a.x.b.y.example.com/"), Some(40));
    assert_eq!(extra_on(p, "https://a.b.y.example.com/"), None);
    // F-231: each fixed part between `*`s is used once, parts never overlap.
    let p = "https://example.com/*a*a*a";
    assert_eq!(extra_on(p, "https://example.com/aaa"), Some(40));
    assert_eq!(extra_on(p, "https://example.com/a"), None);
    // LD-330 (4): the last part never reuses what an earlier part took.
    assert_eq!(
        extra_on("https://*.example.com/a*a", "https://x.example.com/a"),
        None
    );
    let p = "https://example.com/*";
    assert_eq!(extra_on(p, "https://example.com/"), Some(40), "T47");
    assert_eq!(extra_on(p, "https://example.com/a/b"), Some(40), "T47");
    assert_eq!(extra_on(p, "https://www.example.com/a/b"), None);
    assert_eq!(
        extra_on("https://app-*.example.com", "https://app-eu.example.com/"),
        Some(40),
        "T48"
    );
    assert_eq!(
        extra_on("https://app-*.example.com", "https://xapp-eu.example.com/"),
        None,
        "T49"
    );
    assert_eq!(
        extra_on("https://app-*.example.com", "https://app-.example.com/"),
        Some(40)
    );
    // Percent escapes: the pattern's path is encoded as WHATWG encodes
    // paths, hex digits compared without letter case.
    assert_eq!(
        extra_on("https://example.com/ü*", "https://example.com/%C3%BCber"),
        Some(40)
    );
    assert_eq!(
        extra_on(
            "https://example.com/%c3%bc*",
            "https://example.com/%C3%BCber"
        ),
        Some(40)
    );
    assert_eq!(
        extra_on("https://example.com/a*", "https://example.com/b"),
        None
    );
    // A fixed host in a pattern fits as INT-03.7 says: a public suffix
    // never, an IP address or a one-label host by equality.
    assert_eq!(extra_on("https://github.io/*", "https://github.io/x"), None);
    assert_eq!(note("https://co.uk/*"), Some(Note::RefusedPattern));
    assert_eq!(
        extra_on("https://localhost:3000/*", "https://localhost:3000/a"),
        Some(40)
    );
    assert_eq!(
        extra_on("http://192.168.1.1/admin/*", "http://192.168.1.1/admin/x"),
        Some(40)
    );
    assert_eq!(
        extra_on("http://192.168.1.1/admin/*", "http://192.168.1.2/admin/x"),
        None
    );
}

#[test]
fn t50_to_t53_int03_11_ip_address_patterns() {
    assert_eq!(
        extra_on("https://127.128.*/", "https://127.128.129.130/"),
        Some(40),
        "T50"
    );
    assert_eq!(
        extra_on("https://127.128.*/", "https://127.1.129.130/"),
        None,
        "T51"
    );
    assert_eq!(
        extra_on("https://127.160.*.2/login", "https://127.160.8.2/login"),
        Some(40),
        "T52"
    );
    assert_eq!(
        extra_on("https://127.160.*.2/login", "https://127.160.8.3/login"),
        None
    );
    assert_eq!(
        extra_on("http://[2001:db8::*]/", "http://[2001:db8::1]/"),
        None,
        "T53"
    );
    assert_eq!(
        extra_on("https://*.128.129.130/", "https://127.128.129.130/"),
        None
    );
    assert_eq!(
        extra_on("https://127.*.*.*.*/", "https://127.128.129.130/"),
        None
    );
    assert_eq!(extra_on("https://127.*/", "https://example.com/"), None);
}

#[test]
fn t54_to_t57_int03_11_ports_schemes_and_refused_forms() {
    assert_eq!(
        extra_on("https://example.com:8448/*", "https://example.com:8449/a"),
        None,
        "T54"
    );
    assert_eq!(
        extra_on("https://example.com/*/*", "https://example.com:8449/a/b"),
        None,
        "T55"
    );
    assert_eq!(
        extra_on(
            "https://example.com:8449/*/*",
            "https://example.com:8449/a/b"
        ),
        Some(40)
    );
    for p in [
        "http*://example.com",
        "https://**.example.com",
        "https://*.*.example.com",
    ] {
        assert_eq!(extra_on(p, "https://a.example.com/"), None, "T56 {p}");
        assert_eq!(extra_on(p, "https://a.b.example.com/"), None, "T56 {p}");
        assert_eq!(note(p), Some(Note::RefusedPattern), "T56 {p}");
    }
    assert_eq!(
        extra_on("https://example.com:*/", "https://example.com/"),
        None
    );
    assert_eq!(extra_on("*", "https://example.com/"), None);
    assert_eq!(extra_on("***", "https://example.com/"), None);
    assert_eq!(
        main_on("https://*.example.com", "https://a.example.com/"),
        None,
        "T57"
    );
    // Scheme: S-BRW-11 as for plain URLs.
    let e = entry("", &["https://*.example.com"]);
    assert_eq!(rank(&e, "http://a.example.com/"), None);
    assert_eq!(
        rank_with(&e, "http://a.example.com/", None, false, &Site::NONE),
        Some(0)
    );
}

// --- INT-03.2: which URLs, resolved how ---

/// A vault with the entries given, under the root.
fn vault(entries: Vec<Entry>) -> Vault {
    let mut root = Group::new(Uuid([0xA0; 16]), "Root".into(), Time(0));
    root.entries = entries;
    Vault::new(root, Time(0))
}

#[test]
fn t59_to_t62_int03_2_references_placeholders_and_the_passkey_field() {
    let target = Uuid([0x22; 16]);
    let mut t = Entry::new(target, Time(0));
    set(&mut t, "URL", "https://example.com");
    let hex: String = target.0.iter().map(|b| format!("{b:02X}")).collect();
    let mut by_ref = Entry::new(Uuid([0x33; 16]), Time(0));
    set(&mut by_ref, "URL", &format!("{{REF:A@I:{hex}}}"));
    let mut main_ph = Entry::new(Uuid([0x44; 16]), Time(0));
    set(&mut main_ph, "URL", "https://{S:host}/");
    set(&mut main_ph, "host", "example.com");
    let mut extra_ph = Entry::new(Uuid([0x55; 16]), Time(0));
    set(&mut extra_ph, "KP2A_URL", "https://{S:host}/");
    set(&mut extra_ph, "host", "example.com");
    let mut passkey = Entry::new(Uuid([0x66; 16]), Time(0));
    set(&mut passkey, "KPEX_PASSKEY_RELYING_PARTY", "example.com");
    let v = vault(vec![t, by_ref, main_ph, extra_ph, passkey]);
    let ctx = Context::new(Some(&v), Time(0));
    let page = Page::read("https://example.com/", None, true).unwrap();
    let at = |i: usize| page.rank(&v.root.entries[i], &ctx, &Site::NONE);
    assert_eq!(at(1), Some(100), "T59");
    assert_eq!(at(2), None, "T60");
    assert_eq!(at(3), Some(100), "T61");
    let login = Page::read("https://example.com/login", None, true).unwrap();
    assert_eq!(
        login.rank(&v.root.entries[4], &ctx, &Site::NONE),
        Some(85),
        "T62"
    );
    // F-235: the passkey field is always resolved and read as an
    // additional URL (INT-03.2 item 3, INT-04.8).
    let mut rp = Entry::new(Uuid([0x88; 16]), Time(0));
    set(&mut rp, "KPEX_PASSKEY_RELYING_PARTY", "https://{S:host}/");
    set(&mut rp, "host", "example.com");
    assert_eq!(rank(&rp, "https://example.com/"), Some(100));
    let mut rp = Entry::new(Uuid([0x88; 16]), Time(0));
    set(
        &mut rp,
        "KPEX_PASSKEY_RELYING_PARTY",
        "https://*.example.com",
    );
    assert_eq!(rank(&rp, "https://a.example.com/"), Some(40));
    // A reference that cannot be resolved stays as stored and never fits.
    let mut broken = Entry::new(Uuid([0x77; 16]), Time(0));
    set(
        &mut broken,
        "URL",
        "{REF:A@I:00000000000000000000000000000099}",
    );
    let v = vault(vec![broken]);
    let ctx = Context::new(Some(&v), Time(0));
    assert_eq!(page.rank(&v.root.entries[0], &ctx, &Site::NONE), None);
    // History items have no URLs for matching: only the entry's own fields.
    let mut e = entry("https://other.example", &[]);
    e.history.push(entry("https://example.com", &[]));
    assert_eq!(rank(&e, "https://example.com/"), None);
}

#[test]
fn t85_int03_2_additional_urls_in_order() {
    let mut names = vec![
        "KP2A_URL_10",
        "KP2A_URLX",
        "KP2A_URL_2",
        "KP2A_URL",
        "KP2A_URL_B",
    ];
    names.sort_by(|a, b| extra_url_order(a, b));
    assert_eq!(
        names,
        [
            "KP2A_URL",
            "KP2A_URL_2",
            "KP2A_URL_10",
            "KP2A_URLX",
            "KP2A_URL_B"
        ],
        "T85"
    );
}

// --- INT-03.12, INT-03.13 ---

#[test]
fn t68_to_t70_int03_12_allowed_hosts() {
    let e = entry("https://example.com", &[]);
    let allow = ["example.org".to_owned()];
    let site = Site {
        allow: &allow,
        ..Site::NONE
    };
    assert_eq!(
        rank_with(&e, "https://example.org/", None, true, &site),
        Some(80),
        "T68"
    );
    for page in [
        "http://example.org/",
        "https://sub.example.org/",
        "https://example.org:8443/",
    ] {
        assert_eq!(rank_with(&e, page, None, true, &site), None, "T69 {page}");
    }
    assert_eq!(
        rank_with(&e, "http://example.org/", None, false, &site),
        Some(80)
    );
    let both = Site {
        allow: &allow,
        deny: &allow,
        ..Site::NONE
    };
    assert_eq!(
        rank_with(&e, "https://example.org/", None, true, &both),
        None,
        "T70"
    );
    // Listed hosts are read in host form (INT-02.16).
    let allow = ["EXAMPLE.org.".to_owned()];
    let site = Site {
        allow: &allow,
        ..Site::NONE
    };
    assert_eq!(
        rank_with(&e, "https://example.org/", None, true, &site),
        Some(80)
    );
    // A denied page host never fits, not even through the entry's URL.
    let deny = ["example.com".to_owned()];
    let site = Site {
        deny: &deny,
        ..Site::NONE
    };
    assert_eq!(
        rank_with(&e, "https://example.com/", None, true, &site),
        None
    );
}

#[test]
fn t66_t67_int03_13_file_pages_need_the_exact_url() {
    let f = "file:///Users/demo/page.html";
    assert_eq!(main_on(f, f), Some(100), "T66");
    assert_eq!(main_on("https://example.com", f), None, "T67");
    assert_eq!(main_on("file:///Users/demo/other.html", f), None);
    // F-231: exact, so a parent folder or the bare scheme fits nothing.
    assert_eq!(main_on("file:///Users/demo/", f), None);
    assert_eq!(main_on("file://", f), None);
    assert_eq!(main_on(f, "https://example.com/"), None);
    // F-234: the fragment is ignored on both sides (INT-03.1).
    let fx = "file:///Users/demo/page.html#x";
    assert_eq!(main_on(fx, fx), Some(100));
    assert_eq!(main_on(fx, f), Some(100));
    // F-239: a main URL holding `*` never fits, on a file page too (INT-03.3).
    let star = "file:///Users/demo/a*b.html";
    assert_eq!(main_on(star, star), None);
    // LD-323 (2): an additional file URL holding `*` fits only its exact page.
    assert_eq!(extra_on(star, star), Some(100));
    assert_eq!(extra_on(star, f), None);
    // LD-323 (3): exact means the same case too.
    assert_eq!(
        main_on("file:///Users/demo/A.html", "file:///Users/demo/a.html"),
        None
    );
    let allow = ["example.com".to_owned()];
    let site = Site {
        allow: &allow,
        ..Site::NONE
    };
    assert_eq!(rank_with(&entry("", &[]), f, None, true, &site), None);
}

// --- INT-03.1 ---

#[test]
fn t71_int03_1_pages_app_cannot_match_get_error_14() {
    for url in [
        "chrome://settings",
        "about:blank",
        "data:text/html,x",
        "chrome-extension://abcdefghijklmnop/popup.html",
        "javascript:alert(1)",
        "https:///x",
        "https://exa mple.com/",
        "https://a..b/",
        "http://0x7f.1/",
        "",
    ] {
        assert_eq!(Page::read(url, None, true).err(), Some(NOT_A_PAGE), "{url}");
    }
    let long = format!("https://example.com/{}", "a".repeat(8_192));
    assert_eq!(Page::read(&long, None, true).err(), Some(NOT_A_PAGE));
}

// --- INT-03.14 to INT-03.16: rank and order ---

/// The ranks of a vault's entries on a page, walked as INT-02.13 does (a
/// group, its entries in stored order, then its subgroups depth-first),
/// in offer order: the titles.
fn offered(v: &Vault, page: &str, form: Option<&str>, best_only: bool) -> Vec<(u8, String)> {
    fn walk<'v>(g: &'v Group, out: &mut Vec<&'v Entry>) {
        out.extend(&g.entries);
        for sub in &g.groups {
            walk(sub, out);
        }
    }
    let mut all = Vec::new();
    walk(&v.root, &mut all);
    let page = Page::read(page, form, true).unwrap();
    let ctx = Context::new(Some(v), Time(0));
    let mut found: Vec<(u8, String)> = all
        .into_iter()
        .filter_map(|e| {
            let r = page.rank(e, &ctx, &Site::NONE)?;
            Some((r, e.value("Title").to_owned()))
        })
        .collect();
    order(&mut found, best_only);
    found
}

fn titled(title: &str, main: &str, n: u8) -> Entry {
    let mut e = entry(main, &[]);
    e.uuid = Uuid([n; 16]);
    set(&mut e, "Title", title);
    e
}

fn ranked(list: &[(u8, String)]) -> Vec<(u8, &str)> {
    list.iter().map(|(r, t)| (*r, t.as_str())).collect()
}

#[test]
fn t72_t73_int03_14_and_int03_15_rank_order_and_best_only() {
    let v = vault(vec![
        titled("R1", "https://example.com/login", 1),
        titled("R2", "https://example.com", 2),
        titled("R3", "https://example.com/other", 3),
        titled("R4", "https://example.com/login?x=1", 4),
    ]);
    let page = "https://example.com/login?x=1";
    assert_eq!(
        ranked(&offered(&v, page, None, false)),
        [(100, "R4"), (90, "R1"), (85, "R2"), (80, "R3")],
        "T72"
    );
    assert_eq!(ranked(&offered(&v, page, None, true)), [(100, "R4")], "T73");
}

#[test]
fn t74_t75_int03_14_hosts_and_the_form_url() {
    let v = vault(vec![
        titled("R6", "https://example.com", 6),
        titled("R5", "https://mail.example.com", 5),
    ]);
    assert_eq!(
        ranked(&offered(&v, "https://mail.example.com/", None, false)),
        [(100, "R5"), (60, "R6")],
        "T74"
    );
    let v = vault(vec![
        titled("R8", "https://example.com/other", 8),
        titled("R7", "https://example.com/session", 7),
    ]);
    let form = Some("https://example.com/session");
    assert_eq!(
        ranked(&offered(&v, "https://www.example.com/login", form, false)),
        [(100, "R7"), (70, "R8")],
        "T75"
    );
    // The entry path a parent folder of the form URL's: 85. The page host
    // below the entry's: 60, also when the form host is below it too (60
    // is checked before 50). The page host above the entry's: no fit.
    let v = vault(vec![titled("R9", "https://example.com/a", 9)]);
    let form = Some("https://example.com/a/b");
    assert_eq!(
        ranked(&offered(&v, "https://x.example.com/", form, false)),
        [(85, "R9")]
    );
    let form = Some("https://y.example.com/");
    assert_eq!(
        ranked(&offered(&v, "https://x.example.com/", form, false)),
        [(60, "R9")]
    );
    let v = vault(vec![titled("R10", "https://y.example.com/a", 10)]);
    assert_eq!(
        ranked(&offered(&v, "https://example.com/", form, false)),
        []
    );
    let v = vault(vec![titled("R11", "https://example.com", 11)]);
    let form = Some("https://a.b.example.com/");
    assert_eq!(
        ranked(&offered(&v, "https://x.example.com/", form, false)),
        [(60, "R11")]
    );
}

#[test]
fn int03_14_the_parent_folder_needs_a_whole_folder() {
    assert_eq!(
        main_on("https://example.com/log", "https://example.com/login"),
        Some(80)
    );
    assert_eq!(
        main_on("https://example.com/a", "https://example.com/a/b"),
        Some(85)
    );
    assert_eq!(
        main_on("https://example.com/a/", "https://example.com/a/b"),
        Some(85)
    );
    assert_eq!(
        main_on("https://example.com/a/b", "https://example.com/a/b?q=1"),
        Some(90)
    );
}

#[test]
fn t76_int03_16_equal_ranks_in_tree_order() {
    let mut g1 = Group::new(Uuid([0xB1; 16]), "G1".into(), Time(0));
    g1.entries.push(titled("in G1", "https://example.com", 1));
    let mut g2 = Group::new(Uuid([0xB2; 16]), "G2".into(), Time(0));
    g2.entries.push(titled("in G2", "https://example.com", 2));
    let mut root = Group::new(Uuid([0xA0; 16]), "Root".into(), Time(0));
    root.groups = vec![g1, g2];
    let v = Vault::new(root, Time(0));
    assert_eq!(
        ranked(&offered(&v, "https://example.com/", None, false)),
        [(100, "in G1"), (100, "in G2")],
        "T76"
    );
}

#[test]
fn t77_t88_int03_14_highest_rate_and_scheme_first() {
    let e = entry("https://example.com/login", &["\"https://example.com/x\""]);
    assert_eq!(rank(&e, "https://example.com/x"), Some(100), "T77");
    let e = entry("https://example.com/login", &[]);
    assert_eq!(
        rank_with(&e, "http://example.com/login", None, false, &Site::NONE),
        Some(0),
        "T88"
    );
}

// --- INT-03.17: bounds ---

#[test]
fn t79_int03_17_an_entry_url_over_2048_characters_never_fits() {
    let base = "https://example.com/";
    let at_limit = format!("{base}{}", "a".repeat(MAX_ENTRY_URL - base.len()));
    assert_eq!(main_on(&at_limit, base), Some(80));
    // F-237: one character over never fits.
    let over_by_one = format!("{base}{}", "a".repeat(MAX_ENTRY_URL + 1 - base.len()));
    assert_eq!(over_by_one.chars().count(), 2_049);
    assert_eq!(main_on(&over_by_one, base), None);
    assert_eq!(extra_on(&over_by_one, base), None);
    let over = format!("{base}{}", "a".repeat(2_040));
    assert_eq!(over.len(), 2_060);
    assert_eq!(main_on(&over, base), None, "T79");
    assert_eq!(extra_on(&over, base), None);
    // Characters, not bytes.
    let wide = format!("{base}{}", "ü".repeat(MAX_ENTRY_URL - base.len()));
    assert_eq!(main_on(&wide, base), Some(80));
}

#[test]
fn t80_int03_17_only_64_urls_per_entry() {
    let mut extra: Vec<String> = (0..100)
        .map(|i| format!("https://other-{i}.example"))
        .collect();
    extra[79] = "https://example.com".into();
    let e = entry("", &extra.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(rank(&e, "https://example.com/"), None, "T80");
    // The 64th URL is still looked at (main empty: KP2A_URL, then _1 to _63).
    extra[79] = "https://other-79.example".into();
    extra[MAX_URLS - 1] = "https://example.com".into();
    let e = entry("", &extra.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(rank(&e, "https://example.com/"), Some(100));
    // The main URL counts as one of the 64.
    let e = entry(
        "https://other.example",
        &extra.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(rank(&e, "https://example.com/"), None);
}

#[test]
fn t81_t82_int03_17_patterns_with_16_stars_run_in_linear_time() {
    let p = format!("https://example.com/{}b", "*a".repeat(MAX_STARS - 1) + "*");
    assert_eq!(p.matches('*').count(), 16);
    let page = format!("https://example.com/{}", "a".repeat(8_000));
    // The list loads once per process, on first use (see T83).
    assert!(registrable_domain("example.com").is_some());
    let start = cpu();
    assert_eq!(extra_on(&p, &page), None, "T81");
    let took = cpu() - start;
    eprintln!("T81: {took:?}");
    assert!(took < Duration::from_millis(10), "T81 took {took:?}");
    let fits = format!("{page}b");
    assert_eq!(extra_on(&p, &fits), Some(40));
    let seventeen = format!("https://*.example.com/{}", "*a".repeat(16));
    assert_eq!(seventeen.matches('*').count(), 17);
    assert_eq!(
        extra_on(&seventeen, "https://x.example.com/aaaaaaaaaaaaaaaa"),
        None,
        "T82"
    );
    let sixteen = format!("https://*.example.com/{}", "*a".repeat(15));
    assert_eq!(
        extra_on(&sixteen, "https://x.example.com/aaaaaaaaaaaaaaa"),
        Some(40)
    );
}

#[test]
fn t83_int03_17_ten_thousand_entries_with_four_urls_under_200_ms() {
    let mut root = Group::new(Uuid([0xA0; 16]), "Root".into(), Time(0));
    for i in 0..10_000u32 {
        let mut e = Entry::new(Uuid([(i % 251) as u8 + 1; 16]), Time(0));
        set(
            &mut e,
            "URL",
            &format!("https://site-{i}.example.com/login"),
        );
        set(
            &mut e,
            "KP2A_URL",
            &format!("https://www.site-{i}.example/"),
        );
        set(
            &mut e,
            "KP2A_URL_1",
            &format!("\"https://site-{i}.example.org/x\""),
        );
        set(
            &mut e,
            "KP2A_URL_2",
            &format!("https://*.tenant-{i}.example.net/*"),
        );
        root.entries.push(e);
    }
    root.entries[1234].set_field(
        "URL".into(),
        Field {
            value: SecretString::new("https://example.com".into()),
            protected: false,
        },
    );
    let v = Vault::new(root, Time(0));
    let ctx = Context::new(Some(&v), Time(0));
    let page = format!("https://example.com/{}", "p".repeat(8_192 - 20));
    assert_eq!(page.len(), 8_192);
    // The list is read once per process, on first use; that is not part of
    // a request.
    let start = cpu();
    assert!(registrable_domain("example.com").is_some());
    eprintln!("T83: the list loads in {:?}", cpu() - start);
    let start = cpu();
    let p = Page::read(&page, None, true).unwrap();
    let mut found: Vec<(u8, usize)> = v
        .root
        .entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| Some((p.rank(e, &ctx, &Site::NONE)?, i)))
        .collect();
    order(&mut found, false);
    let took = cpu() - start;
    eprintln!("T83: {took:?}");
    assert_eq!(found, [(85, 1234)]);
    assert!(took < Duration::from_millis(200), "T83 took {took:?}");
}

/// F-244 (INT-03.17, LD-126 (1), (3)): one work meter for the request
/// pays every resolution of entry URLs, and one entry index finds the
/// entries, so a hostile vault's references never make matching hang.
/// Entry T's password is 1,000,000 `p`; 10,000 entries each hold 64
/// additional URLs that copy it. Once the meter is empty, a URL is read as
/// stored, and a stored `{` never fits (INT-03.3). The clock is read after
/// each entry, so a missing meter or index fails at once.
#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn t83_f244_int03_17_one_meter_and_index_per_request_bound_references() {
    let mut root = Group::new(Uuid([0xA0; 16]), "Root".into(), Time(0));
    let mut t = Entry::new(Uuid([0xEE; 16]), Time(0));
    set(&mut t, "Password", &"p".repeat(1_000_000));
    root.entries.push(t);
    let url = format!("https://example.com/{{REF:P@I:{}}}", "EE".repeat(16));
    let urls = vec![url.as_str(); 64];
    for i in 0..10_000u32 {
        let mut e = entry("", &urls);
        e.uuid.0[..4].copy_from_slice(&i.to_be_bytes());
        root.entries.push(e);
    }
    let v = Vault::new(root, Time(0));
    // The list loads once per process, on first use (see T83).
    assert!(registrable_domain("example.com").is_some());
    let start = cpu();
    // One meter and one entry index per request (LD-126 (1), (3)).
    let meter = Cell::new(COPY_BUDGET);
    let index = EntryIndex::new(&v);
    let ctx = Context {
        meter: Some(&meter),
        index: Some(&index),
        ..Context::new(Some(&v), Time(0))
    };
    let p = Page::read("https://example.com/", None, true).unwrap();
    let mut found = 0;
    for (n, e) in v.root.entries.iter().enumerate() {
        found += usize::from(p.rank(e, &ctx, &Site::NONE).is_some());
        let took = cpu() - start;
        assert!(
            took < Duration::from_millis(200),
            "F-244: {n} entries took {took:?}"
        );
    }
    eprintln!("F-244: {:?}", cpu() - start);
    assert_eq!(found, 0);
    assert_eq!(meter.get(), 0, "the meter bounded the work");
}

/// F-245 (INT-03.11 step 1, INT-03.17): a host pattern holding `*` has
/// at most 10 labels (one final `.` not counted); more never fit, and the
/// editor shows MI03-01.
#[test]
fn f245_int03_11_a_star_host_pattern_has_at_most_10_labels() {
    assert_eq!(MAX_PATTERN_LABELS, 10);
    let ten = "https://*.a.b.c.d.e.f.g.example.com/";
    let page = "https://x.a.b.c.d.e.f.g.example.com/";
    assert_eq!(extra_on(ten, page), Some(40));
    assert_eq!(
        extra_on("https://*.a.b.c.d.e.f.g.example.com./", page),
        Some(40)
    );
    assert_eq!(note(ten), None);
    let eleven = "https://*.z.a.b.c.d.e.f.g.example.com/";
    let page = "https://x.z.a.b.c.d.e.f.g.example.com/";
    assert_eq!(extra_on(eleven, page), None, "F-245");
    assert_eq!(note(eleven), Some(Note::RefusedPattern));
    // A host without `*` has no such limit (INT-03.7).
    assert_eq!(
        extra_on("https://x.z.a.b.c.d.e.f.g.example.com/*", page),
        Some(40)
    );
}

/// INT-03.4's longest host: 121 x `a.`, then `example.com`: 253 octets.
fn dns_limit_host() -> String {
    let h = format!("{}example.com", "a.".repeat(121));
    assert_eq!(h.len(), 253);
    assert_eq!(registrable_domain(&h).as_deref(), Some("example.com"));
    h
}

/// The thread CPU time of one request for `page` against 10,000 entries,
/// each with main URL `main` and additional URLs `extra`, and how many fit.
fn timed(main: &str, extra: &[&str], page: &str) -> (usize, Duration) {
    let mut root = Group::new(Uuid([0xA0; 16]), "Root".into(), Time(0));
    for i in 0..10_000u32 {
        let mut e = entry(main, extra);
        e.uuid.0[..4].copy_from_slice(&i.to_be_bytes());
        root.entries.push(e);
    }
    let v = Vault::new(root, Time(0));
    let ctx = Context::new(Some(&v), Time(0));
    // The list loads once per process, on first use (see T83).
    assert!(registrable_domain("example.com").is_some());
    let start = cpu();
    let p = Page::read(page, None, true).unwrap();
    let found = v
        .root
        .entries
        .iter()
        .filter(|e| p.rank(e, &ctx, &Site::NONE).is_some())
        .count();
    (found, cpu() - start)
}

/// F-245 (INT-03.17, INT-03.4): T83's bound holds with page and entry
/// hosts at the DNS limit and with hostile patterns: 10,000 entries with 4
/// URLs each, under 200 ms each. (a) plain `https://H/a`; (b) the long
/// pattern tail `https://*.<H less its first label>/*` and (c) a crafted
/// label run, both over 10 labels, so refused; (d) the worst 10-label
/// pattern, whose run `a.a.a.a.a.b` is tried at each place of H.
#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn t83_f245_int03_17_hosts_at_the_dns_limit_under_200_ms() {
    let h = dns_limit_host();
    let page = format!("https://{h}/x");
    let plain = format!("https://{h}/a");
    let tail = format!("https://*.{}/*", h.split_once('.').unwrap().1);
    let run = format!("https://*.{}b.*.example.com/", "a.".repeat(60));
    let worst = "https://*.a.a.a.a.a.b.*.example.com/";
    let shapes: [(&str, &str, &[&str], usize); 4] = [
        ("(a) plain", &plain, &[&plain, &plain, &plain], 10_000),
        ("(b) long tail", "", &[&tail, &tail, &tail, &tail], 0),
        ("(c) label run", "", &[&run, &run, &run, &run], 0),
        ("(d) 10 labels", "", &[worst, worst, worst, worst], 0),
    ];
    for (name, main, extra, fit) in shapes {
        let (found, took) = timed(main, extra, &page);
        eprintln!("F-245 {name}: {took:?}");
        assert_eq!(found, fit, "F-245 {name}");
        assert!(
            took < Duration::from_millis(200),
            "F-245 {name} took {took:?}"
        );
    }
}

/// F-252 (INT-03.17, LD-328): T83's bound holds with entry URLs of 2,048
/// characters, INT-03.17's limit, on page `https://example.com/`: 10,000
/// entries with 4 URLs each (the main URL and 3 additional), under 200 ms
/// each, nothing fits. `é`: each character past the host is tested against
/// INT-03.3's characters; long pattern: its host does not fit, so its path
/// of 2,025 `a` and a `*` is never encoded.
#[test]
#[cfg_attr(debug_assertions, ignore = "timed: release only")]
fn t83_f252_int03_17_urls_of_2048_characters_under_200_ms() {
    let accent = format!("https://example.org/{}", "\u{e9}".repeat(2_028));
    let long = format!("https://*.example.org/{}*", "a".repeat(2_025));
    for (name, url) in [("\u{e9}", &accent), ("long pattern", &long)] {
        assert_eq!(url.chars().count(), MAX_ENTRY_URL);
        let (found, took) = timed(url, &[url, url, url], "https://example.com/");
        eprintln!("F-252 {name}: {took:?}");
        assert_eq!(found, 0, "F-252 {name}");
        assert!(
            took < Duration::from_millis(200),
            "F-252 {name} took {took:?}"
        );
    }
}

// --- INT-03.18: the editor's notes ---

#[test]
fn t84_int03_18_notes_under_website_rows() {
    assert_eq!(note("https://*.co.uk"), Some(Note::RefusedPattern), "T84");
    assert_eq!(Note::RefusedPattern.id(), "MI03-01");
    for (value, want) in [
        ("https://*.example.com", None),
        ("example.com/login", None),
        ("\"https://example.com/x\"", None),
        ("https://{S:host}/", None),
        ("{REF:A@I:00000000000000000000000000000001}", None),
        ("", None),
        ("http*://example.com", Some(Note::RefusedPattern)),
        ("https://*.com/*", Some(Note::RefusedPattern)),
        ("\"\"", Some(Note::RefusedPattern)),
        ("https://exa mple.com", Some(Note::NoHost)),
        ("https://a..b", Some(Note::NoHost)),
        ("http://192.168.001.001", Some(Note::NoHost)),
        ("mailto:alex@example.com", Some(Note::OtherScheme)),
        ("ftp://example.com", Some(Note::OtherScheme)),
        ("file:///Users/demo/page.html", Some(Note::OtherScheme)),
    ] {
        assert_eq!(note(value), want, "{value}");
    }
    assert_eq!(Note::NoHost.id(), "MI03-02");
    assert_eq!(Note::OtherScheme.id(), "MI03-03");
}

/// LD-323 (5): a quoted exact URL that no page reads back to can never fit
/// (INT-03.11), so it gets MI03-02.
#[test]
fn ld323_5_a_quoted_url_that_can_never_fit_gets_mi03_02() {
    for value in [
        "\"example.com\"",
        "\"https://alex@example.com/\"",
        "\"ftp://example.com/\"",
        "\"https://exa mple.com/\"",
        "\"https://a..b/\"",
        "\"file:///Users/demo/page.html\"",
    ] {
        assert_eq!(note(value), Some(Note::NoHost), "{value}");
    }
    for value in [
        "\"https://example.com/login?x=1\"",
        "\"http://192.168.1.1:8080/\"",
    ] {
        assert_eq!(note(value), None, "{value}");
    }
}

// --- AT-F05: lookalike sites ---

/// AT-F05 (T86): lookalike letters, punycode, attacker subdomains, http
/// instead of https, other ports: no fill. Whatever URL field holds the
/// entry's address, none of the pages fits.
#[test]
fn t86_at_f05_lookalike_sites_never_fit() {
    let pages = [
        "https://bank.example.com.evil.example/",
        "https://xn--bnk-6cd.example.com/",
        "https://evil-bank.example.com/",
        "http://bank.example.com/",
        "https://bank.example.com:8443/",
        "https://bank.example.co/",
        "https://bankexample.com/",
        "https://bank-example.com/",
        "https://bank.example.com@evil.example/",
        "https://bank.example.com%2eevil.example/",
    ];
    let site = "https://bank.example.com/";
    let entries = [
        (entry("https://bank.example.com", &[]), site),
        (entry("bank.example.com", &[]), site),
        (entry("", &["https://bank.example.com"]), site),
        (entry("", &["\"https://bank.example.com/\""]), site),
        (
            entry("", &["https://*.bank.example.com/*"]),
            "https://www.bank.example.com/",
        ),
    ];
    for (e, real) in &entries {
        // Each entry fits the real site.
        assert!(rank(e, real).is_some(), "{real}");
        for page in pages {
            let got = Page::read(page, None, true)
                .ok()
                .and_then(|p| p.rank(e, &Context::new(None, Time(0)), &Site::NONE));
            assert_eq!(got, None, "{page}");
        }
    }
}
