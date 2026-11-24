//! Registrable domains (INT-03.10, D-INT03-1 option (b), LD-295 (2)): Larsal's
//! own matcher over the Public Suffix List file kept unchanged in
//! `vendor/public-suffix-list/` (LD-303 (6)), by the list's "formal
//! algorithm" (publicsuffix.org, the list's wiki page "Format"): both the
//! ICANN and the private sections; when no rule matches, the rule is `*`;
//! an exception rule (`!`) wins and loses its leftmost label; else the
//! matching rule with the most labels wins; a wildcard (`*.`) stands for
//! one label. The registrable domain is the public suffix plus one label.
//!
//! The list is compiled into the build and never downloaded (INT-03.19,
//! Rust rule 12): [`list_version`] is the list project's commit the copy
//! came from. Each rule is turned into Larsal's host form once (INT-03.4: lower
//! case, Punycode for non-ASCII labels), so the hosts Larsal compares and the
//! rules have one form (LD-58).

use crate::matching::{Host, host_form};
use std::collections::HashSet;
use std::sync::OnceLock;

/// The list file, unchanged (MPL-2.0 data, LD-221 (1)).
const LIST: &str = include_str!("../../../vendor/public-suffix-list/public_suffix_list.dat");
/// Where the copy came from: its commit, date and SHA-256 (LD-303 (6)).
const SOURCE: &str = include_str!("../../../vendor/public-suffix-list/SOURCE.txt");

/// The list's rules in Larsal's host form, by kind.
struct Rules {
    plain: HashSet<String>,
    /// `*.x` rules, kept as `x`.
    wild: HashSet<String>,
    /// `!x` rules, kept as `x`.
    except: HashSet<String>,
    /// The most labels any rule matches, a wildcard's `*` counted as one:
    /// a longer suffix of a host can match no rule (INT-03.17, F-245).
    longest: usize,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut r = Rules {
            plain: HashSet::new(),
            wild: HashSet::new(),
            except: HashSet::new(),
            longest: 0,
        };
        // The format: one rule per line, read up to the first white space;
        // lines starting with `//` are comments.
        for rule in LIST.lines().filter_map(|l| l.split_whitespace().next()) {
            if rule.starts_with("//") {
                continue;
            }
            let (set, name) = if let Some(n) = rule.strip_prefix('!') {
                (&mut r.except, n)
            } else if let Some(n) = rule.strip_prefix("*.") {
                (&mut r.wild, n)
            } else {
                (&mut r.plain, rule)
            };
            if let Some(Host::Name(ascii)) = host_form(name) {
                r.longest = r
                    .longest
                    .max(rule.trim_start_matches('!').split('.').count());
                set.insert(ascii);
            }
        }
        r
    })
}

/// The list project's commit of the compiled list (INT-03.19, T89).
#[must_use]
pub fn list_version() -> &'static str {
    SOURCE
        .lines()
        .find_map(|l| l.strip_prefix("Commit:"))
        .map_or("", str::trim)
}

/// The registrable domain of `host` in Larsal's host form (INT-03.10), as
/// INT-02.19 and INT-04.11 use it. `None` for a host that is itself a
/// public suffix (`co.uk`, `github.io`), an IP address, a one-label host,
/// and any text that is not a valid host (INT-03.4: an empty label, a
/// character other than letters, digits, `-` and `_`, the DNS limits).
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    match host_form(host)? {
        Host::Name(name) => domain_of(&name).map(str::to_owned),
        Host::V4(_) | Host::V6(_) => None,
    }
}

/// [`registrable_domain`] of a name already in host form.
pub(crate) fn domain_of(name: &str) -> Option<&str> {
    let r = rules();
    // The suffixes of `name`, the shortest first: "com", "example.com", ...
    let suffixes = || {
        name.rmatch_indices('.')
            .filter_map(|(at, _)| name.get(at.saturating_add(1)..))
            .chain(Some(name))
    };
    let mut labels = 1usize; // the default rule `*`
    let mut exception = None;
    let mut shorter: Option<&str> = None;
    for (n, suffix) in suffixes().enumerate().take(r.longest) {
        let count = n.saturating_add(1);
        if r.except.contains(suffix) {
            exception = Some(n);
        }
        if r.plain.contains(suffix) || shorter.is_some_and(|s| r.wild.contains(s)) {
            labels = count;
        }
        shorter = Some(suffix);
    }
    // The public suffix has `labels` labels; the registrable domain one more.
    suffixes().nth(exception.unwrap_or(labels))
}

#[cfg(test)]
mod tests {
    use super::{LIST, SOURCE, list_version, rules};

    /// T89 (INT-03.19): the list compiled into the build is the vendored
    /// copy, byte for byte: its SHA-256 and size are the ones SOURCE.txt
    /// recorded when it was read (LD-303 (6)), and its version is the
    /// commit recorded there.
    #[test]
    fn t89_int03_19_the_compiled_list_is_the_vendored_copy() {
        let digest = larsal_crypto::hash::sha256(&[LIST.as_bytes()]);
        let hex: String = digest.expose().iter().map(|b| format!("{b:02x}")).collect();
        let line = SOURCE
            .lines()
            .find(|l| l.trim_start().starts_with("public_suffix_list.dat"))
            .unwrap();
        assert!(line.contains(&format!("SHA-256 {hex}")), "{line}");
        assert!(line.contains(&format!("{} bytes", LIST.len())), "{line}");
        assert_eq!(list_version().len(), 40);
        assert!(list_version().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    /// Every rule line of the list is read, ICANN and private sections.
    #[test]
    fn int03_10_every_rule_of_both_sections_is_read() {
        let lines = LIST
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|l| !l.starts_with("//"))
            .count();
        let r = rules();
        assert_eq!(r.plain.len() + r.wild.len() + r.except.len(), lines);
        assert!(r.plain.contains("co.uk") && r.plain.contains("github.io"));
        assert!(r.wild.contains("ck") && r.except.contains("www.ck"));
        // Unicode rules in Larsal's host form (the list's `公司.cn`).
        assert!(r.plain.contains("xn--55qx5d.cn"));
        // F-245: the walk's bound is the longest rule, `*` counted (this
        // list: 7, from `*.` rules with 6 more labels).
        let longest = LIST
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|l| !l.starts_with("//"))
            .map(|l| l.trim_start_matches('!').split('.').count())
            .max();
        assert_eq!(Some(r.longest), longest);
        assert_eq!(r.longest, 7);
    }
}
