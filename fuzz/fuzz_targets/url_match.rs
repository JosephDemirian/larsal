//! Fuzz target `url_match` (E7-S3, INT-03, Rust rule 10): URL matching on
//! arbitrary text, as a hostile vault and page send it. The input's lines
//! are the page URL, the form URL, then entry URL values; each value is
//! tried as the main URL, as an additional URL and as an allowed host, with
//! S-BRW-11 on and off, and as the editor's website row (INT-03.18). Must
//! never panic or hang, and keeps INT-03's rules on every input:
//! - a rank is one of INT-03.14's rates;
//! - what fits with S-BRW-11 on also fits with it off (INT-03.5);
//! - a page whose host is a name of two or more labels is fitted by a URL
//!   only when that host has a registrable domain (INT-03.7, INT-03.11:
//!   a public suffix is never one site), except a quoted exact URL;
//! - a registrable domain, when there is one, ends the host it is of.
#![no_main]

use larsal_browser::{Page, Site, note, registrable_domain};
use larsal_core::refs::Context;
use larsal_crypto::secret::SecretString;
use larsal_model::{Entry, Field, Time, Uuid};
use libfuzzer_sys::fuzz_target;

const RATES: [u8; 9] = [0, 40, 50, 60, 70, 80, 85, 90, 100];

fn with(name: &str, value: &str) -> Entry {
    let mut e = Entry::new(Uuid([1; 16]), Time(0));
    e.set_field(
        name.into(),
        Field {
            value: SecretString::new(value.into()),
            protected: false,
        },
    );
    e
}

/// The page host of a web `url`, as INT-03.4 reads it, when it is a name.
fn page_name(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if hostport.starts_with('[') {
        return None;
    }
    let host = hostport.rsplit_once(':').map_or(hostport, |(h, _)| h);
    let host = host.strip_suffix('.').unwrap_or(host);
    (host.contains('.') && !host.rsplit('.').next()?.bytes().all(|b| b.is_ascii_digit()))
        .then(|| host.to_owned())
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.split('\n');
    let url = lines.next().unwrap_or("");
    let form = lines.next().filter(|f| !f.is_empty());
    let values: Vec<&str> = lines.take(4).collect();
    let ctx = Context::new(None, Time(0));
    if let Some(d) = registrable_domain(url) {
        let host = url.trim_end_matches('.').to_ascii_lowercase();
        assert!(host == d || host.ends_with(&format!(".{d}")) || !host.is_ascii());
    }
    let (Ok(on), Ok(off)) = (Page::read(url, form, true), Page::read(url, form, false)) else {
        return;
    };
    let name = page_name(url);
    let public = name
        .as_deref()
        .is_some_and(|n| registrable_domain(n).is_none());
    for v in values {
        let _ = note(v);
        let allow = [v.to_owned()];
        let allowed = Site {
            allow: &allow,
            ..Site::NONE
        };
        for e in [
            with("URL", v),
            with("KP2A_URL", v),
            with("KPEX_PASSKEY_RELYING_PARTY", v),
        ] {
            let strict = on.rank(&e, &ctx, &Site::NONE);
            let loose = off.rank(&e, &ctx, &Site::NONE);
            for r in [strict, loose].into_iter().flatten() {
                assert!(RATES.contains(&r), "INT-03.14: {r}");
            }
            assert!(strict.is_none() || loose.is_some(), "INT-03.5");
            // A quoted exact URL is text equality (INT-03.11), not INT-03.7;
            // a value with `"` can resolve to one (`{TITLE}"..."`).
            if public
                && !v.contains('"')
                && !url
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("file://"))
            {
                assert_eq!(loose, None, "INT-03.7: a public suffix page");
            }
            let _ = on.rank(&e, &ctx, &allowed);
        }
    }
});
