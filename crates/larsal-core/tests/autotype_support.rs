//! The two larsal-core helpers of Auto-Type's picker (E8-S2, LD-196): the
//! Unicode form of a host (INT-05.22, R05-5) and the natural order without
//! its case tie-break (INT-05.26).

use core::cmp::Ordering;
use larsal_core::edit::{natural_cmp, natural_cmp_folded};
use larsal_core::url::host_unicode;

#[test]
fn host_unicode_decodes_every_xn_label() {
    let shown = |h: &str| host_unicode(h).map(|s| s.expose().to_owned());
    // RFC 3492 section 7.1 samples, and a lower and an upper prefix.
    for (code, text) in [
        ("xn--bcher-kva.example", "bücher.example"),
        ("www.XN--bcher-kva.example", "www.bücher.example"),
        ("xn--egbpdaj6bu4bxfgehfvwxn", "ليهمابتكلموشعربي؟"),
        ("xn--3B-ww4c5e180e575a65lsy2b", "3年B組金八先生"),
        ("xn--ihqwcrb4cv8a8dqg056pqjye", "他们为什么不说中文"),
    ] {
        assert_eq!(shown(code).as_deref(), Some(text), "{code}");
    }
    // No `xn--` label, or one that does not decode: no Unicode form.
    for bad in [
        "example.com",
        "",
        "xn--bcher-kv!.example",
        "xn--ü-a.example",
        &format!("xn--{}.example", "a".repeat(64)),
    ] {
        assert_eq!(shown(bad), None, "{bad}");
    }
    // Every 63-octet label decodes or fails without a panic.
    for d in *b"az09" {
        let label = String::from_utf8(vec![d; 59]).unwrap();
        let _ = shown(&format!("xn--{label}"));
    }
}

#[test]
fn natural_order_without_case() {
    assert_eq!(natural_cmp_folded("GitHub", "github"), Ordering::Equal);
    assert_eq!(natural_cmp_folded("a7", "a007"), Ordering::Equal);
    assert_eq!(natural_cmp_folded("a2", "a10"), Ordering::Less);
    assert_eq!(
        natural_cmp_folded("GitHub", "GitHub (work bot)"),
        Ordering::Less
    );
    // natural_cmp keeps its tie-break (MOD-07.5).
    assert_eq!(natural_cmp("GitHub", "github"), Ordering::Less);
    assert_eq!(natural_cmp("a2", "a10"), Ordering::Less);
}
