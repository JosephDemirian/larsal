//! F-270 / LD-353: intrinsic wiping, observed before System deallocates.
//! One test because the existing probe counts this process's deallocations.

use larsal_crypto::secret::SecretString;
use larsal_format::share_item;
use larsal_model::{CustomDataItem, Time, UnknownElement};
use larsal_platform::memory::{Probe, Seen, set_needle};
use std::alloc::System;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();
#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

fn observe(needle: [u8; 8], f: impl FnOnce()) -> (usize, usize) {
    set_needle(needle);
    SEEN.reset();
    f();
    let result = (SEEN.freed.load(Relaxed), SEEN.with_needle.load(Relaxed));
    set_needle([0; 8]);
    result
}

fn wiped(name: &str, needle: [u8; 8], f: impl FnOnce()) {
    let (freed, plain) = observe(needle, f);
    println!("{name}: {freed} blocks freed, {plain} with the value before System deallocation");
    assert!(freed > 0, "{name}: no deallocation observed");
    assert_eq!(
        plain, 0,
        "{name}: serialized credentials reached System unwiped"
    );
}

#[test]
fn f270_serialized_values_wipe_on_drop_replacement_and_clone() {
    // System alone does not wipe: the same live-block probe sees ordinary text.
    let (_, plain) = observe(*b"demo-raW", || drop("demo-raW control".to_owned()));
    assert!(plain > 0, "the probe must detect an unwiped String");

    let mut settings = share_item::Settings::new();
    settings.import = true;
    settings.group = larsal_model::Uuid([0x21; 16]);
    settings.path = "team.larsalvault".into();
    settings.password = SecretString::new("demo-share-1".into());
    let first = settings.write().unwrap();
    let xml =
        larsal_crypto::base64::decode(larsal_crypto::base64::Form::Padded, first.expose()).unwrap();
    let at = xml
        .windows(16)
        .position(|w| w == b"ZGVtby1zaGFyZS0x")
        .unwrap()
        .div_ceil(3)
        * 4;
    let encoded: [u8; 8] = first.expose().as_bytes()[at..at + 8].try_into().unwrap();
    drop((first, xml));
    wiped("writer output and intermediates", encoded, || {
        drop(settings.write().unwrap())
    });
    wiped("XML and password intermediates", *b"ZGVtby1z", || {
        drop(settings.write().unwrap())
    });
    let item = |settings: &mut share_item::Settings| CustomDataItem {
        key: String::from_utf8(share_item::KEY.to_vec()).unwrap(),
        value: settings.write().unwrap(),
        last_modified: Some(Time(5)),
        unknown: vec![UnknownElement {
            name: "Future".into(),
            attributes: Vec::new(),
            content: Vec::new(),
        }],
    };
    wiped("stored value drop", encoded, || drop(item(&mut settings)));
    wiped("public value replacement", encoded, || {
        let mut stored = item(&mut settings);
        stored.value = settings.write().unwrap();
        drop(stored);
    });
    wiped("clone and clone_from", encoded, || {
        let original = item(&mut settings);
        let mut copy = original.clone();
        assert_eq!(copy, original);
        copy.clone_from(&original);
        assert_eq!(copy, original);
        drop((copy, original));
    });
}
