//! T53 (INT-07.33): the IOKit layer on this Mac. The check with a real key
//! waits for the owner's go (OD-01): it is ignored, so `cargo test` reports
//! it as ignored, never as passed. Run it with `--ignored` and a key with
//! demo secret D in slot 2 (variable mode); without a key it fails.
#![cfg(target_os = "macos")]

use app_hwkey::usb::UsbBus;
use app_hwkey::{Bus, HardwareKey, KeyChoice, Slot, detect};

/// Lists HID devices through IOKit; reads properties only, opens nothing,
/// so no key and no slot is touched.
#[test]
fn t53_iokit_lists_devices_without_opening_any() {
    let devices = UsbBus::new().list().expect("IOKit lists HID devices");
    let keys = devices
        .iter()
        .filter(|d| [0x1050, 0x1D50].contains(&d.vendor))
        .count();
    eprintln!(
        "IOKit: {} HID devices, {keys} with a key vendor id",
        devices.len()
    );
}

#[test]
#[ignore = "T53: needs a real key with demo secret D in slot 2; waits for the owner's go (OD-01)"]
fn t53_real_key_detect_and_challenge() {
    let bus = UsbBus::new();
    let found = detect(&bus).expect("detection runs");
    let item = found
        .items
        .iter()
        .find(|i| i.slot == Slot::Two)
        .expect("no key with a usable slot 2 is plugged in: T53 cannot run");
    eprintln!("found: {}", item.label());
    let hw = HardwareKey {
        bus,
        choice: KeyChoice {
            serial: item.serial,
            slot: Slot::Two,
        },
        needs_touch: item.needs_touch,
        events: Some(Box::new(|e| eprintln!("{e:?}"))),
    };
    // KS of FMT-04.6-a padded (FMT-04.9); T03's variable-mode answer.
    let mut padded = [0x20u8; 64];
    padded[..32].copy_from_slice(&[
        0x34, 0x81, 0x48, 0x3a, 0x67, 0xfb, 0x36, 0x5d, 0xa9, 0x11, 0xc5, 0x09, 0x54, 0x20, 0xce,
        0x2b, 0xfd, 0x21, 0x61, 0x79, 0x3b, 0x47, 0xd7, 0xa6, 0x56, 0x1c, 0xed, 0xf9, 0x21, 0x89,
        0x9e, 0x63,
    ]);
    let answer = hw.ask(&padded).expect("the key answers");
    let want = [
        0x57, 0x44, 0xa1, 0x26, 0x7b, 0x30, 0xe1, 0x24, 0x42, 0x15, 0x6b, 0xbd, 0x9d, 0x54, 0x71,
        0x55, 0x41, 0x76, 0x5d, 0x89,
    ];
    assert_eq!(answer.expose(), want);
}
