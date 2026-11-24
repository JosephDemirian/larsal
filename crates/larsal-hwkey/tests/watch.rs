//! LD-190: the IOKit watch on this Mac, without a key. It only reads: no
//! device is opened and the HID manager is never opened. It must leave no
//! thread of ours running. (IOKit also wakes the system's shared dispatch
//! pool, whose idle threads come and go on their own, so a thread count
//! cannot show this; the sink, which lives only on the watch thread, can.)
#![cfg(target_os = "macos")]

use larsal_hwkey::Bus;
use larsal_hwkey::usb::UsbBus;
use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

#[test]
fn t23_iokit_watch_starts_and_stops_without_a_key() {
    let (tx, changes) = mpsc::channel();
    let watch = UsbBus::new()
        .watch(Box::new(move |change| {
            let _ = tx.send(change);
        }))
        .expect("the watch starts");
    // Devices present at the start are not reported as plug-ins.
    assert!(changes.recv_timeout(Duration::from_millis(500)).is_err());
    drop(watch);
    // The watch thread was joined and dropped its state, the sink with it.
    assert_eq!(changes.try_recv(), Err(TryRecvError::Disconnected));
}

/// F-067: a sink that panics never unwinds out of the IOKit callbacks into
/// IOKit and CoreFoundation frames; the event is dropped.
#[test]
fn f_067_a_panicking_sink_never_unwinds_into_iokit() {
    larsal_hwkey::usb::callbacks_for_tests(Box::new(|_| panic!("demo sink panic")));
}
