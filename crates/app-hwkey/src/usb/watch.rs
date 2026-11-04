//! Plug-in and removal events (INT-07.14, INT-07.30, LD-190): IOKit's
//! device-matching and removal callbacks for the vendor ids of INT-07.6, on
//! the run loop of a thread this crate owns (never the app's main run loop).
//! No device is opened or seized here, the HID manager is never opened, and
//! no input report callback is registered (LD-188 (3)).

use super::members;
use crate::{Change, Reason, VENDORS};
use core::ffi::c_void;
use core::ptr::NonNull;
use objc2_core_foundation::{
    CFArray, CFDictionary, CFNumber, CFRetained, CFRunLoop, CFString, kCFRunLoopDefaultMode,
};
use objc2_io_kit::{IOHIDDevice, IOHIDManager, IOReturn, kIOHIDOptionsTypeNone};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;

/// Seconds the run loop waits before the thread checks for a stop.
const STOP_CHECK: f64 = 0.1;

/// A running watch: one thread with its own run loop. Dropping it stops the
/// loop (within 0.1 s) and joins the thread.
pub struct UsbWatch {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for UsbWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the callbacks reach through their context pointer.
struct Watching {
    sink: Box<dyn Fn(Change) + Send>,
    /// Addresses of the devices present when the watch started: their
    /// matching callbacks are the first enumeration, not plug-ins. The set
    /// that holds them stays alive for the whole watch, so no new device can
    /// get one of these addresses.
    known: Vec<usize>,
}

/// Starts the watch thread and waits until its callbacks are in place.
pub(super) fn start(sink: Box<dyn Fn(Change) + Send>) -> Result<UsbWatch, Reason> {
    let stop = Arc::new(AtomicBool::new(false));
    let (ready, started) = mpsc::channel();
    let flag = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("app-hwkey-watch".to_owned())
        .spawn(move || run(sink, &flag, &ready))
        .map_err(|_| Reason::Failed)?;
    // When `run` fails, dropping the watch joins the ended thread.
    let watch = UsbWatch {
        stop,
        thread: Some(thread),
    };
    match started.recv() {
        Ok(true) => Ok(watch),
        _ => Err(Reason::Failed),
    }
}

/// The watch thread: matching for the vendor ids, the two callbacks, then
/// the run loop until `stop`.
fn run(sink: Box<dyn Fn(Change) + Send>, stop: &AtomicBool, ready: &mpsc::Sender<bool>) {
    // SAFETY: reads a constant that CoreFoundation sets up before any code
    // of ours runs and never changes.
    let mode = unsafe { kCFRunLoopDefaultMode };
    let (Some(run_loop), Some(mode)) = (CFRunLoop::current(), mode) else {
        let _ = ready.send(false);
        return;
    };
    let manager = IOHIDManager::new(None, kIOHIDOptionsTypeNone);
    let key = CFString::from_static_str("VendorID");
    let ids: Vec<CFRetained<CFNumber>> = VENDORS
        .iter()
        .map(|&vendor| CFNumber::new_i32(i32::from(vendor)))
        .collect();
    let criteria: Vec<CFRetained<CFDictionary<CFString, CFNumber>>> = ids
        .iter()
        .map(|id| CFDictionary::from_slices(&[&*key], &[&**id]))
        .collect();
    let matching = CFArray::from_retained_objects(&criteria);
    // SAFETY: an array of dictionaries from CFString keys to CFNumber values,
    // the form the HID manager's matching takes.
    unsafe { manager.set_device_matching_multiple(Some(matching.as_opaque())) };
    let present = manager.devices();
    let watching = Watching {
        sink,
        known: present
            .as_deref()
            .map(members)
            .unwrap_or_default()
            .iter()
            .map(|device| device.as_ptr().addr())
            .collect(),
    };
    let context = (&raw const watching).cast_mut().cast::<c_void>();
    // SAFETY: both callbacks have the IOHIDDeviceCallback signature and use
    // `context` only as a shared `&Watching`. `watching` outlives every call:
    // callbacks run only inside `run_in_mode` below, on this thread, and the
    // manager is unscheduled and its callbacks cleared before `watching` is
    // dropped.
    unsafe {
        manager.register_device_matching_callback(Some(arrived), context);
        manager.register_device_removal_callback(Some(removed), context);
    }
    // SAFETY: this thread's own run loop and the default mode, both alive
    // until the manager is unscheduled below.
    unsafe { manager.schedule_with_run_loop(&run_loop, mode) };
    let _ = ready.send(true);
    while !stop.load(Ordering::Relaxed) {
        CFRunLoop::run_in_mode(Some(mode), STOP_CHECK, false);
    }
    // SAFETY: the run loop and mode it was scheduled with. Afterwards no
    // callback can run.
    unsafe { manager.unschedule_from_run_loop(&run_loop, mode) };
    // SAFETY: registering `None` with a null context (both `_Nullable` in
    // `IOHIDManager.h`) replaces the stored callback and context; afterwards
    // the manager holds no pointer to `watching`, which may then be dropped.
    unsafe {
        manager.register_device_matching_callback(None, core::ptr::null_mut());
        manager.register_device_removal_callback(None, core::ptr::null_mut());
    }
}

/// IOKit's matching callback: a device of the vendor ids appeared.
///
/// # Safety
/// `context` points to a `Watching` that lives for the whole call (`run`
/// registers it so); `device` is only compared by address.
unsafe extern "C-unwind" fn arrived(
    context: *mut c_void,
    _result: IOReturn,
    _sender: *mut c_void,
    device: NonNull<IOHIDDevice>,
) {
    // SAFETY: `context` is the `&Watching` registered in `run`, alive while
    // any callback can run (see there).
    let watching = unsafe { &*context.cast::<Watching>() };
    if !watching.known.contains(&device.as_ptr().addr()) {
        tell(watching, Change::Arrived);
    }
}

/// IOKit's removal callback: a device of the vendor ids went away.
///
/// # Safety
/// As for [`arrived`]; `device` is not used.
unsafe extern "C-unwind" fn removed(
    context: *mut c_void,
    _result: IOReturn,
    _sender: *mut c_void,
    _device: NonNull<IOHIDDevice>,
) {
    // SAFETY: as in `arrived`.
    let watching = unsafe { &*context.cast::<Watching>() };
    tell(watching, Change::Removed);
}

/// Passes `change` to the sink. A panic in the sink drops the event and
/// never unwinds into IOKit and CoreFoundation frames (F-067).
fn tell(watching: &Watching, change: Change) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (watching.sink)(change)));
}

/// Tests only (feature `test-callbacks`, F-067): calls both callbacks as
/// IOKit does, with `sink` and no device. Never in product builds.
#[doc(hidden)]
#[cfg(feature = "test-callbacks")]
pub fn callbacks_for_tests(sink: Box<dyn Fn(Change) + Send>) {
    let watching = Watching {
        sink,
        known: Vec::new(),
    };
    let context = (&raw const watching).cast_mut().cast::<c_void>();
    // SAFETY: `context` is a `Watching` that lives across both calls; the
    // device pointer is only compared by address, never read.
    unsafe {
        arrived(context, 0, core::ptr::null_mut(), NonNull::dangling());
        removed(context, 0, core::ptr::null_mut(), NonNull::dangling());
    }
}
