//! The IOKit HID layer (INT-07.7, INT-07.8, D-INT07-1): lists HID devices,
//! opens one interface without seizing it, and moves 8-byte feature reports
//! with report id 0. The only place in this crate where `unsafe` is allowed
//! (Rust rule 2); every block carries a `// SAFETY:` note, enforced by
//! `undocumented_unsafe_blocks`. Listing reads properties only and opens
//! nothing; no input report is ever read, so a key's typed one-time
//! passwords never reach App (INT-07 Security notes). Every function here is
//! safe to call. Plug-in and removal events are in [`watch`].
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod watch;

pub use watch::UsbWatch;
#[cfg(feature = "test-callbacks")]
pub use watch::callbacks_for_tests;

use crate::{Bus, Change, Device, DeviceInfo, Interface, Reason};
use core::ffi::c_void;
use core::ptr::NonNull;
use objc2_core_foundation::{CFIndex, CFNumber, CFRetained, CFSet, CFString};
use objc2_io_kit::{
    IOHIDDevice, IOHIDManager, IOHIDReportType, IOReturn, kIOHIDOptionsTypeNone, kIOReturnNoDevice,
    kIOReturnNotAttached, kIOReturnNotPermitted, kIOReturnNotPrivileged, kIOReturnSuccess,
};
use std::time::{Duration, Instant};

/// The real bus: IOKit's HID manager and the real clock.
#[derive(Debug, Clone, Copy)]
pub struct UsbBus {
    start: Instant,
}

impl UsbBus {
    /// A bus whose clock starts now.
    #[must_use]
    pub fn new() -> UsbBus {
        UsbBus {
            start: Instant::now(),
        }
    }
}

impl Default for UsbBus {
    fn default() -> UsbBus {
        UsbBus::new()
    }
}

/// One HID interface as IOKit lists it.
struct Found {
    device: CFRetained<IOHIDDevice>,
    info: DeviceInfo,
    interface: Option<Interface>,
}

impl Found {
    fn same_device(&self, other: &DeviceInfo) -> bool {
        (self.info.id, self.info.vendor, self.info.product)
            == (other.id, other.vendor, other.product)
    }
}

/// An integer property of a HID interface.
fn number(device: &IOHIDDevice, key: &'static str) -> Option<i64> {
    device
        .property(&CFString::from_static_str(key))?
        .downcast::<CFNumber>()
        .ok()?
        .as_i64()
}

/// The members of a device set from IOHIDManagerCopyDevices; valid while
/// `set` lives.
fn members(set: &CFSet) -> Vec<NonNull<IOHIDDevice>> {
    let mut values: Vec<*const c_void> =
        vec![core::ptr::null(); usize::try_from(set.count()).unwrap_or(0)];
    // SAFETY: `values` has room for exactly `set.count()` pointers, as
    // CFSetGetValues needs; `set` is our own copy, so its count cannot change
    // between the two calls.
    unsafe { set.values(values.as_mut_ptr()) };
    values
        .into_iter()
        .filter_map(|value| NonNull::new(value.cast_mut().cast::<IOHIDDevice>()))
        .collect()
}

/// Every HID interface IOKit sees now. Opens nothing.
fn interfaces() -> Vec<Found> {
    let manager = IOHIDManager::new(None, kIOHIDOptionsTypeNone);
    // SAFETY: `None` matches every HID device; no dictionary is passed, so
    // none can hold values of the wrong type.
    unsafe { manager.set_device_matching(None) };
    let Some(set) = manager.devices() else {
        return Vec::new();
    };
    members(&set)
        .into_iter()
        .filter_map(|device| {
            // SAFETY: IOHIDManagerCopyDevices fills the set with IOHIDDevice
            // references only, and `set` keeps each one alive here; `retain`
            // adds our own reference, released when the CFRetained drops.
            let device = unsafe { CFRetained::retain(device) };
            let interface = match (
                number(&device, "PrimaryUsagePage")?,
                number(&device, "PrimaryUsage")?,
            ) {
                (0xF1D0, 0x01) => Some(Interface::Fido),
                (0x01, 0x06) => Some(Interface::Keyboard),
                _ => None,
            };
            // The location id is 32 bits; IOKit may give it as a negative
            // signed number (0xFA120000 and up), so keep the low 32 bits.
            let location = number(&device, "LocationID")? as u32;
            let info = DeviceInfo {
                id: u64::from(location),
                vendor: u16::try_from(number(&device, "VendorID")?).ok()?,
                product: u16::try_from(number(&device, "ProductID")?).ok()?,
                fido: false,
                keyboard: false,
            };
            Some(Found {
                device,
                info,
                interface,
            })
        })
        .collect()
}

/// IOKit's code as a reason (INT-07.20).
fn reason(code: IOReturn) -> Reason {
    let code = code.cast_unsigned();
    if code == kIOReturnNoDevice || code == kIOReturnNotAttached {
        Reason::Missing
    } else {
        Reason::Failed
    }
}

impl Bus for UsbBus {
    type Device = UsbDevice;

    /// One item per physical device (its interfaces share the location id),
    /// sorted by location id.
    fn list(&self) -> Result<Vec<DeviceInfo>, Reason> {
        let mut devices: Vec<DeviceInfo> = Vec::new();
        for found in interfaces() {
            let at = match devices.iter().position(|d| found.same_device(d)) {
                Some(at) => at,
                None => {
                    devices.push(found.info);
                    devices.len() - 1
                }
            };
            match found.interface {
                Some(Interface::Fido) => devices[at].fido = true,
                Some(Interface::Keyboard) => devices[at].keyboard = true,
                None => {}
            }
        }
        devices.sort_by_key(|d| d.id);
        Ok(devices)
    }

    fn open(&self, device: &DeviceInfo, interface: Interface) -> Result<UsbDevice, Reason> {
        let found = interfaces()
            .into_iter()
            .find(|f| f.interface == Some(interface) && f.same_device(device))
            .ok_or(Reason::Missing)?;
        // kIOHIDOptionsTypeNone: shared, not seized (INT-07.8).
        let code = found.device.open(kIOHIDOptionsTypeNone);
        if code == kIOReturnSuccess {
            return Ok(UsbDevice {
                device: found.device,
            });
        }
        let refused =
            [kIOReturnNotPermitted, kIOReturnNotPrivileged].contains(&code.cast_unsigned());
        Err(if refused && interface == Interface::Keyboard {
            Reason::NotPermitted
        } else {
            reason(code)
        })
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&self, pause: Duration) {
        std::thread::sleep(pause);
    }

    type Watch = UsbWatch;

    fn watch(&self, sink: Box<dyn Fn(Change) + Send>) -> Result<UsbWatch, Reason> {
        watch::start(sink)
    }
}

/// One opened HID interface; closed when dropped (INT-07.8).
pub struct UsbDevice {
    device: CFRetained<IOHIDDevice>,
}

impl Device for UsbDevice {
    fn read(&mut self, report: &mut [u8; 8]) -> Result<(), Reason> {
        let mut len: CFIndex = 8;
        // SAFETY: `report` is 8 writable bytes and `len` says 8, so
        // IOHIDDeviceGetReport writes at most 8 bytes into it and the length
        // into `len`; the call is synchronous and both live through it.
        let code = unsafe {
            self.device.report(
                IOHIDReportType::Feature,
                0,
                NonNull::from(&mut *report).cast::<u8>(),
                NonNull::from(&mut len),
            )
        };
        match (code == kIOReturnSuccess, len) {
            (true, 8) => Ok(()),
            (true, _) => Err(Reason::Failed),
            (false, _) => Err(reason(code)),
        }
    }

    fn write(&mut self, report: &[u8; 8]) -> Result<(), Reason> {
        // SAFETY: IOHIDDeviceSetReport reads exactly the 8 bytes it is told
        // from the pointer during this synchronous call and never writes
        // through it (its C type is `const uint8_t *`); `report` is 8 bytes
        // and lives through the call.
        let code = unsafe {
            self.device.set_report(
                IOHIDReportType::Feature,
                0,
                NonNull::from(report).cast::<u8>(),
                8,
            )
        };
        if code == kIOReturnSuccess {
            Ok(())
        } else {
            Err(reason(code))
        }
    }
}

impl Drop for UsbDevice {
    fn drop(&mut self) {
        // Nothing to do when it fails: the device is gone or already closed.
        let _ = self.device.close(kIOHIDOptionsTypeNone);
    }
}
