//! Hardware keys (spec INT-07, story E10-S1): finds keys programmed for
//! HMAC-SHA1 challenge-response over USB on macOS, lists their slots, and
//! asks one slot a challenge for the key flow of FMT-04.
//!
//! Guarantees: one device operation at a time in the whole process
//! (INT-07.13); every wait is bounded (INT-07.12: 1,150 ms per write step,
//! 1,000 ms for a reply to start, 20 s for a touch); the 20-byte answer is
//! read straight into [`SecretBytes`] and never into a plain buffer of this
//! crate (INT-07.22); no error carries key material; the only things ever
//! sent are the commands `10`, `30`, `38` and the reset report (INT-07.1);
//! detection never waits for a touch (INT-07.15). One key per vault
//! (D-INT07-7); no NFC or smart card readers (D-INT07-2).
//!
//! The protocol code runs unchanged over any [`Bus`]: the IOKit layer in
//! [`usb`] or, in tests, the simulated device of INT-07.30.
// deny, not forbid: the usb/ module allows unsafe (Rust rule 2).
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod protocol;
#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;
// Not in this crate's unit-test binary, so the simulated runs can make no
// real USB call (T47).
#[cfg(all(target_os = "macos", not(test)))]
pub mod usb;
mod watch;

pub use watch::KeyWatcher;

use app_crypto::secret::SecretBytes;
use app_format::error::HardwareKeyReason;
use app_format::keys::ChallengeResponse;
use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// MI07-01 (INT-07.7, INT-07.20): the line for [`Reason::NotPermitted`] on
/// the unlock screen, the wizard's key part and the credential page.
pub const MI07_01: &str = "macOS did not let App reach your security key. Allow App under System Settings › Privacy & Security › Input Monitoring, then try again.";

/// MI07-02 (finding R07-2): the `MSG-SAVE-FAILED` reason for
/// [`Reason::NotPermitted`]. The other reasons are APP-06.30's; while
/// waiting, the save progress line uses M06-35.
pub const MI07_02_NOT_PERMITTED: &str = "macOS did not let App reach the security key";

/// Why a hardware key operation failed (INT-07.20). Holds no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No key connected, the chosen serial not connected, or the key was
    /// removed (M06-17).
    Missing,
    /// The touch wait ended without a touch (M06-18).
    TimedOut,
    /// The slot is not set up for challenge-response (M06-19).
    SlotNotConfigured,
    /// The reply failed its CRC or had the wrong length (M06-20).
    BadAnswer,
    /// macOS refused to open the keyboard interface (MI07-01; D-INT07-3).
    NotPermitted,
    /// Any other IOKit or USB failure, or a write step that never ends (M06-20).
    Failed,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("security key not connected"),
            Self::TimedOut => f.write_str("security key not touched in time"),
            Self::SlotNotConfigured => f.write_str("slot not set up for challenge-response"),
            Self::BadAnswer => f.write_str("bad reply from the security key"),
            Self::NotPermitted => f.write_str("macOS did not allow access to the security key"),
            Self::Failed => f.write_str("security key failure"),
        }
    }
}

impl std::error::Error for Reason {}

impl From<Reason> for HardwareKeyReason {
    /// The key flow's reason, one to one.
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::Missing => HardwareKeyReason::Missing,
            Reason::TimedOut => HardwareKeyReason::TimedOut,
            Reason::SlotNotConfigured => HardwareKeyReason::SlotNotConfigured,
            Reason::BadAnswer => HardwareKeyReason::BadAnswer,
            Reason::NotPermitted => HardwareKeyReason::NotPermitted,
            Reason::Failed => HardwareKeyReason::Failed,
        }
    }
}

/// A configuration slot of the key (INT-07.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// Slot 1 (it usually holds the factory one-time password).
    One,
    /// Slot 2, the usual challenge-response slot.
    Two,
}

impl Slot {
    /// 1 or 2, as the user sees it.
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Slot::One => 1,
            Slot::Two => 2,
        }
    }

    /// The HMAC-SHA1 command of this slot (INT-07.9).
    fn command(self) -> u8 {
        match self {
            Slot::One => 0x30,
            Slot::Two => 0x38,
        }
    }
}

/// Which key to ask (INT-07.5). Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyChoice {
    /// The key's serial number; 0 means the first usable key found.
    pub serial: u32,
    /// The slot.
    pub slot: Slot,
}

/// A plug-in or removal of a device with a vendor id of INT-07.6, as a
/// watched bus reports it (INT-07.14, INT-07.30). Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// A device was plugged in.
    Arrived,
    /// A device was removed.
    Removed,
}

/// What a challenge tells the caller while it runs (INT-07.19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The key waits for a touch: show M06-35 (or M10-18).
    TouchNeeded,
    /// The challenge ended after "touch needed", in any way.
    TouchEnded,
}

/// One usable slot of one key (INT-07.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// "YubiKey 5", "YubiKey NEO", "YubiKey Plus" or "OnlyKey" (INT-07.6).
    pub model: String,
    /// The serial number; 0 when it cannot be read (D-INT07-6).
    pub serial: u32,
    /// The slot.
    pub slot: Slot,
    /// Whether the slot waits for a touch; not shown in the item.
    pub needs_touch: bool,
}

impl Item {
    /// The list text "<model> · serial <serial> · slot <n>" (LD-101), with
    /// "serial unknown" for serial 0.
    #[must_use]
    pub fn label(&self) -> String {
        let serial = match self.serial {
            0 => "unknown".to_owned(),
            n => n.to_string(),
        };
        format!(
            "{} · serial {serial} · slot {}",
            self.model,
            self.slot.number()
        )
    }

    /// The choice that asks this item: a serial of 0 asks any key (D-INT07-6).
    #[must_use]
    pub fn choice(&self) -> KeyChoice {
        KeyChoice {
            serial: self.serial,
            slot: self.slot,
        }
    }
}

/// The result of a look for keys (INT-07.17).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detection {
    /// The usable slots, sorted by serial, then slot.
    pub items: Vec<Item>,
    /// How many keys of INT-07.6 were found and could be read.
    pub devices: usize,
    /// Whether a key was found without a usable slot (M06-36).
    pub without_slot: bool,
}

/// A HID interface App may open (INT-07.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    /// Usage page `F1D0`, usage `01`: macOS opens it without asking.
    Fido,
    /// Usage page `01`, usage `06`: macOS may refuse it (Input Monitoring).
    Keyboard,
}

/// One USB device as listed, before it is opened. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The bus's own handle for the device.
    pub id: u64,
    /// USB vendor id.
    pub vendor: u16,
    /// USB product id.
    pub product: u16,
    /// Whether it has a FIDO interface.
    pub fido: bool,
    /// Whether it has a keyboard interface.
    pub keyboard: bool,
}

/// The layer under the protocol (INT-07.30): the IOKit code, or the
/// simulated device in tests.
pub trait Bus {
    /// An opened interface.
    type Device: Device;
    /// The USB HID devices present now.
    ///
    /// # Errors
    /// A reason when the system cannot list devices.
    fn list(&self) -> Result<Vec<DeviceInfo>, Reason>;
    /// Opens one interface of `device` without seizing it (INT-07.8). The
    /// device closes when the returned value is dropped.
    ///
    /// # Errors
    /// `Missing` when it is gone, `NotPermitted` when macOS refuses the
    /// keyboard interface, else `Failed`.
    fn open(&self, device: &DeviceInfo, interface: Interface) -> Result<Self::Device, Reason>;
    /// Time since a fixed start, for the waits of INT-07.12.
    fn now(&self) -> Duration;
    /// Pauses between two reads.
    fn sleep(&self, pause: Duration);
    /// A running watch; dropping it stops the watch.
    type Watch;
    /// Reports each plug-in and removal of a device with a vendor id of
    /// INT-07.6 to `sink`, from any thread, until the returned watch is
    /// dropped. Devices already plugged in when it starts are not reported.
    /// Opens no device.
    ///
    /// # Errors
    /// `Failed` when the system cannot watch.
    fn watch(&self, sink: Box<dyn Fn(Change) + Send>) -> Result<Self::Watch, Reason>;
}

/// An opened interface: 8-byte feature reports with report id 0 (INT-07.8).
pub trait Device {
    /// Reads one feature report into `report`.
    ///
    /// # Errors
    /// `Missing` when the device is gone, else `Failed`.
    fn read(&mut self, report: &mut [u8; 8]) -> Result<(), Reason>;
    /// Writes one feature report.
    ///
    /// # Errors
    /// `Missing` when the device is gone, else `Failed`.
    fn write(&mut self, report: &[u8; 8]) -> Result<(), Reason>;
}

/// The process-wide lock of INT-07.13.
static DEVICE_LOCK: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    DEVICE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

const YUBICO: u16 = 0x1050;
/// The vendor ids of INT-07.6: Yubico and OnlyKey.
const VENDORS: [u16; 2] = [YUBICO, 0x1D50];
const MAX_DEVICES: usize = 8;

/// The name App shows for a supported device (INT-07.6, D-INT07-5), or
/// `None` for a device without the frame protocol.
fn model(vendor: u16, product: u16, major: u8) -> Option<String> {
    match (vendor, product) {
        (YUBICO, 0x0010 | 0x0401 | 0x0403 | 0x0405 | 0x0407) => Some(format!("YubiKey {major}")),
        (YUBICO, 0x0110 | 0x0111 | 0x0114 | 0x0116) => Some("YubiKey NEO".to_owned()),
        (YUBICO, 0x0410) => Some("YubiKey Plus".to_owned()),
        (0x1D50, 0x60FC) => Some("OnlyKey".to_owned()),
        _ => None,
    }
}

/// The supported devices in the bus's order, at most 8 (INT-07.6, INT-07.15).
fn candidates<B: Bus>(bus: &B) -> Result<Vec<DeviceInfo>, Reason> {
    let mut list = bus.list()?;
    list.retain(|d| (d.fido || d.keyboard) && model(d.vendor, d.product, 0).is_some());
    list.truncate(MAX_DEVICES);
    Ok(list)
}

/// Opens the FIDO interface when there is one, else the keyboard (INT-07.7).
fn open<B: Bus>(bus: &B, device: &DeviceInfo) -> Result<B::Device, Reason> {
    let interface = if device.fido {
        Interface::Fido
    } else {
        Interface::Keyboard
    };
    bus.open(device, interface)
}

/// The serial number, or 0 when it cannot be read (INT-07.11, D-INT07-6).
fn serial<B: Bus>(bus: &B, device: &mut B::Device) -> u32 {
    protocol::exchange(bus, device, &[0; 64], protocol::SERIAL, None)
        .ok()
        .and_then(|s| <[u8; 4]>::try_from(s.expose()).ok())
        .map_or(0, u32::from_be_bytes)
}

/// Looks for keys and their usable slots (INT-07.14 to INT-07.17). Each slot
/// gets a 1-byte test challenge without waiting for a touch, except on a
/// YubiKey NEO or older; a slot that asks for a touch is listed and reset at
/// once, so no touch is ever asked here.
///
/// # Errors
/// `NotPermitted` when macOS refused a key's keyboard interface and no slot
/// could be listed; a reason from the bus when it cannot list devices.
pub fn detect<B: Bus>(bus: &B) -> Result<Detection, Reason> {
    let _one = one_at_a_time();
    let mut found = Detection::default();
    let mut refused = false;
    for info in candidates(bus)? {
        let mut device = match open(bus, &info) {
            Ok(device) => device,
            Err(reason) => {
                refused |= reason == Reason::NotPermitted;
                continue;
            }
        };
        let Ok(status) = protocol::read_status(&mut device) else {
            continue;
        };
        found.devices += 1;
        let serial = serial(bus, &mut device);
        let name = model(info.vendor, info.product, status.firmware[0]).unwrap_or_default();
        let before = found.items.len();
        for slot in [Slot::One, Slot::Two] {
            if !status.configured(slot) {
                continue;
            }
            let needs_touch = if info.vendor == YUBICO && info.product <= 0x0116 {
                Some(false)
            } else {
                test_slot(bus, &mut device, slot)
            };
            if let Some(needs_touch) = needs_touch {
                found.items.push(Item {
                    model: name.clone(),
                    serial,
                    slot,
                    needs_touch,
                });
            }
        }
        found.without_slot |= found.items.len() == before;
    }
    if refused && found.items.is_empty() {
        return Err(Reason::NotPermitted);
    }
    found.items.sort_by_key(|item| (item.serial, item.slot));
    Ok(found)
}

/// The test challenge of INT-07.15 step 4: one random byte padded by the
/// FMT-04.9 rule. `Some(needs touch)` when the slot answers or asks for a
/// touch; `None` when it does neither.
fn test_slot<B: Bus>(bus: &B, device: &mut B::Device, slot: Slot) -> Option<bool> {
    let mut byte = [0u8; 1];
    app_crypto::random::fill(&mut byte).ok()?;
    let padded = app_format::keys::padded_challenge(&byte).ok()?;
    match protocol::exchange(bus, device, &padded, slot.command(), None) {
        Ok(_) => Some(false),
        // Without a touch callback, a touch wait ends at once as TimedOut.
        Err(Reason::TimedOut) => Some(true),
        Err(_) => None,
    }
}

/// One hardware key slot as a part of the composite key (FMT-04.6 to
/// FMT-04.10): each challenge finds the chosen key, asks it, and closes it.
pub struct HardwareKey<B: Bus> {
    /// Where the key is reached.
    pub bus: B,
    /// Which key and slot.
    pub choice: KeyChoice,
    /// Detection said the slot waits for a touch: "touch needed" goes out
    /// as soon as the key is found (INT-07.19).
    pub needs_touch: bool,
    /// Where touch events go, if anywhere.
    pub events: Option<Box<dyn Fn(Event)>>,
}

impl<B: Bus> HardwareKey<B> {
    /// Asks the chosen slot with the 64-byte padded challenge and returns
    /// its 20-byte answer, only in [`SecretBytes`] (INT-07.18). A touch wait
    /// lasts at most 20 s.
    ///
    /// # Errors
    /// `Missing` when no usable key (or not the chosen serial) is connected,
    /// `SlotNotConfigured` when the slot is not set up, `NotPermitted` when
    /// macOS refused the key, and the reasons of the exchange (INT-07.20).
    pub fn ask(&self, padded: &[u8; 64]) -> Result<SecretBytes, Reason> {
        let _one = one_at_a_time();
        let mut fallback = Reason::Missing;
        for info in candidates(&self.bus)? {
            let mut device = match open(&self.bus, &info) {
                Ok(device) => device,
                Err(Reason::NotPermitted) => {
                    fallback = Reason::NotPermitted;
                    continue;
                }
                Err(_) => continue,
            };
            let Ok(status) = protocol::read_status(&mut device) else {
                continue;
            };
            if self.choice.serial != 0 && serial(&self.bus, &mut device) != self.choice.serial {
                continue;
            }
            let answer = if status.configured(self.choice.slot) {
                self.run(&mut device, padded)
            } else {
                Err(Reason::SlotNotConfigured)
            };
            match answer {
                // Serial 0 asks the first usable key: try the next one.
                Err(Reason::SlotNotConfigured) if self.choice.serial == 0 => {
                    if fallback == Reason::Missing {
                        fallback = Reason::SlotNotConfigured;
                    }
                }
                answer => return answer,
            }
        }
        Err(fallback)
    }

    fn run(&self, device: &mut B::Device, padded: &[u8; 64]) -> Result<SecretBytes, Reason> {
        let raised = Cell::new(false);
        let notify = |event: Event| {
            if event == Event::TouchNeeded && raised.replace(true) {
                return;
            }
            if let Some(events) = &self.events {
                events(event);
            }
        };
        if self.needs_touch {
            notify(Event::TouchNeeded);
        }
        let answer = protocol::exchange(
            &self.bus,
            device,
            padded,
            self.choice.slot.command(),
            Some(&notify),
        );
        if raised.get() {
            notify(Event::TouchEnded);
        }
        answer
    }
}

impl<B: Bus> ChallengeResponse for HardwareKey<B> {
    fn challenge(&self, padded: &[u8; 64]) -> Result<SecretBytes, HardwareKeyReason> {
        self.ask(padded).map_err(HardwareKeyReason::from)
    }
}
