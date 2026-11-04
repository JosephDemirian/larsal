//! The simulated USB device of INT-07.30, compiled only into tests. It
//! speaks the feature reports of INT-07.9 to INT-07.12 on a fake clock; its
//! slots answer through app-format's software key (layer 1, INT-07.29), so
//! the HMAC runs in app-crypto.

use crate::protocol::{RESET, crc16};
use crate::{Bus, Change, Device, DeviceInfo, Interface, Reason, VENDORS};
use app_crypto::secret::SecretBytes;
use app_format::keys::{ChallengeResponse, SlotMode, SoftwareKey};
use std::ops::Deref;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Demo secret D of INT-07 and FMT-04.
pub const D: &[u8] = b"App demo HMAC secret";
/// The device's own touch wait (INT-07.12).
const OWN_WAIT: Duration = Duration::from_secs(15);

/// What a slot holds.
pub enum SlotKind {
    /// Not configured: its bit in the status is clear.
    Empty,
    /// HMAC-SHA1 challenge-response, variable or fixed mode.
    Hmac(SoftwareKey),
    /// A one-time password (or any other) configuration: no reply.
    Otp,
}

/// An HMAC-SHA1 slot with `secret`.
pub fn hmac(secret: &[u8], mode: SlotMode) -> SlotKind {
    SlotKind::Hmac(SoftwareKey {
        secret: SecretBytes::new(secret.to_vec()),
        mode,
    })
}

/// One report as the device saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read([u8; 8]),
    Write([u8; 8]),
}

enum State {
    Idle,
    Touch { since: Duration, reply: Vec<u8> },
    Reply { data: Vec<u8>, next: usize },
}

/// One simulated key: what it is, its script, and what it saw.
pub struct Sim {
    pub vendor: u16,
    pub product: u16,
    pub firmware: [u8; 3],
    /// `None`: the serial is hidden (the serial command gets no reply).
    pub serial: Option<u32>,
    pub slots: [SlotKind; 2],
    pub touch: [bool; 2],
    pub fido: bool,
    pub keyboard: bool,
    /// Opening the keyboard interface gives `NotPermitted`.
    pub keyboard_refused: bool,
    /// Script: the touch comes this long after the wait starts; `None`:
    /// never (the device gives up after its own 15 s).
    pub touch_after: Option<Duration>,
    /// Script: report the touch wait forever.
    pub touch_forever: bool,
    /// Script: removed right after this many written reports.
    pub remove_after_writes: Option<usize>,
    /// Script: flip a CRC byte of each reply.
    pub flip_crc: bool,
    /// Script: send only 3 reply reports.
    pub short_reply: bool,
    /// Script: keep the busy bit set forever.
    pub busy_forever: bool,
    /// Script: real time each read takes (a slow device).
    pub slow: Duration,
    /// Told at the first read.
    pub first_read: Option<Sender<()>>,
    /// The real time of every read.
    pub read_times: Vec<Instant>,
    /// Every report, with the fake time.
    pub log: Vec<(Duration, Op)>,
    pub opens: Vec<Interface>,
    pub closes: usize,
    pub removed: bool,
    frame: [u8; 70],
    state: State,
}

impl Sim {
    /// Y5: Yubico `1050:0407`, firmware 5.4.3, serial 24531878, slot 1
    /// one-time password, slot 2 HMAC-SHA1 variable with D, touch off.
    pub fn y5() -> Sim {
        Sim {
            vendor: 0x1050,
            product: 0x0407,
            firmware: [5, 4, 3],
            serial: Some(24_531_878),
            slots: [SlotKind::Otp, hmac(D, SlotMode::Variable)],
            touch: [false, false],
            fido: true,
            keyboard: true,
            keyboard_refused: false,
            touch_after: None,
            touch_forever: false,
            remove_after_writes: None,
            flip_crc: false,
            short_reply: false,
            busy_forever: false,
            slow: Duration::ZERO,
            first_read: None,
            read_times: Vec::new(),
            log: Vec::new(),
            opens: Vec::new(),
            closes: 0,
            removed: false,
            frame: [0; 70],
            state: State::Idle,
        }
    }

    /// The reports written, in order.
    pub fn writes(&self) -> Vec<[u8; 8]> {
        self.log
            .iter()
            .filter_map(|(_, op)| match op {
                Op::Write(r) => Some(*r),
                Op::Read(_) => None,
            })
            .collect()
    }

    /// The command bytes of every frame written (part 9, byte 1 is frame byte 64).
    pub fn commands(&self) -> Vec<u8> {
        self.writes()
            .iter()
            .filter(|r| r[7] == 0x89)
            .map(|r| r[1])
            .collect()
    }

    fn status(&self) -> [u8; 8] {
        let level: u16 = self
            .slots
            .iter()
            .zip([1u16, 2])
            .filter(|(s, _)| !matches!(s, SlotKind::Empty))
            .map(|(_, bit)| bit)
            .sum();
        let [lo, hi] = level.to_le_bytes();
        let [major, minor, build] = self.firmware;
        let busy = if self.busy_forever { 0x80 } else { 0 };
        [0, major, minor, build, 1, lo, hi, busy]
    }

    fn report(&mut self, now: Duration) -> [u8; 8] {
        if let State::Touch { since, reply } = &self.state {
            let waited = now.saturating_sub(*since);
            if self.touch_after.is_some_and(|t| waited >= t) {
                self.state = State::Reply {
                    data: reply.clone(),
                    next: 0,
                };
            } else if waited >= OWN_WAIT && !self.touch_forever {
                self.state = State::Idle;
            } else {
                let left = OWN_WAIT.saturating_sub(waited).as_secs();
                return [0, 0, 0, 0, 0, 0, 0, 0x20 | u8::try_from(left).unwrap()];
            }
        }
        match &mut self.state {
            State::Reply { data, next } => {
                let mut r = [0u8; 8];
                r[7] = 0x40;
                if let Some(part) = data.chunks(7).nth(*next) {
                    r[..part.len()].copy_from_slice(part);
                    r[7] |= u8::try_from(*next).unwrap();
                    *next += 1;
                }
                r
            }
            _ => self.status(),
        }
    }

    fn read(&mut self, now: Duration) -> Result<[u8; 8], Reason> {
        if self.removed {
            return Err(Reason::Missing);
        }
        if let Some(tell) = self.first_read.take() {
            let _ = tell.send(());
        }
        std::thread::sleep(self.slow);
        self.read_times.push(Instant::now());
        let r = self.report(now);
        self.log.push((now, Op::Read(r)));
        Ok(r)
    }

    fn write(&mut self, now: Duration, r: &[u8; 8]) -> Result<(), Reason> {
        if self.removed {
            return Err(Reason::Missing);
        }
        self.log.push((now, Op::Write(*r)));
        if self
            .remove_after_writes
            .is_some_and(|k| self.writes().len() >= k)
        {
            self.removed = true;
        }
        if *r == RESET {
            self.state = State::Idle;
        } else if r[7] & 0x80 != 0 {
            let part = usize::from(r[7] & 0x0F);
            if part == 0 {
                self.frame = [0; 70];
            }
            self.frame[part * 7..part * 7 + 7].copy_from_slice(&r[..7]);
            if part == 9 {
                self.state = self.answer(now);
            }
        }
        Ok(())
    }

    /// What the device does with a complete frame.
    fn answer(&self, now: Duration) -> State {
        let payload: [u8; 64] = self.frame[..64].try_into().unwrap();
        if crc16(&payload).to_le_bytes() != self.frame[65..67] {
            return State::Idle;
        }
        let (mut data, touch) = match self.frame[64] {
            0x10 => match self.serial {
                Some(s) => (s.to_be_bytes().to_vec(), false),
                None => return State::Idle,
            },
            command @ (0x30 | 0x38) => {
                let i = usize::from(command == 0x38);
                let SlotKind::Hmac(key) = &self.slots[i] else {
                    return State::Idle;
                };
                (
                    key.challenge(&payload).unwrap().expose().to_vec(),
                    self.touch[i],
                )
            }
            _ => return State::Idle,
        };
        // The device stores the ones' complement of the CRC, low byte first.
        data.extend_from_slice(&(!crc16(&data)).to_le_bytes());
        if self.flip_crc {
            *data.last_mut().unwrap() ^= 0x01;
        }
        if self.short_reply {
            data.truncate(21);
        }
        if touch {
            State::Touch {
                since: now,
                reply: data,
            }
        } else {
            State::Reply { data, next: 0 }
        }
    }
}

/// The simulated bus: devices in listing order, one fake clock, and the
/// sink of a watch. Clones share it, so a test can plug keys in and pull
/// them out while a watcher's thread uses it.
#[derive(Clone)]
pub struct SimBus(Arc<Mutex<Inner>>);

struct Inner {
    clock: Duration,
    devices: Vec<Sim>,
    sink: Option<Box<dyn Fn(Change) + Send>>,
}

/// One device of the bus, for reading in a test.
pub struct DevRef<'a>(MutexGuard<'a, Inner>, usize);

impl Deref for DevRef<'_> {
    type Target = Sim;
    fn deref(&self) -> &Sim {
        &self.0.devices[self.1]
    }
}

impl SimBus {
    pub fn with(devices: Vec<Sim>) -> SimBus {
        SimBus(Arc::new(Mutex::new(Inner {
            clock: Duration::ZERO,
            devices,
            sink: None,
        })))
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap()
    }

    /// Device `i`; hold it only within one statement while the bus is in use.
    pub fn dev(&self, i: usize) -> DevRef<'_> {
        DevRef(self.inner(), i)
    }

    /// Plugs `sim` in; a watch hears of it when its vendor id is one of INT-07.6.
    pub fn plug_in(&self, sim: Sim) {
        let mut inner = self.inner();
        let ours = VENDORS.contains(&sim.vendor);
        inner.devices.push(sim);
        if let (true, Some(sink)) = (ours, &inner.sink) {
            sink(Change::Arrived);
        }
    }

    /// Pulls device `i` out; a watch hears of it.
    pub fn pull_out(&self, i: usize) {
        let mut inner = self.inner();
        inner.devices[i].removed = true;
        let ours = VENDORS.contains(&inner.devices[i].vendor);
        if let (true, Some(sink)) = (ours, &inner.sink) {
            sink(Change::Removed);
        }
    }
}

impl Bus for SimBus {
    type Device = SimHandle;
    type Watch = ();

    fn list(&self) -> Result<Vec<DeviceInfo>, Reason> {
        Ok(self
            .inner()
            .devices
            .iter()
            .zip(0u64..)
            .filter(|(d, _)| !d.removed)
            .map(|(d, id)| DeviceInfo {
                id,
                vendor: d.vendor,
                product: d.product,
                fido: d.fido,
                keyboard: d.keyboard,
            })
            .collect())
    }

    fn open(&self, info: &DeviceInfo, interface: Interface) -> Result<SimHandle, Reason> {
        let mut inner = self.inner();
        let index = usize::try_from(info.id).map_err(|_| Reason::Missing)?;
        let d = inner.devices.get_mut(index).ok_or(Reason::Missing)?;
        if d.removed {
            return Err(Reason::Missing);
        }
        d.opens.push(interface);
        if interface == Interface::Keyboard && d.keyboard_refused {
            return Err(Reason::NotPermitted);
        }
        Ok(SimHandle {
            bus: self.clone(),
            index,
        })
    }

    fn now(&self) -> Duration {
        self.inner().clock
    }

    fn sleep(&self, pause: Duration) {
        self.inner().clock += pause;
    }

    fn watch(&self, sink: Box<dyn Fn(Change) + Send>) -> Result<(), Reason> {
        self.inner().sink = Some(sink);
        Ok(())
    }
}

/// An opened simulated device; counts its close when dropped.
pub struct SimHandle {
    bus: SimBus,
    index: usize,
}

impl Device for SimHandle {
    fn read(&mut self, report: &mut [u8; 8]) -> Result<(), Reason> {
        let mut inner = self.bus.inner();
        let now = inner.clock;
        *report = inner.devices[self.index].read(now)?;
        Ok(())
    }

    fn write(&mut self, report: &[u8; 8]) -> Result<(), Reason> {
        let mut inner = self.bus.inner();
        let now = inner.clock;
        inner.devices[self.index].write(now, report)
    }
}

impl Drop for SimHandle {
    fn drop(&mut self) {
        self.bus.inner().devices[self.index].closes += 1;
    }
}
