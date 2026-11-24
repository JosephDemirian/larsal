//! The frame protocol of INT-07.9 to INT-07.12, over any [`Bus`].

use crate::{Bus, Device, Event, Reason, Slot};
use larsal_crypto::secret::SecretBytes;
use std::time::Duration;

/// Command: read the serial number (empty payload).
pub(crate) const SERIAL: u8 = 0x10;
/// The report that makes the device leave reply mode (INT-07.10).
pub(crate) const RESET: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x8F];

/// Byte 7 written: a frame part. Byte 7 read: still busy.
const WRITE: u8 = 0x80;
/// Byte 7 read: a reply report.
const PENDING: u8 = 0x40;
/// Byte 7 read: waiting for a touch.
const TOUCH: u8 = 0x20;
/// Byte 7 read: the low 5 bits count reply reports.
const COUNT: u8 = 0x1F;
/// The CRC over reply bytes and their stored CRC (INT-07.10).
const RESIDUAL: u16 = 0xF0B8;

const WRITE_STEP: Duration = Duration::from_millis(1_150);
const REPLY_START: Duration = Duration::from_millis(1_000);
const TOUCH_MAX: Duration = Duration::from_secs(20); // D-INT07-4
const FIRST_PAUSE: Duration = Duration::from_millis(1);
const MAX_PAUSE: Duration = Duration::from_millis(500);

/// The frame CRC of INT-07.9: start `FFFF`, reflected polynomial `8408`.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF_u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            let out = crc & 1;
            crc >>= 1;
            if out != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// The feature reports of one frame (INT-07.9): 64 payload bytes, the
/// command, the CRC low byte first, 3 zero bytes; 7 bytes per report with
/// byte 7 = `80` + part number; all-zero parts skipped except the first and
/// the last.
pub(crate) fn frame_reports(payload: &[u8; 64], command: u8) -> Vec<[u8; 8]> {
    let mut frame = [0u8; 70];
    frame[..64].copy_from_slice(payload);
    frame[64] = command;
    frame[65..67].copy_from_slice(&crc16(payload).to_le_bytes());
    frame
        .as_chunks::<7>()
        .0
        .iter()
        .zip(0u8..)
        .filter(|&(part, n)| n == 0 || n == 9 || part.iter().any(|&b| b != 0))
        .map(|(part, n)| {
            let mut report = [0u8; 8];
            report[..7].copy_from_slice(part);
            report[7] = WRITE | n;
            report
        })
        .collect()
}

/// The status report of INT-07.11.
pub(crate) struct Status {
    /// Major, minor and build version.
    pub firmware: [u8; 3],
    /// Bit `01`: slot 1 configured; bit `02`: slot 2 configured.
    pub touch_level: u16,
}

impl Status {
    pub(crate) fn configured(&self, slot: Slot) -> bool {
        let bit = match slot {
            Slot::One => 0x01,
            Slot::Two => 0x02,
        };
        self.touch_level & bit != 0
    }
}

/// Reads the status with one plain feature report read (INT-07.11).
pub(crate) fn read_status(device: &mut impl Device) -> Result<Status, Reason> {
    let mut r = [0u8; 8];
    device.read(&mut r)?;
    Ok(Status {
        firmware: [r[1], r[2], r[3]],
        touch_level: u16::from_le_bytes([r[5], r[6]]),
    })
}

/// Sends one frame and reads its reply (INT-07.9, INT-07.10): 4 bytes for
/// the serial command, 20 for an HMAC command. Writes the reset report at
/// the end, whatever happened. `touch`: where "touch needed" goes while Larsal
/// waits for a touch; `None` waits for none and gives `TimedOut` at once
/// when the device asks for one (detection, INT-07.15).
pub(crate) fn exchange<B: Bus>(
    bus: &B,
    device: &mut B::Device,
    payload: &[u8; 64],
    command: u8,
    touch: Option<&dyn Fn(Event)>,
) -> Result<SecretBytes, Reason> {
    let (len, silent) = if command == SERIAL {
        (4, Reason::Failed)
    } else {
        (20, Reason::SlotNotConfigured)
    };
    let reply = write_frame(bus, device, payload, command)
        .and_then(|()| read_reply(bus, device, len, silent, touch));
    // A removed device cannot take it; the result already says so.
    let _ = device.write(&RESET);
    reply
}

/// Before each report, waits until the device clears its busy bit, for at
/// most 1,150 ms (INT-07.9).
fn write_frame<B: Bus>(
    bus: &B,
    device: &mut B::Device,
    payload: &[u8; 64],
    command: u8,
) -> Result<(), Reason> {
    let mut status = [0u8; 8];
    for report in frame_reports(payload, command) {
        let mut poll = Poll::new(bus, WRITE_STEP);
        loop {
            device.read(&mut status)?;
            if status[7] & WRITE == 0 {
                break;
            }
            if !poll.wait(bus) {
                return Err(Reason::Failed);
            }
        }
        device.write(&report)?;
    }
    Ok(())
}

/// Reads reply reports (INT-07.10, INT-07.12) straight into secret memory
/// and checks their count and CRC. `silent`: the reason when no reply or
/// touch wait starts within 1,000 ms.
fn read_reply<B: Bus>(
    bus: &B,
    device: &mut B::Device,
    len: usize,
    silent: Reason,
    touch: Option<&dyn Fn(Event)>,
) -> Result<SecretBytes, Reason> {
    let reports = (len + 2).div_ceil(7);
    let mut reply = SecretBytes::zeroed(reports * 7);
    let mut scratch = SecretBytes::zeroed(8);
    let mut got = 0;
    let mut touching = false;
    let mut poll = Poll::new(bus, REPLY_START);
    loop {
        let report: &mut [u8; 8] = scratch
            .expose_mut()
            .try_into()
            .map_err(|_| Reason::Failed)?;
        device.read(report)?;
        let flags = report[7];
        if flags & PENDING != 0 {
            let n = usize::from(flags & COUNT);
            if n == 0 && got > 0 {
                break;
            }
            if n != got || got == reports {
                return Err(Reason::BadAnswer);
            }
            reply.expose_mut()[n * 7..n * 7 + 7].copy_from_slice(&report[..7]);
            got += 1;
            continue;
        }
        if got > 0 {
            return Err(Reason::BadAnswer);
        }
        if flags & TOUCH != 0 {
            let Some(touch) = touch else {
                return Err(Reason::TimedOut);
            };
            if !touching {
                touching = true;
                touch(Event::TouchNeeded);
                poll = Poll::new(bus, TOUCH_MAX);
            }
        } else if touching {
            // The device stopped waiting without a reply.
            return Err(Reason::TimedOut);
        }
        if !poll.wait(bus) {
            return Err(if touching { Reason::TimedOut } else { silent });
        }
    }
    let body = &reply.expose()[..len + 2];
    if got != reports || crc16(body) != RESIDUAL {
        return Err(Reason::BadAnswer);
    }
    Ok(SecretBytes::new(body[..len].to_vec()))
}

/// Polling with a growing pause, 1 ms doubling up to 500 ms, never past the
/// deadline (INT-07.12).
struct Poll {
    deadline: Duration,
    pause: Duration,
}

impl Poll {
    fn new<B: Bus>(bus: &B, limit: Duration) -> Poll {
        Poll {
            deadline: bus.now() + limit,
            pause: FIRST_PAUSE,
        }
    }

    /// Pauses once; false when the deadline has passed.
    fn wait<B: Bus>(&mut self, bus: &B) -> bool {
        let now = bus.now();
        if now >= self.deadline {
            return false;
        }
        bus.sleep(self.pause.min(self.deadline - now));
        self.pause = (self.pause * 2).min(MAX_PAUSE);
        true
    }
}
