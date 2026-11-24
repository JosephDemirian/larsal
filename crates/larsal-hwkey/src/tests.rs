//! INT-07's test cases against the simulated device (INT-07.30), named by
//! T-number. All run on the fake clock; no real USB call is made (T47: the
//! usb module is not in this binary).

use super::*;
use crate::protocol::{RESET, crc16, frame_reports, read_status};
use crate::sim::{D, Op, Sim, SimBus, SlotKind, hmac};
use larsal_crypto::kdf::{Host, SpeedRecord};
use larsal_crypto::secret::SecretString;
use larsal_format::keys::{
    Credentials, SlotMode, composite_key, hardware_part, padded_challenge, password_part,
};
use larsal_format::limits::Limits;
use larsal_format::{Error, Opened, Saved};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Instant;

/// `KS` of FMT-04.6-a.
const KS: &str = "3481483a67fb365da911c5095420ce2bfd2161793b47d7a6561cedf921899e63";
/// T03: the variable-mode and fixed-mode answers for `KS` with D.
const ANSWER: &str = "05c98b753b0a4bda4c42e79228e79ddee3cdac14";
const ANSWER_FIXED: &str = "93816c27e0160e71c86ccc92715253cfb5073d4f";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ks() -> [u8; 64] {
    padded_challenge(&hex(KS)).unwrap()
}

/// A report: 7 bytes in hex, then byte 7.
fn r(seven: &str, flags: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..7].copy_from_slice(&hex(seven));
    out[7] = flags;
    out
}

fn key(devices: Vec<Sim>, serial: u32, slot: Slot) -> HardwareKey<SimBus> {
    HardwareKey {
        bus: SimBus::with(devices),
        choice: KeyChoice { serial, slot },
        needs_touch: false,
        events: None,
    }
}

/// Y5t: slot 2 waits for a touch.
fn y5t() -> Sim {
    let mut s = Sim::y5();
    s.touch[1] = true;
    s
}

/// Y5f: slot 2 in fixed mode.
fn y5f() -> Sim {
    let mut s = Sim::y5();
    s.slots[1] = hmac(D, SlotMode::Fixed);
    s
}

/// The second key of T05 to T07: serial 1000, slot 2 = D variable.
fn k1000() -> Sim {
    let mut s = Sim::y5();
    s.serial = Some(1000);
    s
}

/// NEO: `1050:0116`, firmware 3.4, slot 2 HMAC with D.
fn neo() -> Sim {
    let mut s = Sim::y5();
    s.product = 0x0116;
    s.firmware = [3, 4, 0];
    s.serial = Some(2);
    s
}

fn is_touch_wait(op: &Op) -> bool {
    matches!(op, Op::Read(r) if r[7] & 0x20 != 0 && r[7] & 0x40 == 0)
}

fn first_touch_report(sim: &Sim) -> Duration {
    sim.log
        .iter()
        .find_map(|(t, op)| is_touch_wait(op).then_some(*t))
        .unwrap()
}

fn recorder(hw: &mut HardwareKey<SimBus>) -> Rc<RefCell<Vec<(Event, Duration)>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let (s, bus) = (Rc::clone(&seen), hw.bus.clone());
    hw.events = Some(Box::new(move |e| s.borrow_mut().push((e, bus.now()))));
    seen
}

// ---------------------------------------------------------------------------
// Frames, replies and timing (INT-07.9 to INT-07.12)

#[test]
fn t03_answers_in_variable_and_fixed_mode() {
    for (sim, want) in [(Sim::y5(), ANSWER), (y5f(), ANSWER_FIXED)] {
        let hw = key(vec![sim], 0, Slot::Two);
        assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(want));
    }
}

#[test]
fn t13_frame_reports_of_the_ks_challenge() {
    assert_eq!(crc16(&ks()), 0xED74);
    let hw = key(vec![Sim::y5()], 0, Slot::Two);
    hw.ask(&ks()).unwrap();
    let parts = [
        "3481483a67fb36",
        "5da911c5095420",
        "ce2bfd2161793b",
        "47d7a6561cedf9",
        "21899e63202020",
        "20202020202020",
        "20202020202020",
        "20202020202020",
        "20202020202020",
        "203874ed000000",
    ];
    let mut want: Vec<[u8; 8]> = parts.iter().zip(0x80u8..).map(|(p, f)| r(p, f)).collect();
    want.push(RESET);
    assert_eq!(hw.bus.dev(0).writes(), want);
}

#[test]
fn t14_serial_command_skips_zero_parts() {
    assert_eq!(crc16(&[0; 64]), 0x5B6B);
    let want = vec![r("00000000000000", 0x80), r("00106b5b000000", 0x89)];
    assert_eq!(frame_reports(&[0; 64], 0x10), want);
    // Detection reads the serial with exactly these two reports.
    let bus = SimBus::with(vec![Sim::y5()]);
    detect(&bus).unwrap();
    assert_eq!(bus.dev(0).writes()[..2], want[..]);
}

#[test]
fn t14_padded_test_challenge() {
    let padded = padded_challenge(&[0x5a]).unwrap();
    assert_eq!(padded[1..], [0x3f; 63]);
    assert_eq!(crc16(&padded), 0x0A36);
    let mut want = vec![r("5a3f3f3f3f3f3f", 0x80)];
    want.extend((0x81..=0x88).map(|f| r("3f3f3f3f3f3f3f", f)));
    want.push(r("3f30360a000000", 0x89));
    assert_eq!(frame_reports(&padded, 0x30), want);
}

#[test]
fn t15_busy_forever_fails_after_1150_ms() {
    let mut s = Sim::y5();
    s.busy_forever = true;
    let hw = key(vec![s], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::Failed);
    assert_eq!(hw.bus.now(), Duration::from_millis(1_150));
    // No frame part went out; the reset did.
    assert_eq!(hw.bus.dev(0).writes(), [RESET]);
}

#[test]
fn t16_reply_reports_and_one_reset() {
    let hw = key(vec![Sim::y5()], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
    let dev = hw.bus.dev(0);
    let replies: Vec<[u8; 8]> = dev
        .log
        .iter()
        .filter_map(|(_, op)| match op {
            Op::Read(r) if r[7] & 0x40 != 0 => Some(*r),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        [
            r("05c98b753b0a4b", 0x40),
            r("da4c42e79228e7", 0x41),
            r("9ddee3cdac145c", 0x42),
            r("dd000000000000", 0x43),
            r("00000000000000", 0x40),
        ]
    );
    let bytes: Vec<u8> = replies[..4].iter().flat_map(|r| r[..7].to_vec()).collect();
    assert_eq!(crc16(&bytes[..22]), 0xF0B8);
    assert!(matches!(dev.log.last(), Some((_, Op::Write(w))) if *w == RESET));
    assert_eq!(dev.writes().iter().filter(|w| **w == RESET).count(), 1);
}

#[test]
fn t17_flipped_crc_and_short_reply_are_bad_answers() {
    let mut flipped = Sim::y5();
    flipped.flip_crc = true;
    let mut short = Sim::y5();
    short.short_reply = true;
    for sim in [flipped, short] {
        let hw = key(vec![sim], 0, Slot::Two);
        assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::BadAnswer);
        assert_eq!(
            hw.challenge(&ks()).unwrap_err(),
            HardwareKeyReason::BadAnswer
        );
    }
}

#[test]
fn t18_status_and_serial() {
    let bus = SimBus::with(vec![Sim::y5()]);
    let info = bus.list().unwrap()[0];
    let mut dev = bus.open(&info, Interface::Fido).unwrap();
    let status = read_status(&mut dev).unwrap();
    assert_eq!(status.firmware, [5, 4, 3]);
    assert!(status.configured(Slot::One) && status.configured(Slot::Two));
    assert_eq!(serial(&bus, &mut dev), 24_531_878);
    let reply = Op::Read(r("017653a6c78f00", 0x40));
    assert!(bus.dev(0).log.iter().any(|(_, op)| *op == reply));
}

#[test]
fn t19_touch_after_3_s() {
    // Also with detection's hint: "touch needed" at once, and only once.
    for hint in [false, true] {
        let mut s = y5t();
        s.touch_after = Some(Duration::from_secs(3));
        let mut hw = key(vec![s], 0, Slot::Two);
        hw.needs_touch = hint;
        let seen = recorder(&mut hw);
        assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
        let first = first_touch_report(&hw.bus.dev(0));
        let seen = seen.borrow();
        let events: Vec<Event> = seen.iter().map(|(e, _)| *e).collect();
        assert_eq!(events, [Event::TouchNeeded, Event::TouchEnded]);
        assert!(seen[0].1 <= first + Duration::from_millis(200));
        assert!(hw.bus.now() >= first + Duration::from_secs(3));
    }
}

#[test]
fn t20_untouched_key_gives_up_after_its_15_s() {
    let mut hw = key(vec![y5t()], 0, Slot::Two);
    let seen = recorder(&mut hw);
    assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::TimedOut);
    let waited = hw.bus.now() - first_touch_report(&hw.bus.dev(0));
    assert!(waited >= Duration::from_secs(15) && waited < Duration::from_secs(16));
    assert_eq!(seen.borrow().len(), 2, "touch needed, then touch ended");
}

#[test]
fn t21_endless_touch_wait_ends_at_20_s() {
    let mut s = y5t();
    s.touch_forever = true;
    let hw = key(vec![s], 0, Slot::Two);
    assert_eq!(
        hw.challenge(&ks()).unwrap_err(),
        HardwareKeyReason::TimedOut
    );
    let first = first_touch_report(&hw.bus.dev(0));
    assert_eq!(hw.bus.now() - first, Duration::from_secs(20));
}

// ---------------------------------------------------------------------------
// Which key is asked (INT-07.5 to INT-07.8)

#[test]
fn t05_backup_key_with_another_serial() {
    let hw = key(vec![Sim::y5(), k1000()], 1000, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
    assert!(!hw.bus.dev(0).commands().contains(&0x38));
    assert!(hw.bus.dev(1).commands().contains(&0x38));
}

#[test]
fn t06_chosen_serial_absent_is_missing() {
    let hw = key(vec![k1000()], 24_531_878, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::Missing);
    // Only its serial was read: no challenge reached it.
    assert_eq!(hw.bus.dev(0).commands(), [0x10]);
}

#[test]
fn t07_serial_0_asks_any_key() {
    let hw = key(vec![k1000()], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
}

#[test]
fn t07_serial_0_asks_the_first_usable_key() {
    // The first key's slot 2 holds a one-time password: it never answers.
    let mut otp = Sim::y5();
    otp.slots[1] = SlotKind::Otp;
    let hw = key(vec![otp, k1000()], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
    assert_eq!(hw.bus.dev(0).commands(), [0x38]);
    assert_eq!(hw.bus.dev(1).commands(), [0x38]);
}

#[test]
fn t08_only_devices_with_the_frame_protocol_are_asked() {
    let mut no_otp = Sim::y5();
    no_otp.product = 0x0402;
    let mut other = Sim::y5();
    other.vendor = 0x1234;
    other.product = 0x5678;
    let bus = SimBus::with(vec![no_otp, Sim::y5(), other]);
    assert_eq!(detect(&bus).unwrap().items.len(), 1);
    assert!(bus.dev(0).opens.is_empty());
    assert!(bus.dev(2).opens.is_empty());
}

#[test]
fn t09_model_names() {
    let mut ok = Sim::y5();
    ok.vendor = 0x1D50;
    ok.product = 0x60FC;
    ok.serial = Some(3);
    let mut old = Sim::y5();
    old.product = 0x0010;
    old.firmware = [2, 4, 0];
    old.serial = Some(4);
    let bus = SimBus::with(vec![Sim::y5(), neo(), ok, old]);
    let mut names: Vec<String> = detect(&bus)
        .unwrap()
        .items
        .into_iter()
        .map(|i| i.model)
        .collect();
    names.dedup();
    assert_eq!(names, ["YubiKey NEO", "OnlyKey", "YubiKey 2", "YubiKey 5"]);
}

#[test]
fn t10_fido_interface_first() {
    let hw = key(vec![Sim::y5()], 0, Slot::Two);
    hw.ask(&ks()).unwrap();
    assert_eq!(hw.bus.dev(0).opens, [Interface::Fido]);
}

#[test]
fn t11_refused_keyboard_interface_is_not_permitted() {
    let mut s = Sim::y5();
    s.fido = false;
    s.keyboard_refused = true;
    let hw = key(vec![s], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::NotPermitted);
    assert_eq!(hw.bus.dev(0).opens, [Interface::Keyboard]);
    assert_eq!(detect(&hw.bus).unwrap_err(), Reason::NotPermitted);
    assert_eq!(
        hw.challenge(&ks()).unwrap_err(),
        HardwareKeyReason::NotPermitted
    );
    assert!(MI07_01.contains("Input Monitoring"));
}

#[test]
fn t12_shared_open_closed_after_use() {
    let bus = SimBus::with(vec![Sim::y5()]);
    let info = bus.list().unwrap()[0];
    let other_client = bus.open(&info, Interface::Fido).unwrap();
    let hw = HardwareKey {
        bus,
        choice: KeyChoice {
            serial: 0,
            slot: Slot::Two,
        },
        needs_touch: false,
        events: None,
    };
    hw.ask(&ks()).unwrap();
    let dev = hw.bus.dev(0);
    assert_eq!((dev.opens.len(), dev.closes), (2, 1));
    drop(dev);
    drop(other_client);
    assert_eq!(hw.bus.dev(0).closes, 2);
}

// ---------------------------------------------------------------------------
// Detection (INT-07.15, INT-07.16)

#[test]
fn t25_one_time_password_slot_not_listed() {
    let bus = SimBus::with(vec![Sim::y5()]);
    let found = detect(&bus).unwrap();
    let want = Item {
        model: "YubiKey 5".to_owned(),
        serial: 24_531_878,
        slot: Slot::Two,
        needs_touch: false,
    };
    assert_eq!(found.items, [want]);
    assert_eq!(
        found.items[0].label(),
        "YubiKey 5 · serial 24531878 · slot 2"
    );
    let dev = bus.dev(0);
    // The serial, then one test challenge per slot.
    assert_eq!(dev.commands(), [0x10, 0x30, 0x38]);
    // The first test challenge's part 1: padding bytes 3f.
    let part1 = dev.writes().into_iter().find(|w| w[7] == 0x81).unwrap();
    assert_eq!(part1[..7], [0x3f; 7]);
    assert!(
        !dev.log.iter().any(|(_, op)| is_touch_wait(op)),
        "no touch asked"
    );
}

#[test]
fn t26_touch_slot_listed_and_reset_at_once() {
    let bus = SimBus::with(vec![y5t()]);
    let found = detect(&bus).unwrap();
    assert_eq!(found.items.len(), 1);
    assert!(found.items[0].needs_touch);
    let dev = bus.dev(0);
    let at = dev
        .log
        .iter()
        .position(|(_, op)| is_touch_wait(op))
        .unwrap();
    assert_eq!(dev.log[at + 1], (dev.log[at].0, Op::Write(RESET)));
}

#[test]
fn t27_neo_listed_without_test_challenge() {
    let mut n = neo();
    n.touch[1] = true;
    let bus = SimBus::with(vec![n]);
    let found = detect(&bus).unwrap();
    assert!(
        found
            .items
            .iter()
            .any(|i| i.slot == Slot::Two && i.model == "YubiKey NEO")
    );
    assert_eq!(bus.dev(0).commands(), [0x10]);
}

#[test]
fn t28_key_without_usable_slot() {
    let mut s = Sim::y5();
    s.slots[1] = SlotKind::Otp;
    let bus = SimBus::with(vec![s]);
    let found = detect(&bus).unwrap();
    assert_eq!(
        (found.devices, found.items.len(), found.without_slot),
        (1, 0, true)
    );
}

#[test]
fn t29_hidden_serial_is_any_key() {
    let mut s = Sim::y5();
    s.serial = None;
    let found = detect(&SimBus::with(vec![s])).unwrap();
    assert_eq!(
        found.items[0].label(),
        "YubiKey 5 · serial unknown · slot 2"
    );
    let choice = KeyChoice {
        serial: 0,
        slot: Slot::Two,
    };
    assert_eq!(found.items[0].choice(), choice);
}

#[test]
fn t30_items_sorted_by_serial() {
    let found = detect(&SimBus::with(vec![Sim::y5(), k1000()])).unwrap();
    let serials: Vec<u32> = found.items.iter().map(|i| i.serial).collect();
    assert_eq!(serials, [1000, 24_531_878]);
}

// ---------------------------------------------------------------------------
// One operation at a time, and the watcher (INT-07.13, INT-07.14)

/// A slow Y5 (5 ms of real time per read) that says when its first read
/// runs, that is, when a look holds the device lock.
fn slow_y5() -> (Sim, mpsc::Receiver<()>) {
    let (tell, started) = mpsc::channel();
    let mut s = Sim::y5();
    s.slow = Duration::from_millis(5);
    s.first_read = Some(tell);
    (s, started)
}

type Looks = mpsc::Receiver<(Instant, Result<Detection, Reason>)>;

fn watcher(bus: SimBus) -> (KeyWatcher, Looks) {
    let (tx, looks) = mpsc::channel();
    let w = KeyWatcher::start(bus, move |look| {
        let _ = tx.send((Instant::now(), look));
    })
    .unwrap();
    (w, looks)
}

fn next(looks: &Looks) -> (Instant, Detection) {
    let (at, look) = looks.recv_timeout(Duration::from_secs(10)).unwrap();
    (at, look.unwrap())
}

#[test]
fn t22_challenge_waits_for_a_running_detection() {
    let (slow, started) = slow_y5();
    let bus = SimBus::with(vec![slow]);
    let looking = bus.clone();
    let detection = std::thread::spawn(move || detect(&looking).unwrap());
    started.recv().unwrap();
    let hw = key(vec![Sim::y5()], 0, Slot::Two);
    assert_eq!(hw.ask(&ks()).unwrap().expose(), hex(ANSWER));
    assert_eq!(detection.join().unwrap().items.len(), 1);
    // Both buses note the real time of each read, each while holding the lock.
    let detection_end = *bus.dev(0).read_times.last().unwrap();
    let challenge_start = hw.bus.dev(0).read_times[0];
    assert!(challenge_start > detection_end);
}

#[test]
fn t22_requests_during_a_look_fold_into_one_more() {
    let (slow, started) = slow_y5();
    let (w, looks) = watcher(SimBus::with(vec![slow]));
    started.recv().unwrap();
    // "Look for keys again" twice while the first look runs.
    w.look_again();
    w.look_again();
    let (first, _) = next(&looks);
    let (second, found) = next(&looks);
    assert!(second > first);
    assert_eq!(found.items.len(), 1);
    assert!(
        looks.recv_timeout(Duration::from_millis(700)).is_err(),
        "one more look, not two"
    );
}

#[test]
fn t23_plug_in_starts_a_look_0_5_s_later() {
    let bus = SimBus::with(vec![]);
    let (_w, looks) = watcher(bus.clone());
    assert_eq!(next(&looks).1.devices, 0, "the look when the view appears");
    bus.plug_in(Sim::y5());
    // A second plug-in within 0.5 s moves the look on: one look for both.
    std::thread::sleep(Duration::from_millis(200));
    let plugged = Instant::now();
    bus.plug_in(k1000());
    let (at, found) = next(&looks);
    assert!(at >= plugged + Duration::from_millis(500));
    let listed: Vec<(u32, Slot)> = found.items.iter().map(|i| (i.serial, i.slot)).collect();
    assert_eq!(listed, [(1000, Slot::Two), (24_531_878, Slot::Two)]);
    assert!(
        looks.recv_timeout(Duration::from_millis(700)).is_err(),
        "one look"
    );
}

#[test]
fn t24_removal_starts_no_look() {
    let bus = SimBus::with(vec![Sim::y5()]);
    let (_w, looks) = watcher(bus.clone());
    assert_eq!(next(&looks).1.items.len(), 1);
    bus.pull_out(0);
    assert!(looks.recv_timeout(Duration::from_millis(800)).is_err());
}

// ---------------------------------------------------------------------------
// Failures (INT-07.19 to INT-07.21, INT-07.1)

#[test]
fn t32_no_key_no_touch_event() {
    let mut hw = key(vec![], 0, Slot::Two);
    hw.needs_touch = true;
    let seen = recorder(&mut hw);
    assert_eq!(hw.challenge(&ks()).unwrap_err(), HardwareKeyReason::Missing);
    assert!(seen.borrow().is_empty());
}

#[test]
fn t33_clear_slot_bit_is_slot_not_configured() {
    for serial in [0, 24_531_878] {
        let mut s = Sim::y5();
        s.slots[1] = SlotKind::Empty;
        let hw = key(vec![s], serial, Slot::Two);
        assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::SlotNotConfigured);
        assert!(!hw.bus.dev(0).commands().contains(&0x38));
    }
}

#[test]
fn t49_only_known_commands_are_sent() {
    // Slot 2 holds a configuration of another kind: it never answers.
    let mut s = Sim::y5();
    s.slots[1] = SlotKind::Otp;
    let bus = SimBus::with(vec![s]);
    assert!(detect(&bus).unwrap().items.is_empty());
    let hw = HardwareKey {
        bus,
        choice: KeyChoice {
            serial: 24_531_878,
            slot: Slot::Two,
        },
        needs_touch: false,
        events: None,
    };
    assert_eq!(hw.ask(&ks()).unwrap_err(), Reason::SlotNotConfigured);
    let dev = hw.bus.dev(0);
    assert!(
        dev.commands()
            .iter()
            .all(|c| [0x10, 0x30, 0x38].contains(c))
    );
    assert!(
        dev.writes()
            .iter()
            .all(|w| *w == RESET || (0x80..=0x89).contains(&w[7]))
    );
}

// ---------------------------------------------------------------------------
// The answer in the key flow (FMT-04), AT-H03 and AT-H04

#[test]
fn t03_answer_becomes_r_in_the_composite_key() {
    // FMT-04.6-a: demo-pass, key file X, the key's answer for KS.
    let hw = key(vec![Sim::y5()], 24_531_878, Slot::Two);
    let r = hardware_part(&hw, &hex(KS)).unwrap();
    let want_r = "0bb9f4e1ac2332efd4345b6776a36ae211a5000d108ecb6812f7caea44c1c59e";
    assert_eq!(r.expose(), hex(want_r));
    let p = password_part(&SecretString::new("demo-pass".to_owned()));
    let f = SecretBytes::new((0x60..0x80).collect());
    let c = composite_key(Some(&p), Some(&f), Some(&r));
    let want_c = "5766f34ebf894d4f0339f5cb61f8eb3f596f0c490fd24dc6cca545d5ed3e4a16";
    assert_eq!(c.expose(), hex(want_c));
}

fn host() -> Host {
    Host {
        physical_memory: 16 << 30,
        logical_processors: 8,
        argon2_record: Some(SpeedRecord {
            count: 10,
            memory_kib: 65_536,
            lanes: 4,
            ms: 1_000,
        }),
        aes_record: Some(SpeedRecord {
            count: 100_000_000,
            memory_kib: 0,
            lanes: 1,
            ms: 1_000,
        }),
    }
}

/// A small vault with AES-KDF at 1 round, so saves are cheap.
fn vault() -> larsal_model::Vault {
    let now = larsal_model::Time::from_unix(1_700_000_000).unwrap();
    let root = larsal_model::Group::new(larsal_model::Uuid([1; 16]), "Root".to_owned(), now);
    let mut v = larsal_model::Vault::new(root, now);
    v.encryption.kdf = larsal_model::Kdf::AesKdf { rounds: 1 };
    v
}

fn creds<'a>(password: &'a SecretString, hw: &'a HardwareKey<SimBus>) -> Credentials<'a> {
    Credentials {
        password: Some(password),
        key_file: None,
        hardware_key: Some(hw),
    }
}

fn save_with(hw: &HardwareKey<SimBus>) -> Result<Vec<u8>, Error> {
    let p = SecretString::new("demo-pass".to_owned());
    let saved = larsal_format::save(
        &vault(),
        &creds(&p, hw),
        None,
        &mut host(),
        &Limits::DEFAULT,
        None,
    )?;
    match saved {
        Saved::File(file) => Ok(file.bytes),
        Saved::Ask(_) => panic!("1 AES-KDF round never asks"),
    }
}

fn open_with(file: &[u8], hw: &HardwareKey<SimBus>) -> Result<(), Error> {
    let p = SecretString::new("demo-pass".to_owned());
    match larsal_format::open(file, &creds(&p, hw), &mut host(), &Limits::DEFAULT, None)? {
        Opened::Vault(_) => Ok(()),
        Opened::Ask(_) => panic!("1 AES-KDF round never asks"),
    }
}

#[test]
fn t01_t02_vault_opens_with_the_key_and_every_save_asks_again() {
    let hw = key(vec![Sim::y5()], 0, Slot::Two);
    let first = save_with(&hw).unwrap();
    let second = save_with(&hw).unwrap();
    // T02: one HMAC frame per save, each with that save's new seed.
    let starts: Vec<[u8; 8]> = hw
        .bus
        .dev(0)
        .writes()
        .into_iter()
        .filter(|w| w[7] == 0x80)
        .collect();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0], starts[1]);
    // T01: one HMAC frame per unlock, and the vault opens.
    for file in [&first, &second] {
        open_with(file, &hw).unwrap();
    }
    assert_eq!(hw.bus.dev(0).commands(), [0x38; 4]);
}

#[test]
fn t04_t34_at_h04_other_secret_or_mode_is_the_wrong_key_result() {
    let file = save_with(&key(vec![Sim::y5()], 0, Slot::Two)).unwrap();
    let mut other = Sim::y5();
    other.slots[1] = hmac(b"another demo secret!", SlotMode::Variable);
    for sim in [y5f(), other] {
        let got = open_with(&file, &key(vec![sim], 0, Slot::Two));
        assert_eq!(got.unwrap_err(), Error::WrongKey);
    }
}

#[test]
fn t35_at_h03_key_missing_or_removed() {
    let missing = Error::HardwareKey(HardwareKeyReason::Missing);
    let file = save_with(&key(vec![Sim::y5()], 0, Slot::Two)).unwrap();
    // Unlock without the key: a hardware key error, not the wrong-key result.
    assert_eq!(
        open_with(&file, &key(vec![], 0, Slot::Two)).unwrap_err(),
        missing
    );
    // Removed after the 3rd write report of the save's challenge: no file
    // bytes come back, so there is nothing to write.
    let mut gone = Sim::y5();
    gone.remove_after_writes = Some(3);
    let hw = key(vec![gone], 0, Slot::Two);
    assert_eq!(save_with(&hw).unwrap_err(), missing);
    assert_eq!(hw.bus.dev(0).writes().len(), 3);
}
