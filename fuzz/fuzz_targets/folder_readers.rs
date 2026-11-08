//! Fuzz target `folder_readers` (E23-S3; FIL-04, FIL-06.2, FIL-06.3): every reader of
//! untrusted folder bytes, through larsal-folders' fuzz door, in memory, with the door's
//! demo keys only. Must never panic, hang or allocate from an unchecked length, and a
//! stored file's every failure is the one generic error.
//!
//! Input: a mode byte (taken modulo 7), then the rest.
//! - 0: the rest is a vault configuration.
//! - 1: the rest is a masterkey file.
//! - 2: a parent ID length byte (at most 36 used), the parent ID, then a stored name.
//! - 3: the rest is a new clear name; a name it accepts must open back to itself.
//! - 4: a node name length byte, the node name, then a shortened node's mapping.
//! - 5: a worker byte (1 to 4), then a whole stored file.
//! - 6: a byte position, then up to one chunk of plaintext sealed here: it must open to
//!   exactly its bytes, and with the byte at that position changed it must not open.
#![no_main]

use larsal_folders::Error;
use larsal_folders::fuzz_door;
use libfuzzer_sys::fuzz_target;

const CHUNK: usize = 32_768;
const MAX_PARENT: usize = 36;
const THRESHOLD: usize = 220;

/// A length byte, that many bytes (bounded), then the rest.
fn split_counted(rest: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    let (len, rest) = rest.split_first()?;
    let len = usize::from(*len).min(max).min(rest.len());
    Some(rest.split_at(len))
}

/// Opens a stored file; a failure is only ever the generic one.
fn open(stored: &[u8], workers: usize) -> Result<Vec<u8>, Error> {
    let mut plain = Vec::new();
    let got = fuzz_door::content(stored, workers, &mut |part| plain.extend_from_slice(part));
    match got {
        Ok(()) => Ok(plain),
        Err(e) => {
            assert_eq!(e, Error::Open, "one generic error");
            Err(e)
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 7 {
        0 => drop(fuzz_door::config(rest)),
        1 => drop(fuzz_door::key_file(rest)),
        2 => {
            let Some((parent, name)) = split_counted(rest, MAX_PARENT) else {
                return;
            };
            if let Ok(name) = std::str::from_utf8(name) {
                drop(fuzz_door::name(parent, name));
            }
        }
        3 => {
            let Ok(clear) = std::str::from_utf8(rest) else {
                return;
            };
            if let Ok(stored) = fuzz_door::new_name(b"", clear) {
                let opened = fuzz_door::name(b"", &stored).expect("a name made here opens");
                assert_eq!(
                    fuzz_door::new_name(b"", &opened).ok(),
                    Some(stored),
                    "one stored form"
                );
            }
        }
        4 => {
            let Some((node, mapping)) = split_counted(rest, usize::from(u8::MAX)) else {
                return;
            };
            if let Ok(node) = std::str::from_utf8(node) {
                drop(fuzz_door::shortened(node, mapping, THRESHOLD));
            }
        }
        5 => {
            let Some((workers, stored)) = rest.split_first() else {
                return;
            };
            drop(open(stored, 1 + usize::from(*workers % 4)));
        }
        _ => {
            let Some((at, plain)) = rest.split_first() else {
                return;
            };
            let plain = &plain[..plain.len().min(CHUNK)];
            let sealed = fuzz_door::seal_demo(plain).expect("the demo writer seals");
            assert_eq!(open(&sealed, 1).expect("a right file opens"), plain);
            let mut changed = sealed;
            let i = usize::from(*at) * changed.len() / 256;
            changed[i] ^= 0x80;
            assert!(open(&changed, 2).is_err(), "a changed byte never opens");
        }
    }
});
