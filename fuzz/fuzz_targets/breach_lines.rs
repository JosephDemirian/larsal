//! Fuzz target `breach_lines` (E4-S11, FEA-06): the range answer reader
//! and the hash file record reader on arbitrary bytes, the same bytes for
//! both. Must never panic or hang; a count needs our suffix in the answer,
//! and every record the file reader accepts took at least 42 bytes.
#![no_main]

use larsal_core::breach::{FileError, HashFile, MAX_BODY, parse_range};
use libfuzzer_sys::fuzz_target;

/// The suffix of `password` (FEA-06.3).
const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

fuzz_target!(|data: &[u8]| {
    let started = std::time::Instant::now();
    match parse_range(data, SUFFIX) {
        Err(_) => assert!(data.len() > MAX_BODY),
        Ok(0) => {}
        Ok(_) => assert!(
            data.windows(SUFFIX.len())
                .any(|w| w.eq_ignore_ascii_case(SUFFIX.as_bytes()))
        ),
    }
    let mut file = HashFile::new(data);
    let mut records: u64 = 0;
    let mut hash = [0u8; 20];
    loop {
        match file.next_record(&mut hash) {
            Ok(Some(_)) => records += 1,
            Ok(None) => break,
            Err(FileError::Parse(n)) => {
                assert_eq!(n, records + 1, "the failing record is the next one");
                break;
            }
            Err(FileError::Io(_)) => unreachable!("a byte slice never fails to read"),
        }
    }
    assert!(records * 42 <= data.len() as u64);
    assert!(started.elapsed().as_secs() < 2, "too slow");
});
