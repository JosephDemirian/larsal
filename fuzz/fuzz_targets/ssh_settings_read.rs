//! Fuzz target `ssh_settings_read` (E9-S2): an entry's SSH settings
//! attachment (INT-06.2) on arbitrary bytes must never panic or hang, and
//! is refused over 64 KiB. What Larsal writes back (INT-06.3) reads again with
//! the same values.
#![no_main]

use larsal_sshagent::{MAX_SETTINGS, Settings};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(settings) = Settings::read(data) else {
        return;
    };
    assert!(data.len() <= MAX_SETTINGS);
    if let Some(written) = settings.write() {
        assert_eq!(Settings::read(&written), Some(settings));
    }
});
