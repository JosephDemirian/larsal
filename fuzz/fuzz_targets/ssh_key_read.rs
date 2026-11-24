//! Fuzz target `ssh_key_read` (E9-S1, LD-182 (4)): SSH key reading on
//! arbitrary bytes must never panic, hang or allocate from an unchecked
//! length (AT-A10). Unprotected keys are unlocked too; protected ones are
//! not, so no key derivation runs.
#![no_main]

use larsal_crypto::secret::SecretString;
use larsal_sshagent::SshKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(key) = SshKey::read(data) else {
        return;
    };
    assert!(!key.type_label().is_empty());
    assert!(key.fingerprint().starts_with("SHA256:"));
    assert!(key.public_line().starts_with(key.algorithm()));
    if !key.is_encrypted()
        && let Ok(unlocked) = key.unlock(&SecretString::new(String::new()))
    {
        assert_eq!(unlocked.algorithm(), key.algorithm());
    }
});
