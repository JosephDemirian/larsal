//! What the outside tests open with: the public road, consent said yes to.

use larsal_crypto::secret::SecretBytes;
use larsal_files::{Error, Phase, ScratchRoot, Unlock, Validation};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// The whole flow on ciphertext given in memory, into wiping memory. Its scratch
/// folder is private and empty again as soon as the capture has sealed.
pub fn open_all(data: &[u8], unlock: &Unlock<'_>) -> Result<SecretBytes, Error> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let keep = &mut |_: Phase, _: u64| true;
    let dir = std::env::temp_dir().join(format!(
        "larsal-files-outside-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot = ScratchRoot::open(&dir)?.capture_stream(&mut &*data, keep);
    fs::remove_dir(&dir).unwrap();
    let checked = match snapshot?.unlock(unlock)?.validate(keep)? {
        Validation::Ready(v) => v,
        Validation::Weak(w) => w.accept(),
    };
    let mut plain = SecretBytes::zeroed(usize::try_from(checked.plain_len()).unwrap());
    let mut to: &mut [u8] = plain.expose_mut();
    checked.write_to(&mut to, keep)?;
    Ok(plain)
}
