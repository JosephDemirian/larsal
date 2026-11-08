//! The fuzz target's way to the untrusted readers, in memory, with demo keys. Never on in
//! a product build: a user's file goes through capture (FIL-06.4). Each returns what the
//! reader said; every failure is one error, and none may panic or allocate from an
//! unchecked length.

use crate::content;
use crate::error::Error;
use crate::format;
use crate::keys::MasterKeys;
use crate::names;
use crate::vault::demo_keys;

/// The configuration reader, then the claims as if the signature had held.
///
/// # Errors
/// As the reader.
pub fn config(bytes: &[u8]) -> Result<usize, Error> {
    let parsed = format::parse_config(bytes)?;
    let keys = demo_keys()?;
    let _ = parsed.signed_by(&keys.raw);
    parsed.authenticated_threshold()
}

/// The key file reader.
///
/// # Errors
/// As the reader.
pub fn key_file(bytes: &[u8]) -> Result<(), Error> {
    let parsed = format::parse_key_file(bytes)?;
    let keys = demo_keys()?;
    let _ = parsed.version_proven(&keys.mac);
    let _ = (parsed.fits_a_config(), parsed.predates_config());
    Ok(())
}

/// A stored name below a parent. A right name must come back as itself.
///
/// # Errors
/// As the reader.
pub fn name(parent: &[u8], stored: &str) -> Result<String, Error> {
    let keys: MasterKeys = demo_keys()?;
    let clear = names::open_name(&keys, parent, stored)?;
    let _ = names::is_safe_stored(clear.expose());
    Ok(clear.expose().to_owned())
}

/// A new name's checks and its stored form.
///
/// # Errors
/// As the reader.
pub fn new_name(parent: &[u8], clear: &str) -> Result<String, Error> {
    let keys: MasterKeys = demo_keys()?;
    let normal = names::check_new(clear)?;
    names::seal_name(&keys, parent, normal.expose())
}

/// A shortened node's mapping file.
///
/// # Errors
/// As the reader.
pub fn shortened(deflated: &str, inflated: &[u8], threshold: usize) -> Result<String, Error> {
    names::check_mapping(deflated, inflated, threshold)
}

/// A whole stored file: every chunk checked, each plaintext given to `sink` in order.
///
/// # Errors
/// As the reader.
pub fn content(stored: &[u8], workers: usize, sink: &mut dyn FnMut(&[u8])) -> Result<(), Error> {
    let keys: MasterKeys = demo_keys()?;
    content::open_bytes(&keys, stored, workers, &mut |plain| {
        sink(plain);
        Ok(())
    })
}

/// A stored file under the demo keys, made by the crate's own writer, so the fuzzer gets
/// past a right tag.
///
/// # Errors
/// As the writer.
pub fn seal_demo(plain: &[u8]) -> Result<Vec<u8>, Error> {
    let keys: MasterKeys = demo_keys()?;
    content::seal_small(&keys, plain)
}
