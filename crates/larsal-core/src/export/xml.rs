//! XML export (FEA-09.13, FEA-09.14): the vault document Larsal's save would
//! write, with no protected-value stream, protected values in clear marked
//! `ProtectInMemory="True"`, a `Meta/Binaries` pool holding every
//! attachment (L09-1), and the custom data as it is in memory.

use crate::Error;
use larsal_crypto::secret::SecretBytes;
use larsal_model::Vault;

/// The XML export of `vault`, at the version a save picks (4.0 or higher).
///
/// # Errors
/// `TooLarge` only if the writer refuses, which the plain document never
/// does; kept so nothing can panic.
pub fn xml(vault: &Vault) -> Result<SecretBytes, Error> {
    let written =
        larsal_format::document::write::write_plain(vault).map_err(|_| Error::TooLarge)?;
    Ok(SecretBytes::new(written.xml().to_vec()))
}
