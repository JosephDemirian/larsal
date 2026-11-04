//! The plain XML document of our format (FEA-08 section H): what `app
//! import` reads (FEA-08.61, FEA-08.62). The command line (INT-10, E12)
//! saves the vault with the given credentials and the version FMT-16
//! picks; this module reads the document and checks the target first.
//!
//! Guarantees: the FMT-10 to FMT-15 reading rules of app-format with no
//! protected-value stream: ids, times, history, metadata, custom data,
//! custom icons and deleted objects are kept; `ProtectInMemory="True"` sets
//! the protected flag; a `Meta/Binaries` pool resolves `Ref` numbers in
//! every version. A `Protected="True"` value is refused before it is
//! decoded (the reference crashes on it); a DTD is refused; every read is
//! bounded by app-format's limits.

use super::ImportError;
use app_format::document::{self, Reason};
use app_format::limits::Limits;
use app_model::{Time, Vault};
use std::path::Path;

/// Reads a plain XML document. `now` is the open time for missing times.
///
/// # Errors
/// `MSG-XML-PROTECTED`, `MSG-XML-NOROOT` (no root element of FMT-10.5 or
/// no root group), or [`ImportError::XmlInvalid`] for any other problem.
pub fn read(xml: &[u8], now: Time) -> Result<Vault, ImportError> {
    let opts = document::Options {
        open_time: now,
        limits: &Limits::DEFAULT,
        v3_header: None,
    };
    match document::read_plain(xml, &opts) {
        Ok(doc) => Ok(doc.vault),
        Err(Reason::ProtectedInPlain) => Err(ImportError::XmlProtected),
        Err(Reason::NoRootGroup) => Err(ImportError::XmlNoRoot),
        Err(_) => Err(ImportError::XmlInvalid),
    }
}

/// FEA-08.61: before anything is read or written, the target path must
/// not exist (a link counts as existing) and a password or key file must
/// be given.
///
/// # Errors
/// `MSG-XML-EXISTS`, then `MSG-XML-NOKEY`.
pub fn check_target(target: &Path, has_credentials: bool) -> Result<(), ImportError> {
    if std::fs::symlink_metadata(target).is_ok() {
        return Err(ImportError::XmlExists);
    }
    if !has_credentials {
        return Err(ImportError::XmlNoKey);
    }
    Ok(())
}
