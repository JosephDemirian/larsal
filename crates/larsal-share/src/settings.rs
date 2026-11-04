//! A group's share settings item (INT-08.1 to INT-08.5) and the container
//! path it names. The item's reader and writer live in larsal-format
//! (`share_item`), because larsal-core's references read it too (MOD-08.32).

pub use larsal_format::share_item::{Item, Mode, ROOT, Settings, of, read, share_group};
use std::path::{Path, PathBuf};

/// The container path of a share (INT-08.5): an absolute path as it is; a
/// relative one joined to the folder of `vault_file`; `~` is not
/// expanded. `None` for an empty path, and for any path while the vault
/// has no file yet (Larsal refuses it, MI08-17).
#[must_use]
pub fn resolve(path: &str, vault_file: Option<&Path>) -> Option<PathBuf> {
    let file = vault_file?;
    if path.is_empty() {
        return None;
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    Some(file.parent().unwrap_or(Path::new("")).join(p))
}
