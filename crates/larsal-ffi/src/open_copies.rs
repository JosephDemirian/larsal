//! Attachment-copy selection: private sessions and debug fixtures never share production state.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct OpenCopies {
    root: Result<PathBuf, io::ErrorKind>,
    owned: bool,
    test_root: bool,
    product: &'static str,
}

fn private_dir(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.mode() & 0o7777 != 0o700
        || meta.uid() != larsal_platform::macos::effective_uid()
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn validate_test_root(path: &Path) -> io::Result<PathBuf> {
    let tmp = std::fs::canonicalize("/tmp")?;
    let relative = path
        .strip_prefix("/tmp")
        .or_else(|_| path.strip_prefix(&tmp))
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let canonical = std::fs::canonicalize(path)?;
    if canonical != tmp.join(relative) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut checked = tmp;
    for part in relative.components() {
        checked.push(part);
        private_dir(&checked)?;
    }
    Ok(canonical)
}

fn debug_root() -> Option<std::ffi::OsString> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(crate::instance::TEST_DIR_VARIABLE)
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

// Path calculation only: F-065 probes this without creating or cleaning a folder.
pub(crate) fn production_folder() -> io::Result<PathBuf> {
    let product = if cfg!(debug_assertions) {
        "Larsal-debug"
    } else {
        "Larsal"
    };
    Ok(larsal_platform::macos::user_temp_dir()?
        .join(product)
        .join("open-attachments"))
}

impl OpenCopies {
    pub(crate) fn private() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = (|| {
            let tmp = match debug_root() {
                Some(root) => validate_test_root(Path::new(&root))?,
                None => std::fs::canonicalize("/tmp")?,
            };
            for _ in 0..32 {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = tmp.join(format!("larsal-session-{}-{n}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return validate_test_root(&path),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(io::ErrorKind::AlreadyExists.into())
        })();
        Self {
            root: root.map_err(|e: io::Error| e.kind()),
            owned: true,
            test_root: true,
            product: "Larsal",
        }
    }

    pub(crate) fn fixture(path: &Path) -> Self {
        Self {
            root: validate_test_root(path).map_err(|e| e.kind()),
            owned: false,
            test_root: true,
            product: "Larsal",
        }
    }

    pub(crate) fn shared() -> Self {
        if let Some(root) = debug_root() {
            return Self::fixture(Path::new(&root));
        }
        #[cfg(test)]
        {
            Self::private()
        }
        #[cfg(not(test))]
        {
            let path = production_folder();
            Self {
                root: path
                    .map(|p| p.parent().unwrap().parent().unwrap().to_path_buf())
                    .map_err(|e| e.kind()),
                owned: false,
                test_root: false,
                product: if cfg!(debug_assertions) {
                    "Larsal-debug"
                } else {
                    "Larsal"
                },
            }
        }
    }

    pub(crate) fn validate(&self) -> io::Result<&Path> {
        let root = self.root.as_ref().map_err(|e| io::Error::from(*e))?;
        if self.test_root {
            validate_test_root(root)?;
        } else {
            private_dir(root)?;
        }
        Ok(root)
    }

    pub(crate) fn folder(&self) -> io::Result<PathBuf> {
        let root = self.validate()?;
        let mut path = root.to_path_buf();
        for part in [self.product, "open-attachments"] {
            path.push(part);
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
            private_dir(&path)?;
        }
        Ok(path)
    }
}

impl Drop for OpenCopies {
    fn drop(&mut self) {
        if self.owned
            && let Ok(root) = self.validate()
        {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn sessions_and_cleanup_keep_each_others_canaries() {
        let a = crate::session::Session::new();
        let b = crate::session::Session::new();
        let one = a.open_copies.folder().unwrap();
        let two = b.open_copies.folder().unwrap();
        assert_ne!(one, two);
        assert!(one.starts_with(std::fs::canonicalize("/tmp").unwrap()));
        assert!(one.ends_with("Larsal/open-attachments"));
        let mine = one.join("mine.txt");
        let theirs = two.join("outside-canary.txt");
        std::fs::write(&mine, b"demo mine").unwrap();
        std::fs::write(&theirs, b"demo outside").unwrap();
        crate::edit::clean_open_copies(&a.open_copies);
        assert!(!mine.exists());
        assert_eq!(std::fs::read(&theirs).unwrap(), b"demo outside");
        drop(a);
        assert_eq!(std::fs::read(&theirs).unwrap(), b"demo outside");
        std::fs::remove_file(theirs).unwrap();
    }

    #[test]
    fn fixture_roots_reject_relative_shared_modes_and_symlinks() {
        let own = OpenCopies::private();
        let root = own.root.as_ref().unwrap();
        assert_eq!(validate_test_root(root).unwrap(), *root);
        assert_eq!(validate_test_root(&root.join(".")).unwrap(), *root);
        for bad in [
            Path::new("relative"),
            Path::new("/tmp"),
            Path::new("/"),
            Path::new("/var/empty"),
        ] {
            assert!(validate_test_root(bad).is_err(), "{}", bad.display());
        }
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_test_root(root).is_err());
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.join("link");
        symlink(root, &link).unwrap();
        assert!(validate_test_root(&link).is_err());
        let file = root.join("file");
        std::fs::write(&file, b"demo").unwrap();
        assert!(validate_test_root(&file).is_err());
        let parent = root.join("..").join(root.file_name().unwrap());
        assert!(validate_test_root(&parent).is_err());
    }

    #[test]
    fn planted_product_or_attachment_links_are_rejected() {
        let own = OpenCopies::private();
        let outside = OpenCopies::private();
        let root = own.root.as_ref().unwrap();
        let other = outside.root.as_ref().unwrap();
        let canary = other.join("canary");
        std::fs::write(&canary, b"demo outside").unwrap();
        let product = root.join("Larsal");
        symlink(other, &product).unwrap();
        assert!(own.folder().is_err());
        std::fs::remove_file(&product).unwrap();
        std::fs::create_dir(&product).unwrap();
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(other, product.join("open-attachments")).unwrap();
        assert!(own.folder().is_err());
        drop(own);
        assert_eq!(std::fs::read(canary).unwrap(), b"demo outside");
    }

    #[test]
    fn shared_session_identity_and_private_unit_selection_are_stable() {
        let a = crate::session::Session::shared();
        let b = crate::session::Session::shared();
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(
            a.open_copies.folder().unwrap(),
            b.open_copies.folder().unwrap()
        );
        assert!(
            a.open_copies
                .root
                .as_ref()
                .unwrap()
                .starts_with(std::fs::canonicalize("/tmp").unwrap())
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[ignore = "path-gated child of shared_fixture_selection_is_validated"]
    fn shared_fixture_child() {
        let session = crate::session::Session::shared();
        let private = OpenCopies::private();
        if std::env::var_os("LARSAL_TEST_INVALID_ROOT").is_some() {
            assert!(
                private.root.is_err(),
                "invalid private fixture must not fall back"
            );
            assert!(
                session.open_copies.root.is_err(),
                "invalid fixture must not fall back"
            );
            return;
        }
        let given = debug_root().unwrap();
        let expected = validate_test_root(Path::new(&given)).unwrap();
        let private_root = private
            .root
            .as_ref()
            .expect("private child uses the validated fixture");
        assert_eq!(private_root.parent(), Some(expected.as_path()));
        assert!(private.owned && private.test_root);
        assert_eq!(session.open_copies.root.as_ref().unwrap(), &expected);
        assert!(session.open_copies.test_root && !session.open_copies.owned);
        // Gate mutation behind the path assertions, including under production-selection mutants.
        assert_eq!(
            session.open_copies.folder().unwrap(),
            expected.join("Larsal/open-attachments")
        );
        assert!(std::sync::Arc::ptr_eq(
            &session,
            &crate::session::Session::shared()
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn shared_fixture_selection_is_validated() {
        let fixture = OpenCopies::private();
        let root = fixture.root.as_ref().unwrap();
        let child = |path: &Path, invalid: bool| {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "open_copies::tests::shared_fixture_child",
                "--ignored",
                "--nocapture",
            ])
            .env(crate::instance::TEST_DIR_VARIABLE, path);
            if invalid {
                cmd.env("LARSAL_TEST_INVALID_ROOT", "1");
            }
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        };
        child(root, false);
        child(Path::new("relative"), true);
        child(Path::new("/var/empty"), true);
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
        child(root, true);
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.join("link");
        symlink(root, &link).unwrap();
        child(&link, true);
    }

    #[test]
    #[ignore = "path-only child of selection_ignores_hostile_environment"]
    fn selection_path_child() {
        let actual = production_folder().unwrap();
        let os = larsal_platform::macos::user_temp_dir().unwrap();
        let product = if cfg!(debug_assertions) {
            "Larsal-debug"
        } else {
            "Larsal"
        };
        assert_eq!(actual, os.join(product).join("open-attachments"));
        #[cfg(not(debug_assertions))]
        assert!(
            debug_root().is_none(),
            "release must not read the debug override"
        );
        println!("production path {}", actual.display());
    }

    #[test]
    fn selection_ignores_hostile_environment() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "open_copies::tests::selection_path_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TMPDIR", "/nonexistent-tmpdir/")
            .env("LARSAL_TEST_INSTANCE_DIR", "/must-not-be-used")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("production path "));
    }
}
